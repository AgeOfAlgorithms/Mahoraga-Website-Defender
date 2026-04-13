"""Shadow Analyzer — LLM-based analysis of shadow environment logs.

Runs every 15 seconds. Reads the shadow access log (which includes response
bodies), sends it to the LLM, and asks: "did any successful attack happen?"

This is the GENERIC exploit detector — no hardcoded rules. The LLM reasons
about whether requests + responses indicate:
  - Unauthorized data access (response contains another user's data)
  - Privilege escalation (non-admin got admin data)
  - Data manipulation (balance changed, records modified)
  - Injection success (error messages leaking data, unexpected responses)
  - Information disclosure (internal config, credentials in responses)

When the LLM identifies a successful exploit, it triggers the Fixer pipeline.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path

from harness.agents.llm_runner import run_completion
from harness.cost_governor import CostGovernor

logger = logging.getLogger(__name__)

ANALYSIS_PROMPT = """\
You are a security analyst monitoring a web application's shadow environment.
Attackers have been redirected here — every request you see is from a suspected attacker.

Your job: determine if any request-response pair shows a SUCCESSFUL attack.
Not just attempts — look for evidence that the attacker actually GOT something they shouldn't have.

## Shadow access logs (last cycle)
{log_entries}

## What to look for
1. **Data leakage**: Response contains other users' emails, names, phone numbers, \
vehicle data, passwords, tokens, or any PII that doesn't belong to the requesting user
2. **Privilege escalation**: Response contains admin panels, config dumps, internal \
service info, or data only admins should see
3. **Injection success**: Response is a database error with schema/data leak, or a \
500 error caused by an injection payload in the request body
4. **Business logic abuse**: Response shows negative balances, refunds for items not \
purchased, quantity manipulation
5. **Credential theft**: Response contains JWTs, API keys, password reset tokens \
belonging to other users
6. **SSRF success**: Response contains internal service data (hostnames, ports, \
internal API responses)

## Response format (JSON only, no markdown fencing)
{{
  "attacks_detected": [
    {{
      "type": "data_leakage|broken_access_control|privilege_escalation|authentication_bypass|injection|command_execution|business_logic|credential_theft|ssrf|xss|directory_traversal|information_disclosure|ai_exploitation",
      "severity": "critical|high|medium",
      "request": "the suspicious request line",
      "evidence": "what in the response proves the attack succeeded",
      "vulnerability": "what is the underlying vulnerability",
      "fix_recommendation": "one-sentence description of how to fix this specific vulnerability"
    }}
  ],
  "summary": "one-sentence overall assessment",
  "total_requests_analyzed": <number>
}}

If no successful attacks are detected, return an empty attacks_detected array.
Be conservative — only flag SUCCESSFUL attacks, not just attempts or probing.
"""

HAIKU_COST_PER_CALL = 0.003  # Haiku is cheap


class ShadowAnalyzer:
    """Periodically analyzes shadow logs with LLM to detect successful exploits."""

    IDLE_TIMEOUT = 120.0  # seconds of no shadow activity before sleeping
    IDLE_POLL = 5.0       # how often to check for new lines while idle

    def __init__(
        self,
        shadow_log_path: Path,
        cost_governor: CostGovernor,
        interval: float = 15.0,
        on_exploit_detected=None,
        on_cycle_complete=None,
        max_new_entries: int = 100,
        max_context_entries: int = 20,
    ):
        self.shadow_log_path = shadow_log_path
        self.cost_governor = cost_governor
        self.interval = interval
        self.on_exploit_detected = on_exploit_detected  # callback
        self.on_cycle_complete = on_cycle_complete      # callback(n_new, n_attacks, attacks)
        self.max_new_entries = max_new_entries
        self.max_context_entries = max_context_entries
        self.early_trigger_lines = max_new_entries - max_context_entries
        self._last_position = 0
        self._last_activity = 0.0  # timestamp of last shadow log entry seen
        self._running = False
        self._active = False       # currently analyzing (not idle)

    SYSTEM_PROMPT = (
        "You are a security analyst. Analyze access logs to detect "
        "successful attacks. Respond with JSON only. Be conservative — "
        "only flag attacks where the response PROVES success."
    )

    @property
    def active(self) -> bool:
        return self._active

    def get_system_prompt(self) -> str:
        return self.SYSTEM_PROMPT

    async def run(self) -> None:
        """Main loop — analyze shadow logs every interval seconds.
        Goes idle if no shadow activity for IDLE_TIMEOUT seconds."""
        self._running = True
        logger.info(
            "Shadow Analyzer started (interval=%ds, idle_timeout=%ds, log=%s)",
            self.interval, self.IDLE_TIMEOUT, self.shadow_log_path,
        )

        while self._running:
            try:
                had_data = await self._analyze_cycle()
                if had_data:
                    self._last_activity = time.time()
                    if not self._active:
                        self._active = True
                        logger.info("Shadow Analyzer ACTIVE — shadow traffic detected")
                elif self._active and time.time() - self._last_activity > self.IDLE_TIMEOUT:
                    self._active = False
                    logger.info("Shadow Analyzer IDLE — no shadow traffic for %.0fs",
                                self.IDLE_TIMEOUT)
            except Exception as e:
                logger.error("Shadow analysis cycle failed: %s", e)

            if self._active:
                await self._wait_for_interval_or_burst()
            else:
                # Idle: just check for new lines without calling LLM
                await self._wait_for_activity()

    async def _wait_for_interval_or_burst(self) -> None:
        """Wait up to self.interval seconds, but trigger early if
        early_trigger_lines new log lines accumulate."""
        deadline = time.time() + self.interval
        while self._running and time.time() < deadline:
            if self.shadow_log_path.exists():
                try:
                    size = self.shadow_log_path.stat().st_size
                    if size > self._last_position:
                        # Count new lines without consuming them
                        with open(self.shadow_log_path, "r") as f:
                            f.seek(self._last_position)
                            new_data = f.read(size - self._last_position)
                        n_new = sum(1 for line in new_data.splitlines() if line.strip())
                        if n_new >= self.early_trigger_lines:
                            logger.info("Shadow Analyzer early trigger: %d new lines", n_new)
                            return
                except OSError:
                    pass
            await asyncio.sleep(1)

    async def _wait_for_activity(self) -> None:
        """Poll for new shadow log lines without calling LLM.
        Returns as soon as new lines appear."""
        while self._running:
            if self.shadow_log_path.exists():
                try:
                    size = self.shadow_log_path.stat().st_size
                    if size > self._last_position:
                        return  # new data — caller will run _analyze_cycle
                except OSError:
                    pass
            await asyncio.sleep(self.IDLE_POLL)

    async def _analyze_cycle(self) -> bool:
        """Read new shadow log entries and analyze with LLM.
        Returns True if new entries were found."""
        if not self.shadow_log_path.exists():
            return False

        # Read new lines plus 20 older lines for context
        with open(self.shadow_log_path, "r") as f:
            # Read context lines before _last_position
            context_lines = []
            if self._last_position > 0:
                f.seek(0)
                all_prior = f.read(self._last_position).splitlines()
                context_lines = all_prior[-self.max_context_entries:] if len(all_prior) >= self.max_context_entries else all_prior

            # Read new lines from where we left off
            f.seek(self._last_position)
            new_lines = f.readlines()
            self._last_position = f.tell()

        if not new_lines:
            return False  # nothing new, skip LLM call

        new_entries = [line.strip() for line in new_lines if line.strip()]
        if not new_entries:
            return False

        # Prepend context lines (marked so LLM knows they're older)
        context_entries = [line.strip() for line in context_lines if line.strip()]
        n_context = len(context_entries)
        n_new = len(new_entries)

        logger.info("Analyzing %d new + %d context shadow log entries", n_new, n_context)

        # Budget check
        if not self.cost_governor.can_spend("shadow_analysis", HAIKU_COST_PER_CALL):
            logger.warning("Budget exceeded, skipping shadow analysis")
            return True  # had data, just can't afford to analyze

        # Truncate new entries if too many
        if len(new_entries) > self.max_new_entries:
            new_entries = new_entries[-self.max_new_entries:]

        # Truncate long fields (JWTs, response bodies) to reduce prompt size
        def _truncate_entry(line: str) -> str:
            import re
            # Shorten JWT tokens to first 20 chars + ...
            line = re.sub(r'(eyJ[A-Za-z0-9_-]{17})[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*', r'\1...', line)
            # Shorten very long resp_body (keep first 300 chars)
            m = re.search(r'resp_body="(.{300,})"', line)
            if m:
                line = line[:m.start(1)] + m.group(1)[:300] + '..."'
            return line

        context_entries = [_truncate_entry(e) for e in context_entries]
        new_entries = [_truncate_entry(e) for e in new_entries]

        # Collapse consecutive identical requests (same method+path+status)
        # to reduce prompt size for brute-force / enumeration floods
        new_entries = self._dedup_entries(new_entries)
        context_entries = self._dedup_entries(context_entries)

        entries = context_entries + new_entries

        # Mark context vs new so the LLM focuses on new but has context
        if context_entries:
            log_text = (
                "--- CONTEXT (previous requests, for reference only) ---\n"
                + "\n".join(context_entries)
                + "\n\n--- NEW REQUESTS (analyze these) ---\n"
                + "\n".join(new_entries)
            )
        else:
            log_text = "\n".join(new_entries)
        prompt = ANALYSIS_PROMPT.format(log_entries=log_text)

        system_prompt = self.SYSTEM_PROMPT

        response_text = ""
        actual_cost = 0.0
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response_text, actual_cost = await run_completion(
                    prompt=prompt,
                    system_prompt=system_prompt,
                )
                break
            except Exception as e:
                logger.error(
                    "Shadow analysis LLM call failed (attempt %d/%d): %s",
                    attempt + 1, max_retries, e,
                )
                if attempt < max_retries - 1:
                    await asyncio.sleep(5 * (attempt + 1))
                else:
                    return True  # had data, LLM call just failed

        self.cost_governor.record_spend("shadow_analysis", actual_cost)

        # Parse response
        try:
            text = response_text.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1].rsplit("```", 1)[0]
            result = json.loads(text)
        except json.JSONDecodeError:
            logger.error("Failed to parse shadow analysis: %s", response_text[:200])
            return True

        attacks = result.get("attacks_detected", [])
        if not attacks:
            logger.debug(
                "Shadow analysis: no successful attacks in %d entries",
                result.get("total_requests_analyzed", len(entries)),
            )
            if self.on_cycle_complete:
                await self.on_cycle_complete(n_new, 0, [])
            return True

        # Exploits detected!
        if self.on_cycle_complete:
            await self.on_cycle_complete(n_new, len(attacks), attacks)

        for attack in attacks:
            logger.warning(
                "SHADOW EXPLOIT DETECTED: type=%s severity=%s vuln=%s",
                attack.get("type"), attack.get("severity"),
                attack.get("vulnerability", "")[:80],
            )

            if self.on_exploit_detected:
                await self.on_exploit_detected(attack)

        return True

    @staticmethod
    def _dedup_entries(entries: list[str]) -> list[str]:
        """Collapse consecutive log lines with same method+path+status.

        E.g. 100 identical 'POST /check-otp 500' lines become:
        'POST /check-otp 500 [x100, bodies varied: otp=4601..4700]'
        plus one sample line with full detail.
        """
        import re
        if not entries:
            return entries

        def _signature(line: str) -> str:
            """Extract method+path+status as grouping key."""
            m = re.search(r'"(GET|POST|PUT|DELETE|PATCH)\s+(\S+)\s+\S+"\s+(\d+)', line)
            return f"{m.group(1)} {m.group(2)} {m.group(3)}" if m else ""

        result = []
        i = 0
        while i < len(entries):
            sig = _signature(entries[i])
            if not sig:
                result.append(entries[i])
                i += 1
                continue

            # Count consecutive entries with same signature
            j = i + 1
            while j < len(entries) and _signature(entries[j]) == sig:
                j += 1

            count = j - i
            if count <= 2:
                # Not worth collapsing
                result.extend(entries[i:j])
            else:
                # Keep first entry as sample, summarize the rest
                result.append(entries[i])
                result.append(f"  [... repeated {count - 1} more times with same {sig}, varying request bodies]")
            i = j

        return result

    def stop(self):
        self._running = False
