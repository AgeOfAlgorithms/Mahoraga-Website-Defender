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

from claude_agent_sdk import query, ClaudeAgentOptions, AssistantMessage, TextBlock

from harness.cost_governor import CostGovernor

logger = logging.getLogger(__name__)

ANALYSIS_PROMPT = """\
You are a security analyst monitoring a web application's shadow environment.
Attackers have been redirected here — every request you see is from a suspected attacker.

Your job: determine if any request-response pair shows a SUCCESSFUL attack.
Not just attempts — look for evidence that the attacker actually GOT something they shouldn't have.

## Shadow access logs (last 15 seconds)
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
7. **Flag capture**: Response contains a string matching XVEH{{...}} pattern — this \
means the attacker completed an exploit chain

## Response format (JSON only, no markdown fencing)
{{
  "attacks_detected": [
    {{
      "type": "data_leakage|privilege_escalation|injection|business_logic|credential_theft|ssrf|flag_capture",
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

    def __init__(
        self,
        shadow_log_path: Path,
        cost_governor: CostGovernor,
        interval: float = 15.0,
        on_exploit_detected=None,
    ):
        self.shadow_log_path = shadow_log_path
        self.cost_governor = cost_governor
        self.interval = interval
        self.on_exploit_detected = on_exploit_detected  # callback
        self._last_position = 0
        self._running = False

    async def run(self) -> None:
        """Main loop — analyze shadow logs every interval seconds."""
        self._running = True
        logger.info(
            "Shadow Analyzer started (interval=%ds, log=%s)",
            self.interval, self.shadow_log_path,
        )

        while self._running:
            try:
                await self._analyze_cycle()
            except Exception as e:
                logger.error("Shadow analysis cycle failed: %s", e)
            await asyncio.sleep(self.interval)

    async def _analyze_cycle(self) -> None:
        """Read new shadow log entries and analyze with LLM."""
        if not self.shadow_log_path.exists():
            return

        # Read new lines
        with open(self.shadow_log_path, "r") as f:
            f.seek(self._last_position)
            new_lines = f.readlines()
            self._last_position = f.tell()

        if not new_lines:
            return  # nothing new, skip LLM call

        # Filter to only shadow entries (should already be, but safety check)
        entries = [line.strip() for line in new_lines if line.strip()]
        if not entries:
            return

        logger.info("Analyzing %d shadow log entries", len(entries))

        # Budget check
        if not self.cost_governor.can_spend("shadow_analysis", HAIKU_COST_PER_CALL):
            logger.warning("Budget exceeded, skipping shadow analysis")
            return

        # Truncate if too many entries (keep last 50)
        if len(entries) > 50:
            entries = entries[-50:]

        log_text = "\n".join(entries)
        prompt = ANALYSIS_PROMPT.format(log_entries=log_text)

        options = ClaudeAgentOptions(
            system_prompt=(
                "You are a security analyst. Analyze access logs to detect "
                "successful attacks. Respond with JSON only. Be conservative — "
                "only flag attacks where the response PROVES success."
            ),
            max_turns=1,
        )

        response_text = ""
        try:
            async for message in query(prompt=prompt, options=options):
                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, TextBlock):
                            response_text += block.text
        except Exception as e:
            logger.error("Shadow analysis LLM call failed: %s", e)
            return

        self.cost_governor.record_spend("shadow_analysis", HAIKU_COST_PER_CALL)

        # Parse response
        try:
            text = response_text.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1].rsplit("```", 1)[0]
            result = json.loads(text)
        except json.JSONDecodeError:
            logger.error("Failed to parse shadow analysis: %s", response_text[:200])
            return

        attacks = result.get("attacks_detected", [])
        if not attacks:
            logger.debug(
                "Shadow analysis: no successful attacks in %d entries",
                result.get("total_requests_analyzed", len(entries)),
            )
            return

        # Exploits detected!
        for attack in attacks:
            logger.warning(
                "SHADOW EXPLOIT DETECTED: type=%s severity=%s vuln=%s",
                attack.get("type"), attack.get("severity"),
                attack.get("vulnerability", "")[:80],
            )

            if self.on_exploit_detected:
                await self.on_exploit_detected(attack)

    def stop(self):
        self._running = False
