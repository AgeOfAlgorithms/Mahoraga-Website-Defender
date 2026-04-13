"""Orchestrator — the main loop that routes events through the agent pipeline.

Option D flow:
  PROD:   Watcher detects suspicious activity → score session → redirect to shadow
  SHADOW: Shadow Analyzer (LLM) reads logs + response bodies → detects successful exploits
          → Fixer patches (scoped to that exploit only) → Reviewer checks
          → Tester validates → deploy to prod

Generic detection — no hardcoded exploit patterns. The LLM reasons about
whether request+response pairs indicate a successful attack.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import asdict
from pathlib import Path

import yaml

from harness.agents.analyzer import Analyzer
from harness.agents.fixer import Fixer
from harness.agents.reviewer import Reviewer

from harness.agents.watcher import Watcher
from harness.control_plane_client import ControlPlaneClient
from harness.cost_governor import CostGovernor
from harness.shadow_analyzer import ShadowAnalyzer
from harness.types import (
    ApprovalPolicy,
    AuditEntry,
    PipelineTicket,
    SecurityEvent,
    Severity,
    TicketStatus,
)

logger = logging.getLogger(__name__)


class Orchestrator:
    """Main defense loop coordinating all agents."""

    def __init__(
        self,
        project_dir: Path,
        app_url: str = "http://localhost:8888",
        control_plane_url: str = "http://localhost:9090",
    ):
        self.project_dir = project_dir
        self.app_url = app_url

        # Directories
        self.events_dir = project_dir / "events"
        self.patches_dir = project_dir / "patches"
        self.audit_dir = project_dir / "audit"
        self.logs_dir = project_dir / "logs" / "nginx"
        self.rules_dir = project_dir / "detection" / "rules"
        self.config_dir = project_dir / "config"
        self.pipeline_dir = project_dir / "pipeline"
        self.pipeline_dir.mkdir(exist_ok=True)

        # Load config
        self.policies = self._load_yaml("policies.yaml")
        self.budgets = self._load_yaml("budgets.yaml")

        # Cost governor
        self.cost_governor = CostGovernor(
            daily_budget=self.budgets["budget"]["daily_ceiling_usd"],
            per_incident_cap=self.budgets["budget"]["per_incident_cap_usd"],
            hourly_api_calls_limit=self.budgets["budget"]["hourly_api_call_limit"],
            anomaly_multiplier=self.budgets["budget"]["circuit_breaker_multiplier"],
        )
        self.cost_governor.set_ledger_path(project_dir / "audit" / "cost_ledger.json")

        # Control plane client for real-time actions
        self.control_plane = ControlPlaneClient(base_url=control_plane_url)

        # Agents
        self.watcher = Watcher(
            log_path=self.logs_dir / "access.log",
            events_dir=self.events_dir,
            rules_dir=self.rules_dir,
            extra_log_dir=project_dir / "logs",
        )
        self.analyzer = Analyzer(self.cost_governor, str(project_dir))
        self.fixer = Fixer(self.cost_governor)
        self.reviewer = Reviewer(self.cost_governor, str(project_dir))

        # Inter-agent queues
        self._exploit_queue: asyncio.Queue[dict] = asyncio.Queue()
        self._review_queue: asyncio.Queue[tuple] = asyncio.Queue()  # (triage, patch)

        # Dedup tracking — keyed on type+endpoint (e.g. "ssrf|/mechanic/contact_mechanic")
        # Same vuln type on different endpoints = different vulns
        # Same vuln type on same endpoint detected multiple times = duplicate
        self._pending_vulns: set[str] = set()   # currently queued/being fixed
        self._fixed_vulns: set[str] = set()     # already patched + deployed
        self._stale_tickets: list = []           # tickets to re-enqueue on startup

        # Restore dedup state from pipeline tickets on disk
        # Reset stale fixing/reviewing tickets back to detected (queue was lost on restart)
        for ticket_file in self.pipeline_dir.glob("*.json"):
            try:
                ticket = PipelineTicket.load(ticket_file)
                if ticket.dedup_key:
                    if ticket.status == TicketStatus.DEPLOYED.value:
                        self._fixed_vulns.add(ticket.dedup_key)
                    elif ticket.status in (TicketStatus.QUEUED.value, TicketStatus.FIXING.value,
                                           TicketStatus.PENDING_REVIEW.value, TicketStatus.REVIEWING.value):
                        # Queue was lost — reset and re-enqueue
                        ticket.status = TicketStatus.QUEUED.value
                        ticket.agent = ""
                        ticket.save(self.pipeline_dir)
                        self._pending_vulns.add(ticket.dedup_key)
                        self._stale_tickets.append(ticket)
                        logger.info("Reset stale ticket %s (%s) — will re-enqueue",
                                    ticket.id, ticket.type)
            except Exception:
                pass
        # Also check patches dir for backward compat
        for patch_file in self.patches_dir.glob("*.json"):
            try:
                data = json.loads(patch_file.read_text())
                dedup_key = data.get("_dedup_key", "")
                if dedup_key:
                    self._fixed_vulns.add(dedup_key)
            except (json.JSONDecodeError, OSError):
                pass
        if self._fixed_vulns:
            logger.info("Restored %d fixed vulns from disk: %s",
                        len(self._fixed_vulns), self._fixed_vulns)

        # Shadow LLM analyzer — generic exploit detection every 15s
        self.shadow_analyzer = ShadowAnalyzer(
            shadow_log_path=project_dir / "logs" / "nginx" / "shadow.log",
            cost_governor=self.cost_governor,
            interval=10.0,
            on_exploit_detected=self._enqueue_exploit,
            on_cycle_complete=self._on_analyzer_cycle,
        )

        # Batching queues
        self._event_queue: asyncio.Queue[SecurityEvent] = asyncio.Queue()
        self._batch_buffer: dict[Severity, list[SecurityEvent]] = {
            s: [] for s in Severity
        }

        # Dynamic agent scaling — tracks running asyncio tasks by name
        self._agent_tasks: dict[str, asyncio.Task] = {}
        self._agent_counts_file = project_dir / "config" / "agent_counts.json"
        self._current_counts = {"fixer": 2, "reviewer": 1}

    async def run(self, poll_interval: float = 2.0) -> None:
        """Main loop — parallel agent loops connected by queues."""
        logger.info("Reactive Defender started. Watching %s", self.watcher.log_path)
        logger.info("Budget: $%.2f/day, $%.2f/incident",
                     self.cost_governor.daily_budget,
                     self.cost_governor.per_incident_cap)
        logger.info("Shadow analyzer: every %.0fs on %s",
                     self.shadow_analyzer.interval,
                     self.shadow_analyzer.shadow_log_path)

        # Load saved agent counts if they exist
        if self._agent_counts_file.exists():
            try:
                saved = json.loads(self._agent_counts_file.read_text())
                self._current_counts.update(saved)
            except (json.JSONDecodeError, OSError):
                pass

        # Write agent model info for dashboard
        from harness.agents.llm_runner import AGENT_MODEL, COMPLETION_MODEL
        agent_models = {
            "watcher": None,
            "shadow_analyzer": COMPLETION_MODEL,
            "fixer": AGENT_MODEL,
            "reviewer": AGENT_MODEL,
        }
        (self.config_dir / "agent_models.json").write_text(
            json.dumps(agent_models, indent=2))

        # Start core loops (non-scalable singletons)
        core_tasks = {
            "scanner": asyncio.create_task(self._scan_loop(poll_interval)),
            "processor": asyncio.create_task(self._process_loop()),
            "shadow_analyzer": asyncio.create_task(self.shadow_analyzer.run()),
        }

        # Start scalable agents at configured counts
        self._scale_agents("fixer", self._current_counts.get("fixer", 2))
        self._scale_agents("reviewer", self._current_counts.get("reviewer", 1))

        # Re-enqueue stale tickets from previous run
        for ticket in self._stale_tickets:
            attack = {
                "type": ticket.type,
                "severity": ticket.severity,
                "vulnerability": ticket.evidence,
                "evidence": ticket.evidence,
                "request": "",
                "fix_recommendation": "",
                "_event_id": ticket.id,
                "_dedup_key": ticket.dedup_key,
            }
            await self._exploit_queue.put(attack)
            logger.info("Re-enqueued stale ticket %s (%s)", ticket.id, ticket.type)
        self._stale_tickets.clear()

        # Watch for scaling changes
        scale_watcher = asyncio.create_task(self._watch_agent_counts())

        all_tasks = list(core_tasks.values()) + [scale_watcher]
        results = await asyncio.gather(*all_tasks, return_exceptions=True)
        for task, result in zip(all_tasks, results):
            if isinstance(result, Exception):
                logger.error("Task crashed: %s", result)

    def _scale_agents(self, agent_type: str, desired: int) -> None:
        """Scale agent instances up or down. Max 3 per type."""
        desired = max(1, min(3, desired))
        current = sum(1 for name in self._agent_tasks
                      if name.startswith(f"{agent_type}_"))

        if desired == current:
            return

        if agent_type == "fixer":
            queue = self._exploit_queue
            make_handler = lambda name: lambda item: self._run_fixer(item, name)
        elif agent_type == "reviewer":
            queue = self._review_queue
            make_handler = lambda name: lambda item: self._run_reviewer(item)
        else:
            return

        if desired > current:
            # Scale up
            for i in range(current + 1, desired + 1):
                name = f"{agent_type}_{i}"
                if name not in self._agent_tasks:
                    handler = make_handler(name)
                    task = asyncio.create_task(self._agent_loop(name, queue, handler))
                    self._agent_tasks[name] = task
                    logger.info("Spawned agent: %s", name)
        else:
            # Scale down — cancel highest-numbered instances
            to_remove = []
            for name in sorted(self._agent_tasks.keys(), reverse=True):
                if name.startswith(f"{agent_type}_") and len(to_remove) < current - desired:
                    to_remove.append(name)
            for name in to_remove:
                self._agent_tasks[name].cancel()
                del self._agent_tasks[name]
                logger.info("Stopped agent: %s", name)

        self._current_counts[agent_type] = desired

    async def _watch_agent_counts(self) -> None:
        """Poll config/agent_counts.json for scaling changes."""
        while True:
            await asyncio.sleep(3)
            if not self._agent_counts_file.exists():
                continue
            try:
                desired = json.loads(self._agent_counts_file.read_text())
                for agent_type in ("fixer", "reviewer"):
                    count = desired.get(agent_type)
                    if count is not None and count != self._current_counts.get(agent_type):
                        self._scale_agents(agent_type, count)
            except (json.JSONDecodeError, OSError):
                pass

    def get_agent_counts(self) -> dict:
        """Return current agent instance counts."""
        return dict(self._current_counts)

    async def _agent_loop(self, name: str, queue: asyncio.Queue, handler) -> None:
        """Generic resilient agent loop — pulls from queue, calls handler,
        catches all errors, and keeps going."""
        logger.info("Agent loop '%s' started", name)
        while True:
            item = await queue.get()
            try:
                await handler(item)
            except Exception as e:
                logger.error("Agent '%s' error (continuing): %s", name, e, exc_info=True)
                # Reset ticket status if the handler crashed
                try:
                    event_id = None
                    if isinstance(item, dict):
                        event_id = item.get("_event_id")
                    elif isinstance(item, tuple) and len(item) >= 1:
                        event_id = getattr(item[0], "event_id", None)
                    if event_id:
                        self._update_ticket(event_id, status=TicketStatus.QUEUED.value, agent="")
                        self._audit("error", event_id, name, f"Agent crashed: {e}")
                except Exception:
                    pass

    async def _scan_loop(self, interval: float) -> None:
        """Continuously scan logs for new events."""
        while True:
            try:
                events = self.watcher.scan_new_lines()
                for event in events:
                    self._audit("detection", event.event_id, "watcher",
                                f"Detected {event.event_type} [{event.severity.value}]")

                    # Create a pipeline ticket for dashboard visibility
                    self._update_ticket(
                        event.event_id,
                        type=event.event_type,
                        endpoint=event.evidence.get("path", ""),
                        severity=event.severity.value,
                        status=TicketStatus.DETECTED.value,
                        evidence=f"{event.event_type} [{event.severity.value}] from {event.evidence.get('source_ip', '')}",
                        dedup_key=f"watcher|{event.event_type}|{event.evidence.get('source_ip', '')}",
                    )

                    # Score session IMMEDIATELY — never delay redirect decisions
                    try:
                        await self._take_immediate_action(event)
                    except Exception as e:
                        logger.error("Scoring failed for %s: %s", event.event_id, e)

                    # Critical events skip the batch queue for further processing
                    if event.severity == Severity.CRITICAL:
                        await self._event_queue.put(event)
                    else:
                        self._batch_buffer[event.severity].append(event)

                # Flush batches based on delay config
                await self._flush_batches()

            except Exception as e:
                logger.error("Scan loop error: %s", e)

            await asyncio.sleep(interval)

    async def _flush_batches(self) -> None:
        """Move buffered events to the processing queue based on delay config."""
        delays = self.budgets.get("batching", {})
        now = time.time()

        for severity in [Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            delay_key = f"{severity.value}_delay_seconds"
            max_delay = delays.get(delay_key, 60)
            buffer = self._batch_buffer[severity]

            ready = [e for e in buffer if now - e.timestamp >= max_delay]
            for event in ready:
                await self._event_queue.put(event)
                buffer.remove(event)

    async def _process_loop(self) -> None:
        """Process events through the full agent pipeline."""
        while True:
            event = await self._event_queue.get()
            try:
                await self._handle_event(event)
            except Exception as e:
                logger.error("Pipeline error for %s: %s", event.event_id, e)
                self._audit("error", event.event_id, "orchestrator", str(e))

    async def _handle_event(self, event: SecurityEvent) -> None:
        """Event handling — scoring already happened in _scan_loop.

        The Fixer pipeline is triggered separately by the Shadow Analyzer
        when it observes successful exploits in the shadow environment.
        """
        logger.info("Processing event %s: %s [%s]",
                     event.event_id, event.event_type, event.severity.value)

        self._audit("event_recorded", event.event_id, "orchestrator",
                     f"{event.event_type} [{event.severity.value}]")

    async def _on_analyzer_cycle(self, n_entries: int, n_attacks: int) -> None:
        """Called after each shadow analyzer cycle."""
        if n_attacks > 0:
            self._audit("shadow_analysis_complete", "system", "shadow_analyzer",
                         f"Analyzed {n_entries} entries — {n_attacks} exploit(s) detected")
        else:
            self._audit("shadow_analysis_complete", "system", "shadow_analyzer",
                         f"Analyzed {n_entries} entries — no exploits detected")

    async def _enqueue_exploit(self, attack: dict) -> None:
        """Called by ShadowAnalyzer — drops the exploit into the fixer queue.
        Deduplicates by type+endpoint — same vuln type on different endpoints
        are treated as different vulnerabilities."""
        import uuid, re

        exploit_type = attack.get("type", "unknown")
        request_line = attack.get("request", "")

        # Extract endpoint path from request line (e.g. "GET /workshop/api/mechanic/..." → "/mechanic/")
        path_match = re.search(r'(?:GET|POST|PUT|DELETE|PATCH)\s+(\S+)', request_line)
        endpoint = path_match.group(1) if path_match else ""
        # Normalize: strip query params, keep first 3 path segments
        endpoint = endpoint.split("?")[0]
        parts = endpoint.strip("/").split("/")
        endpoint = "/".join(parts[:4]) if parts else ""

        dedup_key = f"{exploit_type}|{endpoint}"
        attack["_dedup_key"] = dedup_key

        if dedup_key in self._fixed_vulns:
            logger.debug("Skipping already-fixed: %s", dedup_key)
            return
        if dedup_key in self._pending_vulns:
            logger.debug("Skipping duplicate queued: %s", dedup_key)
            return

        event_id = f"shadow_{uuid.uuid4().hex[:8]}"
        attack["_event_id"] = event_id
        vuln_key = attack.get("vulnerability", "")
        severity = attack.get("severity", "high")

        self._audit("shadow_exploit_detected", event_id, "shadow_analyzer",
                     f"type={exploit_type} severity={severity} "
                     f"vuln={vuln_key} request={request_line}")

        self._update_ticket(
            event_id,
            type=exploit_type,
            endpoint=endpoint,
            severity=severity,
            status=TicketStatus.QUEUED.value,
            evidence=f"type={exploit_type} severity={severity} vuln={vuln_key} request={request_line}",
            dedup_key=dedup_key,
        )

        self._pending_vulns.add(dedup_key)
        await self._exploit_queue.put(attack)
        logger.info(
            "Exploit queued for Fixer: type=%s severity=%s",
            exploit_type, severity,
        )

    # ── Fixer agent ──────────────────────────────────────────────

    async def _run_fixer(self, attack: dict, agent_name: str = "fixer_1") -> None:
        """Fixer handler — generates a patch inside the running container."""
        from harness.types import TriageResult

        exploit_type = attack.get("type", "unknown")
        severity = attack.get("severity", "high")
        vuln = attack.get("vulnerability", "")
        fix_rec = attack.get("fix_recommendation", "")
        evidence = attack.get("evidence", "")

        event_id = attack.get("_event_id", f"shadow_{__import__('uuid').uuid4().hex[:8]}")

        logger.warning(
            "%s: type=%s severity=%s vuln=%s",
            agent_name, exploit_type, severity, vuln[:80],
        )

        triage = TriageResult(
            event_id=event_id,
            is_threat=True,
            classification=exploit_type,
            confidence=0.9,
            severity=Severity(severity),
            recommended_action=fix_rec,
            analysis=f"Shadow LLM analysis: {vuln}. Evidence: {evidence}. Request: {attack.get('request', '')}",
            approval_policy=ApprovalPolicy.AUTO_APPLY_NOTIFY,
        )

        rejections = attack.get("_rejections", [])
        retry_label = f" (retry #{len(rejections)})" if rejections else ""
        self._audit("fixer_started", event_id, agent_name,
                     f"Fixing{retry_label} {exploit_type}: {vuln}")
        self._update_ticket(event_id, status=TicketStatus.FIXING.value,
                            agent=agent_name, retry_count=len(rejections))
        def _on_tool(cmd):
            self._audit("tool_call", event_id, agent_name, cmd)

        def _on_prompt(_sys_prompt, user_prompt):
            self._audit("user_prompt", event_id, agent_name, user_prompt)

        patch = await self.fixer.generate_patch(
            triage, rejections=rejections, on_tool_call=_on_tool,
            on_prompt_built=_on_prompt, agent_name=agent_name)
        dedup_key = attack.get("_dedup_key", f"{exploit_type}|unknown")

        if patch is None:
            fixer_retries = attack.get("_fixer_retries", 0)
            max_fixer_retries = 3
            self._audit("patch_failed", event_id, agent_name,
                         f"{exploit_type} — Fixer failed to generate a patch"
                         f" (attempt {fixer_retries + 1}/{max_fixer_retries})")
            if fixer_retries + 1 < max_fixer_retries:
                # Re-enqueue with incremented retry count
                attack["_fixer_retries"] = fixer_retries + 1
                self._update_ticket(event_id, status=TicketStatus.QUEUED.value, agent="")
                await self._exploit_queue.put(attack)
                logger.info("Re-queued %s for fixer retry %d/%d",
                            event_id, fixer_retries + 2, max_fixer_retries)
            else:
                # Max retries exhausted — give up
                self._audit("patch_abandoned", event_id, agent_name,
                             f"{exploit_type} — Fixer gave up after {max_fixer_retries} attempts")
                self._update_ticket(event_id, status=TicketStatus.DETECTED.value, agent="")
                self._pending_vulns.discard(dedup_key)
                logger.warning("Fixer gave up on %s after %d attempts",
                               event_id, max_fixer_retries)
            return

        # Mark as fixed — don't re-fix
        self._fixed_vulns.add(dedup_key)
        self._pending_vulns.discard(dedup_key)

        # Save patch to disk so dashboard can display it
        self._save_patch(patch, triage, dedup_key)

        self._audit("patch_proposed", event_id, agent_name,
                     f"{exploit_type} — {patch.description}")
        self._update_ticket(event_id, status=TicketStatus.PENDING_REVIEW.value,
                            agent="", patch_id=patch.patch_id,
                            patch_description=patch.description,
                            patch_files=patch.files_modified)

        # Hand off to reviewer (include original attack for re-queue on rejection)
        await self._review_queue.put((triage, patch, attack))

    # ── Reviewer agent ───────────────────────────────────────────

    async def _run_reviewer(self, item: tuple) -> None:
        """Reviewer handler — checks patch scope and functionality, then deploys."""
        triage, patch, attack = item
        event_id = triage.event_id
        dedup_key = attack.get("_dedup_key", "")

        self._update_ticket(event_id, status=TicketStatus.REVIEWING.value, agent="reviewer")

        def _on_review_prompt(_sys_prompt, user_prompt):
            self._audit("user_prompt", event_id, "reviewer", user_prompt)

        def _on_review_tool(cmd):
            self._audit("tool_call", event_id, "reviewer", cmd)

        review = await self.reviewer.review(triage, patch, on_prompt_built=_on_review_prompt, on_tool_call=_on_review_tool)
        if review and not review.approved:
            self._audit("review_rejected", event_id, "reviewer",
                         f"Patch rejected: {review.issues}")
            logger.warning("Patch %s rejected: %s", patch.patch_id, review.issues)
            # Remove from fixed so it can be retried
            self._fixed_vulns.discard(dedup_key)
            # Attach rejection history so fixer knows what NOT to do
            prev_rejections = attack.get("_rejections", [])
            prev_rejections.append({
                "patch_description": patch.description,
                "issues": review.issues,
                "suggestion": review.suggestion if hasattr(review, 'suggestion') else "",
            })
            attack["_rejections"] = prev_rejections
            self._update_ticket(event_id, status=TicketStatus.QUEUED.value,
                                agent="", retry_count=len(prev_rejections))
            # Re-queue for fixer to try again
            await self._exploit_queue.put(attack)
            logger.info("Re-queued rejected vuln for fixer (attempt %d): %s",
                        len(prev_rejections), dedup_key)
            return

        # Deploy: rebuild/reload affected services
        await self._deploy_patch(patch, event_id)
        self._update_ticket(event_id, status=TicketStatus.DEPLOYED.value)

        self._audit("deployed", event_id, "reviewer",
                     f"Approved and deployed: {triage.classification} — {patch.description}")
        logger.info(
            "EXPLOIT FIXED: type=%s patch=%s — %s",
            triage.classification, patch.patch_id, patch.description,
        )

    async def _deploy_patch(self, patch, event_id: str) -> None:
        """Rebuild/reload affected services after patch is approved."""
        import subprocess

        files = patch.files_modified or []
        services_to_rebuild = set()
        services_to_reload = set()

        for f in files:
            f_lower = f.lower()
            if "workshop" in f_lower:
                services_to_reload.add(("crapi-workshop", "docker exec crapi-workshop pkill -HUP -f gunicorn"))
                services_to_reload.add(("shadow-workshop", "docker exec shadow-workshop pkill -HUP -f gunicorn"))
            elif "identity" in f_lower:
                services_to_rebuild.add("crapi-identity")
                services_to_rebuild.add("shadow-identity")
            elif "community" in f_lower:
                services_to_rebuild.add("crapi-community")
                services_to_rebuild.add("shadow-community")
            elif "nginx" in f_lower:
                services_to_reload.add(("nginx-proxy", "docker exec nginx-proxy nginx -s reload"))

        # Hot-reload Python/nginx (instant)
        for name, cmd in services_to_reload:
            try:
                subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
                logger.info("Reloaded %s", name)
            except Exception as e:
                logger.error("Failed to reload %s: %s", name, e)

        # Rebuild compiled services (Java/Go)
        if services_to_rebuild:
            svc_list = " ".join(services_to_rebuild)
            cmd = f"docker compose up -d --build {svc_list}"
            logger.info("Rebuilding services: %s", svc_list)
            self._audit("rebuilding", event_id, "orchestrator",
                         f"Rebuilding: {svc_list}")
            try:
                subprocess.run(
                    cmd, shell=True, capture_output=True, timeout=300,
                    cwd=str(self.project_dir),
                )
                logger.info("Rebuild complete: %s", svc_list)
            except subprocess.TimeoutExpired:
                logger.error("Rebuild timed out for: %s", svc_list)
            except Exception as e:
                logger.error("Rebuild failed for %s: %s", svc_list, e)

    def _deploy(self, patch) -> None:
        """Apply a patch — save it and execute via control plane."""
        import json
        path = self.patches_dir / f"{patch.patch_id}.json"
        path.write_text(json.dumps(asdict(patch), indent=2))
        logger.info("Patch %s saved to %s", patch.patch_id, path)

    async def _take_immediate_action(self, event: SecurityEvent) -> None:
        """Score the session via control plane. When score exceeds threshold,
        the session is transparently redirected to the shadow environment.
        No blocking — we WANT the attacker to continue so we can observe."""
        # Extract session identifiers from the event
        token = event.evidence.get("auth_header_preview", "")
        log_line = event.evidence.get("log_line", "")

        # Try to extract the full auth token from the log line
        import re
        auth_match = re.search(r'auth="(Bearer [^"]+)"', log_line)
        if auth_match:
            token = auth_match.group(1)

        # Build IP:UserAgent composite fingerprint (matches nginx Lua logic)
        source_ip = event.evidence.get("source_ip", "")
        user_agent = event.evidence.get("user_agent", "")
        if not user_agent and log_line:
            # Fallback: extract from log line (format: ... "referer" "UA" rt=...)
            import re
            ua_match = re.search(r'" "([^"]*)" rt=', log_line)
            user_agent = ua_match.group(1) if ua_match else ""
        fingerprint = f"{source_ip}:{user_agent}" if source_ip else ""

        # Score the session
        try:
            result = await self.control_plane.score_session(
                event_type=event.event_type,
                severity=event.severity.value,
                token=token,
                ja3=fingerprint,
            )
            if result.get("redirected"):
                self._audit("session_redirected_to_shadow", event.event_id,
                            "orchestrator",
                            f"Session redirected after {event.event_type}")
                logger.warning(
                    "SESSION REDIRECTED TO SHADOW for %s (trigger: %s)",
                    event.event_id, event.event_type,
                )
                # Sync attacker's user record to shadow DB so their token works
                self._sync_attacker_to_shadow(token)
            # Also sync on subsequent events if token is present and session already in shadow
            elif token and token != "-":
                self._sync_attacker_to_shadow(token)
            else:
                self._audit("session_scored", event.event_id, "orchestrator",
                            f"Scored {event.event_type} [{event.severity.value}] "
                            f"identifiers={result.get('identifiers', [])}")
        except Exception as e:
            logger.error("Failed to score session for %s: %s", event.event_id, e)

    _synced_emails: set[str] = set()

    def _sync_attacker_to_shadow(self, token: str) -> None:
        """Extract email from JWT and sync user to shadow DB."""
        if not token or token == "-":
            return
        try:
            import jwt as pyjwt
            # Strip "Bearer " prefix
            raw = token.replace("Bearer ", "").strip()
            # Decode without verification (we just need the email)
            payload = pyjwt.decode(raw, options={"verify_signature": False})
            email = payload.get("sub", "")
            if not email:
                return
            if email in self._synced_emails:
                return
            self._synced_emails.add(email)
            from harness.shadow_user_sync import sync_user_to_shadow
            synced = sync_user_to_shadow(email)
            if synced:
                self._audit("shadow_user_synced", "system", "orchestrator",
                            f"Synced user {email} to shadow DB")
        except Exception as e:
            logger.error("Shadow user sync failed: %s", e)

    def _save_patch(self, patch, triage, dedup_key: str = "") -> None:
        """Save patch record to disk for the dashboard."""
        from dataclasses import asdict
        patch_data = asdict(patch)
        patch_data["classification"] = triage.classification
        patch_data["severity"] = triage.severity.value
        patch_data["analysis"] = triage.analysis[:300]
        patch_data["_dedup_key"] = dedup_key
        patch_file = self.patches_dir / f"{patch.patch_id}.json"
        patch_file.write_text(json.dumps(patch_data, indent=2, default=str))

    def _update_ticket(self, ticket_id: str, **kwargs) -> PipelineTicket:
        """Load existing ticket or create new, apply updates, save."""
        path = self.pipeline_dir / f"{ticket_id}.json"
        if path.exists():
            ticket = PipelineTicket.load(path)
        else:
            ticket = PipelineTicket(id=ticket_id)
        for k, v in kwargs.items():
            setattr(ticket, k, v)
        ticket.save(self.pipeline_dir)
        return ticket

    def _audit(self, action: str, event_id: str, agent: str, detail: str) -> None:
        """Write an immutable audit entry."""
        entry = AuditEntry(
            event_id=event_id,
            action=action,
            agent=agent,
            detail=detail,
            cost_usd=self.cost_governor._daily_spend,
        )
        entry.save(self.audit_dir)

    def _load_yaml(self, filename: str) -> dict:
        path = self.config_dir / filename
        if path.exists():
            return yaml.safe_load(path.read_text()) or {}
        logger.warning("Config file %s not found, using defaults", path)
        return {}
