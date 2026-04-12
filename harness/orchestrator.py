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
    SecurityEvent,
    Severity,
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

        # Dedup tracking — keyed on vulnerability description, not generic type
        self._pending_vulns: set[str] = set()   # vuln descriptions currently queued
        self._fixed_vulns: set[str] = set()     # vuln descriptions already patched

        # Restore fixed vulns from previous patches on disk
        for patch_file in self.patches_dir.glob("*.json"):
            try:
                data = json.loads(patch_file.read_text())
                # Use the analysis field which contains the specific vuln description
                analysis = data.get("analysis", "")[:80]
                if analysis:
                    self._fixed_vulns.add(analysis)
            except (json.JSONDecodeError, OSError):
                pass
        if self._fixed_vulns:
            logger.info("Restored %d fixed vulns from disk", len(self._fixed_vulns))

        # Shadow LLM analyzer — generic exploit detection every 15s
        self.shadow_analyzer = ShadowAnalyzer(
            shadow_log_path=project_dir / "logs" / "nginx" / "shadow.log",
            cost_governor=self.cost_governor,
            interval=15.0,
            on_exploit_detected=self._enqueue_exploit,
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

        # Start core loops (non-scalable singletons)
        core_tasks = {
            "scanner": asyncio.create_task(self._scan_loop(poll_interval)),
            "processor": asyncio.create_task(self._process_loop()),
            "shadow_analyzer": asyncio.create_task(self.shadow_analyzer.run()),
        }

        # Start scalable agents at configured counts
        self._scale_agents("fixer", self._current_counts.get("fixer", 2))
        self._scale_agents("reviewer", self._current_counts.get("reviewer", 1))

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

    async def _scan_loop(self, interval: float) -> None:
        """Continuously scan logs for new events."""
        while True:
            try:
                events = self.watcher.scan_new_lines()
                for event in events:
                    self._audit("detection", event.event_id, "watcher",
                                f"Detected {event.event_type} [{event.severity.value}]")

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

    async def _enqueue_exploit(self, attack: dict) -> None:
        """Called by ShadowAnalyzer — drops the exploit into the fixer queue.
        Deduplicates by vulnerability type — no point fixing the same thing twice."""
        import uuid

        vuln_key = attack.get("vulnerability", "")[:80]
        exploit_type = attack.get("type", "unknown")

        # Skip if we already fixed or are fixing this specific vulnerability
        if vuln_key in self._fixed_vulns:
            logger.debug("Skipping already-fixed vuln: %s", vuln_key[:50])
            return
        if vuln_key in self._pending_vulns:
            logger.debug("Skipping duplicate queued vuln: %s", vuln_key[:50])
            return

        # Assign event_id and emit audit NOW so kanban shows "Analyzing"
        # while it waits in the queue for the fixer to pick it up
        event_id = f"shadow_{uuid.uuid4().hex[:8]}"
        attack["_event_id"] = event_id
        request_line = attack.get("request", "")
        severity = attack.get("severity", "high")

        self._audit("shadow_exploit_detected", event_id, "shadow_analyzer",
                     f"type={exploit_type} severity={severity} "
                     f"vuln={vuln_key[:100]} request={request_line[:100]}")

        self._pending_vulns.add(vuln_key)
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
            analysis=f"Shadow LLM analysis: {vuln}. Evidence: {evidence[:200]}",
            approval_policy=ApprovalPolicy.AUTO_APPLY_NOTIFY,
        )

        self._audit("fixer_started", event_id, agent_name,
                     f"Fixing {exploit_type}: {vuln[:80]}")
        patch = await self.fixer.generate_patch(triage)
        if patch is None:
            self._audit("error", event_id, agent_name,
                         f"Patch generation failed for: {exploit_type}")
            self._pending_vulns.discard(vuln[:80])
            return

        # Mark this specific vulnerability as fixed — don't re-fix
        self._fixed_vulns.add(vuln[:80])
        self._pending_vulns.discard(vuln[:80])

        # Save patch to disk so dashboard can display it
        self._save_patch(patch, triage)

        self._audit("patch_proposed", event_id, agent_name,
                     f"exploit={exploit_type} files={patch.files_modified}")

        # Hand off to reviewer
        await self._review_queue.put((triage, patch))

    # ── Reviewer agent ───────────────────────────────────────────

    async def _run_reviewer(self, item: tuple) -> None:
        """Reviewer handler — checks patch scope and functionality, then deploys."""
        triage, patch = item
        event_id = triage.event_id

        review = await self.reviewer.review(triage, patch)
        if review and not review.approved:
            self._audit("review_rejected", event_id, "reviewer",
                         f"Patch rejected: {review.issues}")
            logger.warning("Patch %s rejected: %s", patch.patch_id, review.issues)
            return

        # Deploy: rebuild/reload affected services
        await self._deploy_patch(patch, event_id)

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
        # Extract User-Agent from log line (watcher doesn't always put it in evidence)
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
            else:
                self._audit("session_scored", event.event_id, "orchestrator",
                            f"Scored {event.event_type} [{event.severity.value}] "
                            f"identifiers={result.get('identifiers', [])}")
        except Exception as e:
            logger.error("Failed to score session for %s: %s", event.event_id, e)

    def _save_patch(self, patch, triage) -> None:
        """Save patch record to disk for the dashboard."""
        from dataclasses import asdict
        patch_data = asdict(patch)
        patch_data["classification"] = triage.classification
        patch_data["severity"] = triage.severity.value
        patch_data["analysis"] = triage.analysis[:300]
        patch_file = self.patches_dir / f"{patch.patch_id}.json"
        patch_file.write_text(json.dumps(patch_data, indent=2, default=str))

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
