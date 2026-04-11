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
from harness.agents.tester import Tester
from harness.agents.watcher import Watcher
from harness.control_plane_client import ControlPlaneClient
from harness.cost_governor import CostGovernor
from harness.shadow_analyzer import ShadowAnalyzer
from harness.types import (
    ApprovalPolicy,
    AuditEntry,
    EventStatus,
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
        self.tester = Tester(self.cost_governor, app_url, str(project_dir))

        # Inter-agent queues
        self._exploit_queue: asyncio.Queue[dict] = asyncio.Queue()
        self._review_queue: asyncio.Queue[tuple] = asyncio.Queue()  # (triage, patch)
        self._test_queue: asyncio.Queue[tuple] = asyncio.Queue()    # (triage, patch)

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

    async def run(self, poll_interval: float = 2.0) -> None:
        """Main loop — six parallel agent loops connected by queues.

        Scanner → scores sessions, redirects to shadow
        Shadow Analyzer → detects exploits → exploit_queue
        Fixer → patches containers → review_queue
        Reviewer → checks patch scope → test_queue
        Tester → validates no regressions → marks deployed
        Process → handles batched events
        """
        logger.info("Reactive Defender started. Watching %s", self.watcher.log_path)
        logger.info("Budget: $%.2f/day, $%.2f/incident",
                     self.cost_governor.daily_budget,
                     self.cost_governor.per_incident_cap)
        logger.info("Shadow analyzer: every %.0fs on %s",
                     self.shadow_analyzer.interval,
                     self.shadow_analyzer.shadow_log_path)

        loops = {
            "scanner": self._scan_loop(poll_interval),
            "processor": self._process_loop(),
            "shadow_analyzer": self.shadow_analyzer.run(),
            "fixer": self._agent_loop("fixer", self._exploit_queue, self._run_fixer),
            "reviewer": self._agent_loop("reviewer", self._review_queue, self._run_reviewer),
            "tester": self._agent_loop("tester", self._test_queue, self._run_tester),
        }

        results = await asyncio.gather(
            *loops.values(), return_exceptions=True,
        )
        for name, result in zip(loops.keys(), results):
            if isinstance(result, Exception):
                logger.error("Task %s crashed: %s", name, result)

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

                    # Critical events skip the batch queue
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
        """Event handling: score session → redirect to shadow if threshold met.

        The Fixer pipeline is triggered separately by the Shadow Analyzer
        when it observes successful exploits in the shadow environment.
        """
        logger.info("Processing event %s: %s [%s]",
                     event.event_id, event.event_type, event.severity.value)

        # Score and redirect
        try:
            await self._take_immediate_action(event)
        except Exception as e:
            logger.error("Scoring failed for %s: %s", event.event_id, e)

        self._audit("event_recorded", event.event_id, "orchestrator",
                     f"{event.event_type} [{event.severity.value}]")

    async def _enqueue_exploit(self, attack: dict) -> None:
        """Called by ShadowAnalyzer — drops the exploit into the fixer queue."""
        await self._exploit_queue.put(attack)
        logger.info(
            "Exploit queued for Fixer: type=%s severity=%s",
            attack.get("type"), attack.get("severity"),
        )

    # ── Fixer agent ──────────────────────────────────────────────

    async def _run_fixer(self, attack: dict) -> None:
        """Fixer handler — generates a patch inside the running container."""
        import uuid
        from harness.types import TriageResult

        exploit_type = attack.get("type", "unknown")
        severity = attack.get("severity", "high")
        vuln = attack.get("vulnerability", "")
        fix_rec = attack.get("fix_recommendation", "")
        evidence = attack.get("evidence", "")
        request_line = attack.get("request", "")

        event_id = f"shadow_{uuid.uuid4().hex[:8]}"

        logger.warning(
            "FIXER: type=%s severity=%s vuln=%s",
            exploit_type, severity, vuln[:80],
        )
        self._audit("shadow_exploit_detected", event_id, "shadow_analyzer",
                     f"type={exploit_type} severity={severity} "
                     f"vuln={vuln[:100]} request={request_line[:100]}")

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

        patch = await self.fixer.generate_patch(triage)
        if patch is None:
            self._audit("error", event_id, "fixer",
                         f"Patch generation failed for: {exploit_type}")
            return

        # Save patch to disk so dashboard can display it
        self._save_patch(patch, triage)

        self._audit("patch_proposed", event_id, "fixer",
                     f"exploit={exploit_type} files={patch.files_modified}")

        # Hand off to reviewer
        await self._review_queue.put((triage, patch))

    # ── Reviewer agent ───────────────────────────────────────────

    async def _run_reviewer(self, item: tuple) -> None:
        """Reviewer handler — checks that the patch is scoped correctly."""
        triage, patch = item
        event_id = triage.event_id

        review = await self.reviewer.review(triage, patch)
        if review and not review.approved:
            self._audit("review_rejected", event_id, "reviewer",
                         f"Patch rejected: {review.issues}")
            logger.warning("Patch %s rejected: %s", patch.patch_id, review.issues)
            return

        self._audit("review_passed", event_id, "reviewer",
                     f"Patch approved: {patch.description}")

        # Hand off to tester
        await self._test_queue.put((triage, patch))

    # ── Tester agent ─────────────────────────────────────────────

    async def _run_tester(self, item: tuple) -> None:
        """Tester handler — validates no regressions, marks as deployed."""
        triage, patch = item
        event_id = triage.event_id

        test_result = await self.tester.test_patch(patch)
        if test_result and not test_result.passed and not test_result.is_minor:
            self._audit("test_failed", event_id, "tester",
                         f"Regression: {test_result.complaint}")
            logger.warning("Patch %s failed testing: %s", patch.patch_id, test_result.complaint)
            return

        self._audit("deployed", event_id, "orchestrator",
                     f"Fixed: {triage.classification} — {patch.description}")
        logger.info(
            "EXPLOIT FIXED: type=%s patch=%s — %s",
            triage.classification, patch.patch_id, patch.description,
        )

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
