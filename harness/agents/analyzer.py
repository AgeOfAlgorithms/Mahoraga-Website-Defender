"""Analyzer agent — LLM-powered triage of SecurityEvents.

Uses Haiku for known-pattern classification, Sonnet for novel anomalies.
Produces TriageResults that determine whether the Fixer should act.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict

from claude_agent_sdk import query, ClaudeAgentOptions, AssistantMessage, TextBlock

from harness.cost_governor import CostGovernor
from harness.types import (
    ApprovalPolicy,
    SecurityEvent,
    Severity,
    TriageResult,
)

logger = logging.getLogger(__name__)

TRIAGE_PROMPT = """\
You are a security analyst triaging a detected event from a web application's \
intrusion detection system. Analyze the evidence and respond with a JSON object.

## Event
{event_json}

## Response format (JSON only, no markdown fencing)
{{
  "is_threat": true/false,
  "classification": "sql_injection|xss|path_traversal|command_injection|brute_force|rate_abuse|sensitive_exposure|false_positive|other",
  "confidence": 0.0-1.0,
  "severity": "critical|high|medium|low|info",
  "recommended_action": "brief description of what to do",
  "analysis": "2-3 sentence explanation",
  "approval_policy": "auto_apply|auto_apply_notify|human_required"
}}

## Approval policy guidelines
- auto_apply: IP blocks, rate-limit increases, WAF rule additions
- auto_apply_notify: Config changes, temporary blocks, adding security headers
- human_required: Code patches, database changes, firewall rule deletions

Be conservative: when in doubt, set approval_policy to "human_required".
"""

# Estimated cost per call (conservative upper bound)
HAIKU_COST_ESTIMATE = 0.005
SONNET_COST_ESTIMATE = 0.03


class Analyzer:
    """Triages SecurityEvents using Claude."""

    def __init__(self, cost_governor: CostGovernor, project_dir: str = "."):
        self.cost_governor = cost_governor
        self.project_dir = project_dir

    async def triage(self, event: SecurityEvent) -> TriageResult | None:
        """Analyze a security event and return a triage result."""
        # Pick model tier based on whether this is a known pattern
        is_known = event.event_type in {
            "sql_injection", "xss_attempt", "path_traversal",
            "command_injection", "auth_brute_force_signal",
            "sensitive_file_access", "rate_limit_exceeded",
        }
        cost_estimate = HAIKU_COST_ESTIMATE if is_known else SONNET_COST_ESTIMATE

        if not self.cost_governor.can_spend(event.event_id, cost_estimate):
            logger.warning("Budget exceeded, escalating event %s to human", event.event_id)
            return TriageResult(
                event_id=event.event_id,
                is_threat=True,
                classification="budget_escalation",
                confidence=0.0,
                severity=event.severity,
                recommended_action="Human review required — budget limit reached",
                analysis="Cost governor blocked LLM analysis. Manual triage needed.",
                approval_policy=ApprovalPolicy.HUMAN_REQUIRED,
            )

        event_json = json.dumps(asdict(event), indent=2, default=str)
        prompt = TRIAGE_PROMPT.format(event_json=event_json)

        options = ClaudeAgentOptions(
            system_prompt="You are a security triage analyst. Respond with JSON only.",
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
            logger.error("Analyzer LLM call failed for %s: %s", event.event_id, e)
            return None

        self.cost_governor.record_spend(event.event_id, cost_estimate)

        try:
            # Strip markdown fencing if present
            text = response_text.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1].rsplit("```", 1)[0]
            data = json.loads(text)
        except json.JSONDecodeError:
            logger.error("Failed to parse analyzer response: %s", response_text[:200])
            return None

        return TriageResult(
            event_id=event.event_id,
            is_threat=data.get("is_threat", True),
            classification=data.get("classification", "unknown"),
            confidence=data.get("confidence", 0.5),
            severity=Severity(data.get("severity", "medium")),
            recommended_action=data.get("recommended_action", ""),
            analysis=data.get("analysis", ""),
            approval_policy=ApprovalPolicy(data.get("approval_policy", "human_required")),
        )
