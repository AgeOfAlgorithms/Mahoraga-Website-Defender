"""Reviewer agent — evaluates patches for correctness and security.

Separate from the Fixer so it can't be lenient about its own work.
This is the generator-evaluator separation from the Anthropic harness article.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict

from claude_agent_sdk import query, ClaudeAgentOptions, AssistantMessage, TextBlock

from harness.cost_governor import CostGovernor
from harness.types import PatchProposal, ReviewResult, TriageResult

logger = logging.getLogger(__name__)

REVIEW_PROMPT = """\
You are a senior security reviewer. A patch has been proposed to fix a \
vulnerability. Your job is to evaluate whether the patch is correct, safe, \
and does not introduce new issues.

## Original Threat
{triage_json}

## Proposed Patch
{patch_json}

## Review criteria
1. Does the patch actually fix the vulnerability described in the threat?
2. Does it introduce any new security issues (OWASP Top 10)?
3. Could it break existing functionality?
4. **SCOPE CHECK (critical)**: Does the patch ONLY fix the specific vulnerability \
in the threat report? REJECT if it also fixes other bugs, adds comments, \
refactors code, adds type hints, or makes any change not directly needed \
for this specific fix. The patch must be laser-focused.
5. Are the rollback steps adequate?

## OFF-LIMITS — do NOT read these files/directories
vuln_chains/, plant_flags.py, plant_shadow_flags.py, harness/, detection/,
config/, dashboard/, docker-compose.yml, start.sh, .env files.
Only review the application source code that was modified by the patch.

## Response format (JSON only, no markdown fencing)
{{
  "approved": true/false,
  "issues": ["list of issues found, empty if none"],
  "security_concerns": ["any new security risks introduced"],
  "suggestion": "what to change if not approved, empty string if approved"
}}

Be strict. If in doubt, reject. A false negative (missing a real issue) is \
much worse than a false positive (rejecting a good patch).
"""

REVIEW_COST_ESTIMATE = 0.05


class Reviewer:
    """Reviews patches for correctness and security soundness."""

    def __init__(self, cost_governor: CostGovernor, project_dir: str = "."):
        self.cost_governor = cost_governor
        self.project_dir = project_dir

    async def review(self, triage: TriageResult, patch: PatchProposal) -> ReviewResult | None:
        """Review a proposed patch."""
        if not self.cost_governor.can_spend(triage.event_id, REVIEW_COST_ESTIMATE):
            logger.warning("Budget exceeded, cannot review patch %s", patch.patch_id)
            return ReviewResult(
                patch_id=patch.patch_id,
                approved=False,
                issues=["Budget limit reached — human review required"],
            )

        triage_json = json.dumps(asdict(triage), indent=2, default=str)
        patch_json = json.dumps(asdict(patch), indent=2, default=str)
        prompt = REVIEW_PROMPT.format(triage_json=triage_json, patch_json=patch_json)

        options = ClaudeAgentOptions(
            system_prompt="You are a strict security reviewer. Respond with JSON only. "
                          "Use docker exec to verify patches inside containers if needed.",
            max_turns=3,
            allowed_tools=["Bash"],
            permission_mode="bypassPermissions",
        )

        response_text = ""
        try:
            async for message in query(prompt=prompt, options=options):
                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, TextBlock):
                            response_text += block.text
        except Exception as e:
            logger.error("Reviewer LLM call failed for %s: %s", patch.patch_id, e)
            return None

        self.cost_governor.record_spend(triage.event_id, REVIEW_COST_ESTIMATE)

        try:
            text = response_text.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1].rsplit("```", 1)[0]
            data = json.loads(text)
        except json.JSONDecodeError:
            logger.error("Failed to parse reviewer response: %s", response_text[:200])
            return None

        return ReviewResult(
            patch_id=patch.patch_id,
            approved=data.get("approved", False),
            issues=data.get("issues", []),
            security_concerns=data.get("security_concerns", []),
            suggestion=data.get("suggestion", ""),
        )
