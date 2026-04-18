"""Reviewer agent — evaluates patches for correctness and security.

Separate from the Fixer so it can't be lenient about its own work.
This is the generator-evaluator separation from the Anthropic harness article.

Uses LLM with a sandboxed bash tool that only allows
docker exec commands into whitelisted containers.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import asdict

from harness.agents.llm_runner import run_agent
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
3. **Functionality check**: Could this patch break normal user workflows? \
Consider: login, signup, viewing vehicles, placing orders, applying coupons, \
contacting mechanics, viewing reports, community posts. If the patch adds \
input validation, does it reject legitimate input? If it adds auth checks, \
does it block authorized users?
4. **SCOPE CHECK (critical)**: Does the patch ONLY fix the specific vulnerability \
in the threat report? REJECT if it also fixes other bugs, adds comments, \
refactors code, adds type hints, or makes any change not directly needed \
for this specific fix. The patch must be laser-focused.
5. Do NOT reject based on rollback path format — paths like crapi-fork/... are correct \
(they are host filesystem paths, not container paths).

## Verification
The "diff" field above contains an approximate diff of the code changes. \
Use it to understand the intent of the patch, but ALWAYS read the actual \
patched file from crapi-fork/ on the host filesystem to verify correctness. \
Check that the fix is syntactically valid and wouldn't cause runtime crashes.

## Response format (JSON only, no markdown fencing)
{{
  "approved": true/false,
  "issues": ["list of issues found, empty if none"],
  "security_concerns": ["any new security risks introduced"],
  "functionality_impact": "none|minor|breaking — assessment of impact on normal user flows",
  "suggestion": "what to change if not approved, empty string if approved"
}}

Be strict but practical. REJECT if the patch could break normal functionality. \
APPROVE if the fix is correct, scoped, and safe for users.
"""

SYSTEM_PROMPT = (
    "You are a strict security reviewer. Use docker exec to verify patches "
    "inside containers if needed. Your FINAL message must be ONLY a JSON "
    "object with the response format specified. No explanation, no markdown, "
    "no code fences — just the raw JSON object."
)

REVIEW_COST_ESTIMATE = 0.02


class Reviewer:
    """Reviews patches for correctness and security soundness."""

    def __init__(self, cost_governor: CostGovernor, project_dir: str = "."):
        self.cost_governor = cost_governor
        self.project_dir = project_dir

    def get_system_prompt(self) -> str:
        return SYSTEM_PROMPT

    async def review(self, triage: TriageResult, patch: PatchProposal, on_prompt_built: callable = None, on_tool_call: callable = None) -> ReviewResult | None:
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

        if on_prompt_built:
            on_prompt_built(SYSTEM_PROMPT, prompt)

        max_retries = 3
        response_text = ""
        actual_cost = 0.0
        for attempt in range(max_retries):
            try:
                response_text, actual_cost = await asyncio.wait_for(
                    run_agent(
                        prompt=prompt,
                        system_prompt=SYSTEM_PROMPT,
                        max_turns=15,
                        on_tool_call=on_tool_call,
                        role="reviewer",
                    ),
                    timeout=180,  # 3 minute hard cap per attempt
                )
                break  # success
            except asyncio.TimeoutError:
                logger.error(
                    "Reviewer timed out for %s (attempt %d/%d): exceeded 3min cap",
                    patch.patch_id, attempt + 1, max_retries,
                )
                if attempt >= max_retries - 1:
                    return None
            except Exception as e:
                logger.error(
                    "Reviewer LLM call failed for %s (attempt %d/%d): %s",
                    patch.patch_id, attempt + 1, max_retries, e,
                )
                if attempt < max_retries - 1:
                    wait = 5 * (attempt + 1)
                    logger.info("Retrying in %ds...", wait)
                    await asyncio.sleep(wait)
                else:
                    return None

        self.cost_governor.record_spend(triage.event_id, actual_cost)

        try:
            text = response_text.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1].rsplit("```", 1)[0]
            start = text.find("{")
            end = text.rfind("}") + 1
            if start >= 0 and end > start:
                text = text[start:end]
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
