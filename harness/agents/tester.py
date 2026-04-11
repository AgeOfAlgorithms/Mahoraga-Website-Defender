"""Tester agent — simulates normal user flows after a fix is applied.

Validates that the patch hasn't broken functionality or degraded performance.
Uses Playwright MCP to interact with the live site as a real user would,
following the Anthropic article's pattern of live interaction over static analysis.

The Tester produces complaints when things break. Other agents can choose to
ignore minor complaints (is_minor=True) but must address major ones.
"""

from __future__ import annotations

import json
import logging

from claude_agent_sdk import query, ClaudeAgentOptions, AssistantMessage, TextBlock

from harness.cost_governor import CostGovernor
from harness.types import PatchProposal, TestResult

logger = logging.getLogger(__name__)

TEST_PROMPT = """\
You are a QA tester simulating a normal user of the crAPI web application \
(a vehicle service platform). A security patch was just applied and you need \
to verify the application still works correctly.

## Patch that was applied
{patch_json}

## Your task
Navigate to the application at {app_url} and perform these user flows:

1. **Homepage load** — does it render without errors?
2. **Vehicle dashboard** — can you view the vehicle dashboard and location?
3. **Community forum** — can you view posts and comments?
4. **Login flow** — can you access the login page? (don't need valid credentials)
5. **Shop** — can you browse products and the mechanic service?

For each flow:
- Note if it works, is broken, or is noticeably slower
- If something is broken, determine if it's likely caused by the patch

## Response format (JSON only, no markdown fencing)
{{
  "passed": true/false,
  "flows_tested": ["homepage", "vehicle_dashboard", "community", "login", "shop"],
  "regressions": ["list of broken things, empty if none"],
  "performance_impact": "none|minor|major",
  "complaint": "human-readable description of any issues, empty string if all good",
  "is_minor": true/false
}}

## Severity guidelines for is_minor
- minor (is_minor=true): Cosmetic issues, slightly slower load times (<2s increase),
  non-critical features affected
- major (is_minor=false): Core features broken, pages don't load, errors visible
  to users, significant performance degradation (>3s increase)

Be a demanding but fair tester. Report real issues, not nitpicks.
"""

TEST_COST_ESTIMATE = 0.04


class Tester:
    """Simulates user flows to catch regressions from patches."""

    def __init__(
        self,
        cost_governor: CostGovernor,
        app_url: str = "http://localhost:3000",
        project_dir: str = ".",
    ):
        self.cost_governor = cost_governor
        self.app_url = app_url
        self.project_dir = project_dir

    async def test_patch(self, patch: PatchProposal) -> TestResult | None:
        """Run user flow tests after a patch is applied."""
        if not self.cost_governor.can_spend(patch.event_id, TEST_COST_ESTIMATE):
            logger.warning("Budget exceeded, cannot test patch %s", patch.patch_id)
            return TestResult(
                patch_id=patch.patch_id,
                passed=False,
                regressions=["Budget limit — manual testing required"],
            )

        patch_json = json.dumps({
            "patch_id": patch.patch_id,
            "patch_type": patch.patch_type,
            "description": patch.description,
            "files_modified": patch.files_modified,
        }, indent=2)

        prompt = TEST_PROMPT.format(patch_json=patch_json, app_url=self.app_url)

        # Tester gets Playwright MCP for real browser interaction
        options = ClaudeAgentOptions(
            system_prompt=(
                "You are a QA tester. Use the browser tools to navigate the "
                "application and verify user flows work. Respond with JSON only."
            ),
            max_turns=10,  # needs multiple turns to navigate pages
            allowed_tools=["Read"],
            mcp_servers={
                "playwright": {
                    "type": "stdio",
                    "command": "npx",
                    "args": ["@anthropic/mcp-playwright"],
                },
            },
            cwd=self.project_dir,
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
            logger.error("Tester LLM call failed for %s: %s", patch.patch_id, e)
            return None

        self.cost_governor.record_spend(patch.event_id, TEST_COST_ESTIMATE)

        try:
            text = response_text.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1].rsplit("```", 1)[0]
            data = json.loads(text)
        except json.JSONDecodeError:
            logger.error("Failed to parse tester response: %s", response_text[:200])
            return None

        result = TestResult(
            patch_id=patch.patch_id,
            passed=data.get("passed", False),
            flows_tested=data.get("flows_tested", []),
            regressions=data.get("regressions", []),
            performance_impact=data.get("performance_impact", "none"),
            complaint=data.get("complaint", ""),
            is_minor=data.get("is_minor", False),
        )

        if result.complaint:
            level = "minor" if result.is_minor else "MAJOR"
            logger.warning(
                "Tester complaint [%s] for patch %s: %s",
                level, patch.patch_id, result.complaint,
            )

        return result
