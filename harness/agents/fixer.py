"""Fixer agent — patches the specific vulnerability in the RUNNING containers.

CRITICAL CONSTRAINTS:
1. Only fix the SINGLE vulnerability described in the triage report
2. Edit files that the running containers actually serve from
3. Do NOT fix other bugs found along the way

Deployment targets:
- Workshop (Python/Django): mounted volume at ./crapi-fork/services/workshop/
  → container reads from /app/ → Django auto-reloads on file change (~2s)
- Vuln chains (Python): mounted volume at ./vuln_chains/
  → container reads from /app/ → uvicorn auto-reloads (~1s)
- Control plane (Python): mounted volume at ./control_plane/
  → container reads from /app/ → uvicorn auto-reloads (~1s)
- Identity (Java): source at ./crapi-fork/services/identity/
  → requires rebuild + restart (not hot-patchable)
- Community (Go): source at ./crapi-fork/services/community/
  → requires rebuild + restart (not hot-patchable)
- Nginx: config at ./nginx/nginx.conf
  → requires `docker compose restart nginx` (~1s)

For Java/Go services, the Fixer edits source and flags that a rebuild is needed.
The orchestrator handles the rebuild + restart.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict
from pathlib import Path

from claude_agent_sdk import query, ClaudeAgentOptions, AssistantMessage, TextBlock

from harness.cost_governor import CostGovernor
from harness.types import PatchProposal, TriageResult

logger = logging.getLogger(__name__)

FIX_PROMPT = """\
You are a security engineer patching ONE specific vulnerability in a RUNNING
web application. Your edits will be applied to the live service immediately.

## Exploit Report (from shadow environment)
{triage_json}

## Editable paths (these are mounted into running containers)
- Workshop (Python/Django): {workshop_dir}/crapi/
  Hot-reloads automatically on save.
- Custom vuln chains (Python): {vuln_chains_dir}/chains/
  Hot-reloads automatically on save.
- Nginx config: {nginx_dir}/nginx.conf
  Requires restart after edit.
- Identity (Java): {identity_dir}/src/main/java/com/crapi/
  Requires rebuild — edit only if absolutely necessary.
- Community (Go): {community_dir}/api/
  Requires rebuild — edit only if absolutely necessary.

## STRICT RULES
1. Fix ONLY the vulnerability described above — NOTHING else
2. Do NOT fix other bugs or vulnerabilities you notice
3. Do NOT refactor, add comments, add type hints, or improve code quality
4. Do NOT add error handling beyond what's needed for this specific fix
5. Make the MINIMUM change necessary to close this vulnerability
6. PREFER editing Python files (hot-reload) over Java/Go (needs rebuild)
7. If the fix is in Java or Go, set needs_rebuild to true

## Your task
1. Read the source files relevant to the exploit
2. Identify the exact lines that cause the vulnerability
3. Edit ONLY those lines
4. Report what you changed

## Response format (JSON only, no markdown fencing)
{{
  "patch_type": "code_fix",
  "description": "one sentence describing the fix",
  "vulnerability": "what was wrong",
  "files_modified": ["relative paths of files you edited"],
  "needs_rebuild": false,
  "needs_restart": ["list of services that need restart, e.g. nginx"],
  "changes_summary": "what specifically was changed"
}}
"""

CODE_FIX_COST_ESTIMATE = 0.15


class Fixer:
    """Patches the specific vulnerability in running containers."""

    def __init__(
        self,
        cost_governor: CostGovernor,
        project_dir: str = ".",
    ):
        self.cost_governor = cost_governor
        self.project_dir = Path(project_dir)
        self.workshop_dir = self.project_dir / "crapi-fork" / "services" / "workshop"
        self.vuln_chains_dir = self.project_dir / "vuln_chains"
        self.nginx_dir = self.project_dir / "nginx"
        self.identity_dir = self.project_dir / "crapi-fork" / "services" / "identity"
        self.community_dir = self.project_dir / "crapi-fork" / "services" / "community"

    async def generate_patch(self, triage: TriageResult) -> PatchProposal | None:
        """Generate and apply a patch for the exploited vulnerability."""
        if not self.cost_governor.can_spend(triage.event_id, CODE_FIX_COST_ESTIMATE):
            logger.warning("Budget exceeded, cannot patch for %s", triage.event_id)
            return None

        triage_json = json.dumps(asdict(triage), indent=2, default=str)
        prompt = FIX_PROMPT.format(
            triage_json=triage_json,
            workshop_dir=self.workshop_dir,
            vuln_chains_dir=self.vuln_chains_dir,
            nginx_dir=self.nginx_dir,
            identity_dir=self.identity_dir,
            community_dir=self.community_dir,
        )

        options = ClaudeAgentOptions(
            system_prompt=(
                "You are a security engineer. Fix ONLY the specific vulnerability "
                "described in the triage report. Do NOT fix anything else. "
                "Make the minimum change necessary. Respond with JSON only."
            ),
            max_turns=10,
            allowed_tools=["Read", "Edit", "Glob", "Grep"],
            cwd=str(self.project_dir),
        )

        response_text = ""
        try:
            async for message in query(prompt=prompt, options=options):
                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, TextBlock):
                            response_text += block.text
        except Exception as e:
            logger.error("Fixer LLM call failed for %s: %s", triage.event_id, e)
            return None

        self.cost_governor.record_spend(triage.event_id, CODE_FIX_COST_ESTIMATE)

        try:
            text = response_text.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1].rsplit("```", 1)[0]
            data = json.loads(text)
        except json.JSONDecodeError:
            logger.error("Failed to parse fixer response: %s", response_text[:200])
            return None

        files_modified = data.get("files_modified", [])
        needs_rebuild = data.get("needs_rebuild", False)
        needs_restart = data.get("needs_restart", [])

        if needs_rebuild:
            logger.warning("Patch requires rebuild of: %s", needs_restart)

        if needs_restart:
            logger.info("Patch requires restart of: %s", needs_restart)

        return PatchProposal(
            event_id=triage.event_id,
            patch_type=data.get("patch_type", "code_fix"),
            description=data.get("description", ""),
            diff="",
            files_modified=files_modified,
            rollback_steps=f"git checkout -- {' '.join(files_modified)}",
        )
