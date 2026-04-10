"""Fixer agent — patches vulnerabilities inside RUNNING containers only.

CRITICAL: The fixer NEVER modifies source code on the host. All edits
happen inside Docker containers via `docker exec`. Changes are ephemeral
and lost when containers restart — source code stays clean.

Patchable containers:
- crapi-workshop (Python/Django): edits /app/crapi/ → auto-reloads
- nginx-proxy (OpenResty): edits /usr/local/openresty/nginx/conf/ → needs reload

Non-patchable (would need rebuild):
- crapi-identity (Java): compiled JAR, can't hot-patch
- crapi-community (Go): compiled binary, can't hot-patch
"""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import asdict

from claude_agent_sdk import query, ClaudeAgentOptions, AssistantMessage, TextBlock

from harness.cost_governor import CostGovernor
from harness.types import PatchProposal, TriageResult

logger = logging.getLogger(__name__)

FIX_PROMPT = """\
You are a security engineer patching ONE specific vulnerability in a RUNNING
web application. You will read and edit files INSIDE Docker containers — never
on the host filesystem.

## Exploit Report (from shadow environment)
{triage_json}

## How to read files inside containers
Use the Bash tool to run docker exec commands:
```
docker exec crapi-workshop cat /app/crapi/shop/views.py
docker exec crapi-workshop grep -n "vulnerable_pattern" /app/crapi/mechanic/views.py
docker exec nginx-proxy cat /usr/local/openresty/nginx/conf/nginx.conf
```

## How to apply patches inside containers
Use docker exec with sed or python to edit files in-place:
```
docker exec crapi-workshop sed -i 's/old_code/new_code/' /app/crapi/shop/views.py
docker exec crapi-workshop python3 -c "
import pathlib
p = pathlib.Path('/app/crapi/shop/views.py')
code = p.read_text()
code = code.replace('vulnerable_line', 'fixed_line')
p.write_text(code)
"
```

For nginx, edit the config then reload:
```
docker exec nginx-proxy sed -i 's/old_config/new_config/' /usr/local/openresty/nginx/conf/nginx.conf
docker exec nginx-proxy nginx -s reload
```

## Patchable containers
- **crapi-workshop** (Python/Django at /app/crapi/): auto-reloads on file change
- **nginx-proxy** (OpenResty at /usr/local/openresty/nginx/conf/): needs `nginx -s reload`

## NOT patchable (skip these)
- crapi-identity (Java JAR — can't hot-patch)
- crapi-community (Go binary — can't hot-patch)

## OFF-LIMITS — do NOT access
- Any file on the host filesystem
- vuln_chains/, plant_flags.py, harness/, detection/, config/, dashboard/
- Flag values, challenge descriptions, or test data
- Other containers' data (postgresdb, mongodb, redis)

## STRICT RULES
1. Fix ONLY the vulnerability described above — NOTHING else
2. Do NOT fix other bugs or vulnerabilities you notice
3. Do NOT refactor, add comments, add type hints, or improve code quality
4. Make the MINIMUM change necessary to close this vulnerability
5. ALL file reads and edits must use `docker exec` — never direct file access
6. Do NOT search for or read flag values

## Your task
1. Read the relevant source files inside the container
2. Identify the exact lines that cause the vulnerability
3. Edit ONLY those lines inside the container
4. Report what you changed

## Response format (JSON only, no markdown fencing)
{{
  "patch_type": "code_fix",
  "description": "one sentence describing the fix",
  "vulnerability": "what was wrong",
  "container": "which container was patched",
  "files_modified": ["paths inside the container"],
  "changes_summary": "what specifically was changed",
  "rollback": "docker restart <container_name>"
}}
"""

CODE_FIX_COST_ESTIMATE = 0.15


class Fixer:
    """Patches vulnerabilities inside running containers via docker exec."""

    def __init__(self, cost_governor: CostGovernor):
        self.cost_governor = cost_governor

    async def generate_patch(self, triage: TriageResult) -> PatchProposal | None:
        """Generate and apply a patch inside running containers."""
        if not self.cost_governor.can_spend(triage.event_id, CODE_FIX_COST_ESTIMATE):
            logger.warning("Budget exceeded, cannot patch for %s", triage.event_id)
            return None

        triage_json = json.dumps(asdict(triage), indent=2, default=str)
        prompt = FIX_PROMPT.format(triage_json=triage_json)

        options = ClaudeAgentOptions(
            system_prompt=(
                "You are a security engineer. Fix ONLY the specific vulnerability "
                "described in the triage report. All file access must be through "
                "docker exec commands — never read or write files directly. "
                "Respond with JSON only after applying the fix."
            ),
            max_turns=15,
            allowed_tools=["Bash"],
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

        container = data.get("container", "unknown")
        files_modified = data.get("files_modified", [])

        logger.info(
            "Patch applied in container %s: %s (%s)",
            container, data.get("description", ""), files_modified,
        )

        return PatchProposal(
            event_id=triage.event_id,
            patch_type=data.get("patch_type", "code_fix"),
            description=data.get("description", ""),
            diff=data.get("changes_summary", ""),
            files_modified=files_modified,
            rollback_steps=data.get("rollback", f"docker restart {container}"),
        )
