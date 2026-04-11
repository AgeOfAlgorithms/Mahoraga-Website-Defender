"""Fixer agent — patches vulnerabilities inside RUNNING containers only.

CRITICAL: The fixer NEVER modifies source code on the host. All edits
happen inside Docker containers via `docker exec`. Changes are ephemeral
and lost when containers restart — source code stays clean.

Uses GLM (Zhipu AI) with a sandboxed bash tool that only allows
docker exec commands into whitelisted containers.

Patchable containers:
- crapi-workshop (Python/Django): edits /app/crapi/ → auto-reloads
- nginx-proxy (OpenResty): edits /usr/local/openresty/nginx/conf/ → needs reload

Non-patchable (would need rebuild):
- crapi-identity (Java): compiled JAR, can't hot-patch
- crapi-community (Go): compiled binary, can't hot-patch
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import asdict

from harness.agents.glm_runner import run_glm_agent
from harness.cost_governor import CostGovernor
from harness.types import PatchProposal, TriageResult

logger = logging.getLogger(__name__)

FIX_PROMPT = """\
You are a security engineer patching ONE specific vulnerability in a RUNNING
web application. You will read and edit files INSIDE Docker containers — never
on the host filesystem.

## Exploit Report (from shadow environment)
{triage_json}

## Source code layout (crapi-workshop at /app/)
- /app/crapi/shop/views.py — shop, orders, coupons
- /app/crapi/mechanic/views.py — mechanic reports, contact_mechanic (SSRF)
- /app/crapi/merchant/views.py — merchant/vehicle endpoints
- /app/crapi/user/views.py — admin, management dashboard, API keys, fleet status
- /app/utils/jwt.py — JWT authentication decorator
- /app/crapi_site/urls.py — URL routing
- /app/crapi_site/settings.py — Django settings

## How to read files
```
docker exec crapi-workshop cat /app/crapi/shop/views.py
docker exec crapi-workshop bash -c 'grep -n "pattern" /app/crapi/mechanic/views.py'
```
IMPORTANT: For pipes, use bash -c: `docker exec crapi-workshop bash -c 'cat file | grep pattern'`
Do NOT use pipes outside docker exec (e.g. `docker exec ... | grep ...` is WRONG).

## How to apply patches
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

For nginx:
```
docker exec nginx-proxy sed -i 's/old/new/' /usr/local/openresty/nginx/conf/nginx.conf
docker exec nginx-proxy nginx -s reload
```

## Patchable containers
- **crapi-workshop** (Python/Django at /app/crapi/): after editing, reload with:
  `docker exec crapi-workshop pkill -HUP -f gunicorn`
- **nginx-proxy** (OpenResty at /usr/local/openresty/nginx/conf/): after editing, reload with:
  `docker exec nginx-proxy nginx -s reload`

## NOT patchable (skip these)
- crapi-identity (Java JAR — can't hot-patch)
- crapi-community (Go binary — can't hot-patch)

## STRICT RULES
1. Fix ONLY the vulnerability described above — NOTHING else
2. Do NOT fix other bugs or vulnerabilities you notice
3. Do NOT refactor, add comments, add type hints, or improve code quality
4. Make the MINIMUM change necessary to close this vulnerability
5. ALL file reads and edits must use `docker exec` — never direct file access
6. Be EFFICIENT — read only the file you need, make the fix, respond

## Your task
1. Read the relevant source files inside the container
2. Identify the exact lines that cause the vulnerability
3. Edit ONLY those lines inside the container
4. Respond with the JSON below

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

SYSTEM_PROMPT = (
    "You are a security engineer. Fix ONLY the specific vulnerability "
    "described in the triage report. All file access must be through "
    "docker exec commands — never read or write files directly. "
    "Be EFFICIENT — read only the file you need, make the minimal fix, "
    "and respond. Do not explore the codebase broadly. "
    "After applying the fix, your FINAL message must be ONLY a JSON "
    "object with the response format specified. No explanation, no "
    "markdown, no code fences — just the raw JSON object."
)

CODE_FIX_COST_ESTIMATE = 0.05  # GLM is much cheaper than Claude


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

        max_retries = 3
        response_text = ""
        for attempt in range(max_retries):
            try:
                response_text = await run_glm_agent(
                    prompt=prompt,
                    system_prompt=SYSTEM_PROMPT,
                    max_turns=20,
                )
                break  # success
            except Exception as e:
                logger.error(
                    "Fixer GLM call failed for %s (attempt %d/%d): %s",
                    triage.event_id, attempt + 1, max_retries, e,
                )
                if attempt < max_retries - 1:
                    wait = 5 * (attempt + 1)
                    logger.info("Retrying in %ds...", wait)
                    await asyncio.sleep(wait)
                else:
                    return None

        self.cost_governor.record_spend(triage.event_id, CODE_FIX_COST_ESTIMATE)

        try:
            text = response_text.strip()
            # Try to extract JSON from the response (may be mixed with text)
            if text.startswith("```"):
                text = text.split("\n", 1)[1].rsplit("```", 1)[0].strip()
            # Find the JSON object in the text
            start = text.find("{")
            end = text.rfind("}") + 1
            if start >= 0 and end > start:
                text = text[start:end]
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
