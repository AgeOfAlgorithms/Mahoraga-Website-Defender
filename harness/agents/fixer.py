"""Fixer agent — patches vulnerabilities by editing source in crapi-fork/.

Uses LLM with a sandboxed bash tool. The sandbox enforces:
- File access ONLY within crapi-fork/ (path validation, not just prompting)
- docker exec only into whitelisted containers (for reloads)
- docker compose rebuild for compiled services (Java/Go)
- Blocked paths: harness/, vuln_chains/, flags, .env, etc.

All services are patchable:
- crapi-workshop (Python): edit source → gunicorn reload (instant)
- crapi-identity (Java): edit source → docker compose rebuild
- crapi-community (Go): edit source → docker compose rebuild
- nginx-proxy: edit config → nginx reload
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import asdict

from harness.agents.llm_runner import run_agent
from harness.cost_governor import CostGovernor
from harness.types import PatchProposal, TriageResult

logger = logging.getLogger(__name__)

FIX_PROMPT = """\
You are a security engineer patching ONE specific vulnerability in a web
application. You edit source files directly in the crapi-fork/ directory,
then reload or rebuild the affected service.

## Exploit Report (from shadow environment)
{triage_json}

## Source code layout (all paths relative to crapi-fork/)
### Python — crapi-workshop (hot-reloadable)
- services/workshop/crapi/shop/views.py — shop, orders, coupons
- services/workshop/crapi/mechanic/views.py — mechanic reports, contact_mechanic (SSRF)
- services/workshop/crapi/merchant/views.py — merchant/vehicle endpoints
- services/workshop/crapi/user/views.py — admin, management, API keys, fleet status
- services/workshop/utils/jwt.py — JWT authentication decorator
- services/workshop/crapi_site/urls.py — URL routing

### Java — crapi-identity (needs rebuild after edit)
- services/identity/src/main/java/com/crapi/controller/ — REST controllers
- services/identity/src/main/java/com/crapi/service/Impl/ — service implementations
- services/identity/src/main/java/com/crapi/config/ — security config

### Go — crapi-community (needs rebuild after edit)
- services/community/api/ — API handlers

## How to read/edit files
Read files directly from crapi-fork/:
```
cat crapi-fork/services/workshop/crapi/shop/views.py
grep -n "pattern" crapi-fork/services/workshop/crapi/mechanic/views.py
```

Edit with sed or python3:
```
sed -i 's/old_code/new_code/' crapi-fork/services/workshop/crapi/shop/views.py
python3 -c "
from pathlib import Path
p = Path('crapi-fork/services/workshop/crapi/shop/views.py')
code = p.read_text()
code = code.replace('vulnerable_line', 'fixed_line')
p.write_text(code)
"
```

## After patching — reload the service
**Python (workshop):** hot-reload, no rebuild needed:
  `docker exec crapi-workshop pkill -HUP -f gunicorn`
  `docker exec shadow-workshop pkill -HUP -f gunicorn`

**Java (identity):** must rebuild:
  `docker compose up -d --build crapi-identity shadow-identity`

**Go (community):** must rebuild:
  `docker compose up -d --build crapi-community shadow-community`

**Nginx:** reload config:
  `docker exec nginx-proxy nginx -s reload`

## STRICT RULES
1. Fix ONLY the vulnerability described above — NOTHING else
2. Do NOT fix other bugs or vulnerabilities you notice
3. Do NOT refactor, add comments, add type hints, or improve code quality
4. Make the MINIMUM change necessary to close this vulnerability
5. Be EFFICIENT — read only the file you need, make the fix, respond
6. Always apply the fix to BOTH prod and shadow services

## Your task
1. Read the relevant source file in crapi-fork/
2. Identify the exact lines that cause the vulnerability
3. Edit ONLY those lines
4. Reload/rebuild the affected service
5. Respond with the JSON below

## Response format (JSON only, no markdown fencing)
{{
  "patch_type": "code_fix",
  "description": "one sentence describing the fix",
  "vulnerability": "what was wrong",
  "service": "which service was patched (workshop/identity/community/nginx)",
  "files_modified": ["paths relative to crapi-fork/"],
  "changes_summary": "what specifically was changed",
  "rollback": "git checkout crapi-fork/<file> && docker compose up -d --build <service>"
}}
"""

SYSTEM_PROMPT = (
    "You are a security engineer. Fix ONLY the specific vulnerability "
    "described in the triage report. Edit source files directly in the "
    "crapi-fork/ directory, then reload or rebuild the service. "
    "Be EFFICIENT — read only the file you need, make the minimal fix, "
    "and respond. Do not explore the codebase broadly. "
    "After applying the fix, your FINAL message must be ONLY a JSON "
    "object with the response format specified. No explanation, no "
    "markdown, no code fences — just the raw JSON object."
)

CODE_FIX_COST_ESTIMATE = 0.05


class Fixer:
    """Patches vulnerabilities inside running containers via docker exec."""

    # Map request paths / vuln keywords to source files
    PATH_TO_SOURCE = {
        "/shop/": "services/workshop/crapi/shop/views.py",
        "/mechanic/": "services/workshop/crapi/mechanic/views.py",
        "/merchant/": "services/workshop/crapi/merchant/views.py",
        "/management/": "services/workshop/crapi/user/views.py",
        "api_key": "services/workshop/crapi/user/views.py",
        "fleet": "services/workshop/crapi/user/views.py",
        "jwt": "services/workshop/utils/jwt.py",
        "alg:none": "services/workshop/utils/jwt.py",
        "ssrf": "services/workshop/crapi/mechanic/views.py",
        "contact_mechanic": "services/workshop/crapi/mechanic/views.py",
        "coupon": "services/workshop/crapi/shop/views.py",
        "order": "services/workshop/crapi/shop/views.py",
        "quantity": "services/workshop/crapi/shop/views.py",
    }

    def __init__(self, cost_governor: CostGovernor):
        self.cost_governor = cost_governor

    def _pre_read_source(self, triage) -> str:
        """Try to pre-read the relevant source file based on the exploit details."""
        from pathlib import Path
        analysis = (triage.analysis + " " + triage.recommended_action).lower()

        for keyword, rel_path in self.PATH_TO_SOURCE.items():
            if keyword.lower() in analysis:
                full_path = Path("crapi-fork") / rel_path
                if full_path.exists():
                    content = full_path.read_text()
                    # Add line numbers
                    lines = content.split("\n")
                    numbered = "\n".join(f"{i+1:4d} | {line}" for i, line in enumerate(lines))
                    # Truncate if too long
                    if len(numbered) > 6000:
                        numbered = numbered[:6000] + "\n... (truncated)"
                    return f"# File: crapi-fork/{rel_path}\n{numbered}"
        return ""

    async def generate_patch(self, triage: TriageResult, rejections: list = None) -> PatchProposal | None:
        """Generate and apply a patch inside running containers."""
        if not self.cost_governor.can_spend(triage.event_id, CODE_FIX_COST_ESTIMATE):
            logger.warning("Budget exceeded, cannot patch for %s", triage.event_id)
            return None

        triage_json = json.dumps(asdict(triage), indent=2, default=str)

        # Pre-read the likely source file so the LLM doesn't waste turns exploring
        source_context = self._pre_read_source(triage)
        prompt = FIX_PROMPT.format(triage_json=triage_json)
        if source_context:
            prompt += f"\n\n## Source code (pre-loaded for efficiency — edit this file)\n```\n{source_context}\n```"

        # Include rejection history so the LLM tries a different approach
        if rejections:
            prompt += "\n\n## PREVIOUS ATTEMPTS REJECTED — do NOT repeat these\n"
            for i, rej in enumerate(rejections, 1):
                prompt += f"### Attempt {i}: {rej.get('patch_description', '')}\n"
                prompt += f"Rejected because: {rej.get('issues', [])}\n"
                if rej.get('suggestion'):
                    prompt += f"Reviewer suggestion: {rej['suggestion']}\n"
            prompt += "\nYou MUST try a DIFFERENT approach this time.\n"

        max_retries = 3
        response_text = ""
        for attempt in range(max_retries):
            try:
                response_text = await run_agent(
                    prompt=prompt,
                    system_prompt=SYSTEM_PROMPT,
                    max_turns=100,
                )
                break  # success
            except Exception as e:
                logger.error(
                    "Fixer LLM call failed for %s (attempt %d/%d): %s",
                    triage.event_id, attempt + 1, max_retries, e,
                )
                if attempt < max_retries - 1:
                    wait = 5 * (attempt + 1)
                    logger.info("Retrying in %ds...", wait)
                    await asyncio.sleep(wait)
                else:
                    return None

        self.cost_governor.record_spend(triage.event_id, CODE_FIX_COST_ESTIMATE)

        if not response_text.strip():
            logger.error("Fixer returned empty response for %s", triage.event_id)
            return None

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
            logger.error("Failed to parse fixer response: %s", response_text[:300])
            return None

        service = data.get("service", data.get("container", "unknown"))
        files_modified = data.get("files_modified", [])

        logger.info(
            "Patch applied to %s: %s (%s)",
            service, data.get("description", ""), files_modified,
        )

        return PatchProposal(
            event_id=triage.event_id,
            patch_type=data.get("patch_type", "code_fix"),
            description=data.get("description", ""),
            diff=data.get("changes_summary", ""),
            files_modified=files_modified,
            rollback_steps=data.get("rollback", f"docker compose up -d --build {service}"),
        )
