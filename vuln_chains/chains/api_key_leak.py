"""Chain 1: API Key Exfiltration via Debug Endpoint

Attack chain (5 steps):
  1. Discover /chains/apikeys/docs returns a Swagger page (recon)
  2. Find /chains/apikeys/debug/config leaks partial config with a hint
  3. Brute-force the /chains/apikeys/debug/dump?token= with partial key
  4. Obtain a leaked internal API key from the dump
  5. Use the API key to access /chains/apikeys/admin/secrets

Detection windows:
  - Step 1: access to /debug path (honeypot signal)
  - Step 2: repeated requests to /debug/dump with different tokens (brute-force)
  - Step 3: use of leaked API key on /admin/ endpoint
"""

from __future__ import annotations

import hashlib
import hmac

from fastapi import APIRouter, Header, HTTPException, Query

router = APIRouter(prefix="/chains/apikeys", tags=["api-key-leak"])

CHAIN_META = {
    "name": "API Key Exfiltration",
    "steps": 5,
    "difficulty": "medium",
    "attack_types": ["recon", "brute_force", "credential_leak"],
    "detection_signals": ["debug_endpoint_access", "brute_force_pattern", "leaked_key_usage"],
}

# The "secret" API key — attacker needs to discover this
INTERNAL_API_KEY = "xveh-sk-83d2e6f1a47b09c5"
# Partial hint leaked in config
PARTIAL_KEY = "xveh-sk-83d2****"
# Debug dump requires a 4-char token suffix brute-force
DUMP_TOKEN_SUFFIX = "e6f1"


@router.get("/status")
async def status():
    """Public health check — nothing interesting."""
    return {"service": "api-keys", "status": "ok"}


@router.get("/debug/config")
async def debug_config():
    """Step 2: Leaks partial config. A real app would never expose this."""
    return {
        "debug": True,
        "version": "2.4.1-staging",
        "api_key_prefix": PARTIAL_KEY,
        "note": "dump endpoint requires key suffix verification",
        "dump_endpoint": "/chains/apikeys/debug/dump?token=<last4>",
    }


@router.get("/debug/dump")
async def debug_dump(token: str = Query(default="")):
    """Step 3: Brute-forceable — attacker tries all 4-hex-char combos.
    That's 65536 possibilities, creating a clear brute-force signal."""
    if len(token) != 4:
        raise HTTPException(status_code=400, detail="token must be 4 characters")
    if token.lower() != DUMP_TOKEN_SUFFIX:
        raise HTTPException(status_code=403, detail="invalid token")

    # Success — leak the full key
    return {
        "dump": {
            "internal_api_key": INTERNAL_API_KEY,
            "db_host": "postgres:5432",
            "note": "use api key in X-Internal-Key header on /admin endpoints",
        }
    }


@router.get("/admin/secrets")
async def admin_secrets(x_internal_key: str = Header(default="")):
    """Step 5: Requires the leaked API key."""
    if not hmac.compare_digest(x_internal_key, INTERNAL_API_KEY):
        raise HTTPException(status_code=401, detail="invalid api key")
    return {
        "secrets": [
            {"name": "FLAG", "value": "XVEH{staging_key_dump_4f9a}"},
            {"name": "service_account_pw", "value": "Tr0ub4dor&3"},
        ]
    }
