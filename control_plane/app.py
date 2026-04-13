"""Control Plane — real-time defense API for the Reactive Defender.

Capabilities:
- Session scoring (JA3 fingerprint + auth token tracking)
- Shadow environment redirect (transparent attacker redirection)
- Token revocation
- System status

Backed by Redis for sub-millisecond lookups that nginx checks on every request.
"""

from __future__ import annotations

import os
import time

import jwt
import redis.asyncio as redis
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

app = FastAPI(title="Reactive Defender Control Plane", version="0.2.0")

JWT_SECRET = os.environ.get("JWT_SECRET", "crapi")
REDIS_HOST = os.environ.get("REDIS_HOST", "redis")

# Score thresholds for shadow redirect (tiered model)
REDIRECT_THRESHOLD = 30  # score needed to redirect to shadow

pool: redis.Redis | None = None


@app.on_event("startup")
async def startup():
    global pool
    pool = redis.Redis(host=REDIS_HOST, port=6379, decode_responses=True)


@app.on_event("shutdown")
async def shutdown():
    if pool:
        await pool.aclose()


# ══════════════════════════════════════════════════════════════════
# SESSION SCORING — JA3 fingerprint + auth token tracking
# ══════════════════════════════════════════════════════════════════

class ScoreEvent(BaseModel):
    """Watcher sends these when it detects suspicious activity."""
    token: str = ""          # auth token from the request (if present)
    ja3: str = ""            # IP:UserAgent composite fingerprint
    event_type: str          # detection type (e.g. "honeypot_v3_admin")
    severity: str            # "critical", "high", "medium", "low"
    points: int = 0          # explicit points (0 = auto from severity)


# Auto-scoring by severity
SEVERITY_POINTS = {
    "critical": 40,
    "high": 15,
    "medium": 5,
    "low": 2,
}

# Score TTL by severity — how long before a score decays
SEVERITY_TTL = {
    "critical": 300,   # 5 minutes
    "high": 300,       # 5 minutes
    "medium": 300,     # 5 minutes
    "low": 120,        # 2 minutes
}

SHADOW_REDIRECT_TTL = 300  # 5 minutes — how long a redirect persists


@app.post("/control/session/score")
async def add_score(event: ScoreEvent):
    """Add threat score to a session. Identified by token and/or JA3.
    When score exceeds threshold, the session is marked for shadow redirect."""
    points = event.points or SEVERITY_POINTS.get(event.severity, 5)
    ttl = SEVERITY_TTL.get(event.severity, 60)
    identifiers = []
    now = time.time()

    # Score by token
    if event.token:
        key = f"score:token:{event.token}"
        new_score = await pool.incrbyfloat(key, points)
        await pool.expire(key, ttl)
        identifiers.append(("token", event.token[:30], new_score))

        # Log the detection event
        await pool.rpush(f"events:token:{event.token}",
                         f"{now}|{event.event_type}|{event.severity}|{points}")
        await pool.expire(f"events:token:{event.token}", ttl)

    # Score by JA3 (persists across token changes)
    if event.ja3:
        key = f"score:ja3:{event.ja3}"
        new_score = await pool.incrbyfloat(key, points)
        await pool.expire(key, ttl)
        identifiers.append(("ja3", event.ja3, new_score))

        # Link JA3 to token for cross-reference
        if event.token:
            await pool.setex(f"ja3_token:{event.ja3}", ttl, event.token)
            await pool.setex(f"token_ja3:{event.token}", ttl, event.ja3)

    # Check if any identifier crossed the redirect threshold
    redirected = False
    for id_type, id_value, score in identifiers:
        if score >= REDIRECT_THRESHOLD:
            await _redirect_session(id_type, id_value, event.token, event.ja3, score)
            redirected = True

    # If already in shadow, refresh TTL so they stay until 5 min of inactivity
    if not redirected:
        already_shadow = False
        if event.token and await pool.exists(f"shadow:token:{event.token}"):
            await pool.expire(f"shadow:token:{event.token}", SHADOW_REDIRECT_TTL)
            already_shadow = True
        if event.ja3 and await pool.exists(f"shadow:ja3:{event.ja3}"):
            await pool.expire(f"shadow:ja3:{event.ja3}", SHADOW_REDIRECT_TTL)
            already_shadow = True
        if already_shadow:
            redirected = True  # still in shadow

    return {
        "points_added": points,
        "identifiers": [
            {"type": t, "id": v[:30], "total_score": s}
            for t, v, s in identifiers
        ],
        "redirected": redirected,
        "threshold": REDIRECT_THRESHOLD,
    }


async def _redirect_session(trigger_type: str, trigger_value: str,
                             token: str, ja3: str, score: float):
    """Mark a session for redirect to shadow environment."""
    now = str(time.time())

    # Mark the token for shadow redirect
    if token:
        await pool.setex(f"shadow:token:{token}", SHADOW_REDIRECT_TTL, now)

    # Mark the JA3 so new tokens from same tool also get redirected
    if ja3:
        await pool.setex(f"shadow:ja3:{ja3}", SHADOW_REDIRECT_TTL, now)

    # Log the redirect event
    await pool.rpush("shadow:redirect_log",
                     f"{now}|{trigger_type}={trigger_value}|score={score}|token={token[:30] if token else ''}|ja3={ja3}")


@app.get("/control/session/check")
async def check_session(request: Request):
    """Called by nginx on EVERY request (via auth_request).
    Returns 200 for prod, 302-equivalent header for shadow.
    nginx reads the X-Target-Env header to decide routing."""
    token = request.headers.get("X-Auth-Token", "")
    ja3 = request.headers.get("X-JA3-Hash", "")  # IP:UserAgent composite

    # Check token-level redirect
    if token and await pool.exists(f"shadow:token:{token}"):
        return {"target": "shadow", "reason": "token_flagged"}

    # Check IP:JA3 composite redirect (catches token rotation)
    if ja3 and await pool.exists(f"shadow:ja3:{ja3}"):
        # Also flag the current token so future checks are faster
        if token:
            await pool.setex(f"shadow:token:{token}", SHADOW_REDIRECT_TTL, str(time.time()))
        return {"target": "shadow", "reason": "ja3_flagged"}

    return {"target": "prod"}


@app.get("/control/session/score/{token}")
async def get_session_score(token: str):
    """Get the current threat score for a session."""
    token_score = await pool.get(f"score:token:{token}") or "0"
    ja3 = await pool.get(f"token_ja3:{token}") or ""
    ja3_score = await pool.get(f"score:ja3:{ja3}") or "0" if ja3 else "0"
    is_shadow = await pool.exists(f"shadow:token:{token}")

    # Get recent events
    events = await pool.lrange(f"events:token:{token}", 0, -1) or []

    return {
        "token_score": float(token_score),
        "ja3": ja3,
        "ja3_score": float(ja3_score),
        "is_redirected_to_shadow": bool(is_shadow),
        "redirect_threshold": REDIRECT_THRESHOLD,
        "recent_events": events[-10:],  # last 10
    }


@app.post("/control/session/reset/{token}")
async def reset_session_score(token: str):
    """Reset a session's score (e.g., after false positive investigation)."""
    await pool.delete(f"score:token:{token}")
    await pool.delete(f"shadow:token:{token}")
    await pool.delete(f"events:token:{token}")
    ja3 = await pool.get(f"token_ja3:{token}")
    if ja3:
        await pool.delete(f"score:ja3:{ja3}")
        await pool.delete(f"shadow:ja3:{ja3}")
    return {"status": "reset", "token": token[:30]}


# ══════════════════════════════════════════════════════════════════
# SHADOW ENVIRONMENT MANAGEMENT
# ══════════════════════════════════════════════════════════════════

@app.get("/control/shadow/status")
async def shadow_status():
    """List all sessions currently redirected to shadow."""
    redirected_tokens = []
    async for key in pool.scan_iter("shadow:token:*"):
        token = key.replace("shadow:token:", "")
        since = await pool.get(key)
        redirected_tokens.append({"token": token[:30] + "...", "since": since})

    redirected_ja3s = []
    async for key in pool.scan_iter("shadow:ja3:*"):
        ja3 = key.replace("shadow:ja3:", "")
        since = await pool.get(key)
        redirected_ja3s.append({"ja3": ja3, "since": since})

    # Get redirect log
    log_entries = await pool.lrange("shadow:redirect_log", -20, -1) or []

    return {
        "redirected_tokens": len(redirected_tokens),
        "redirected_ja3s": len(redirected_ja3s),
        "tokens": redirected_tokens[:20],
        "ja3s": redirected_ja3s[:20],
        "recent_redirects": log_entries,
    }


@app.post("/control/sessions/reset")
async def reset_all_sessions():
    """Flush all session scores, shadow redirects, and redirect logs."""
    cleared = 0
    for pattern in ("score:token:*", "score:ja3:*", "shadow:token:*",
                    "shadow:ja3:*", "events:token:*", "events:ja3:*"):
        async for key in pool.scan_iter(pattern):
            await pool.delete(key)
            cleared += 1
    await pool.delete("shadow:redirect_log")
    return {"status": "ok", "keys_cleared": cleared}


# ══════════════════════════════════════════════════════════════════
# TOKEN MANAGEMENT (kept from v0.1)
# ══════════════════════════════════════════════════════════════════

class TokenRevokeRequest(BaseModel):
    token: str
    reason: str = ""


class TokenRevokeByUserRequest(BaseModel):
    email: str
    reason: str = ""


@app.post("/control/tokens/revoke")
async def revoke_token(req: TokenRevokeRequest):
    try:
        payload = jwt.decode(req.token, JWT_SECRET, algorithms=["HS256", "RS256"],
                             options={"verify_signature": False})
        exp = payload.get("exp", 0)
        ttl = max(int(exp - time.time()), 60)
    except jwt.InvalidTokenError:
        ttl = 3600

    await pool.setex(f"token:blacklist:{req.token}", ttl, req.reason or "revoked")
    return {"status": "revoked", "ttl_seconds": ttl}


@app.post("/control/tokens/revoke-user")
async def revoke_user_tokens(req: TokenRevokeByUserRequest):
    await pool.set(f"user:revoked:{req.email}", str(time.time()))
    return {"status": "all_tokens_revoked", "email": req.email}


# ══════════════════════════════════════════════════════════════════
# SYSTEM STATUS
# ══════════════════════════════════════════════════════════════════

@app.get("/control/status")
async def system_status():
    blocked_count = 0
    async for _ in pool.scan_iter("ip:blocked:*"):
        blocked_count += 1

    revoked_count = 0
    async for _ in pool.scan_iter("token:blacklist:*"):
        revoked_count += 1

    shadow_count = 0
    async for _ in pool.scan_iter("shadow:token:*"):
        shadow_count += 1

    return {
        "status": "operational",
        "blocked_ips": blocked_count,
        "revoked_tokens": revoked_count,
        "shadow_redirected_sessions": shadow_count,
        "redirect_threshold": REDIRECT_THRESHOLD,
        "redis_connected": await pool.ping(),
    }


