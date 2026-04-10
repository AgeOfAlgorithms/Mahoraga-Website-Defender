"""Chain 3: JWT Algorithm Confusion → Token Forgery → Data Theft

Attack chain (5 steps):
  1. Login normally and receive a JWT token
  2. Discover /chains/jwt/.well-known/jwks.json exposes the public key
  3. Notice the server accepts "alg": "HS256" signed with the RSA public key
     (algorithm confusion vulnerability)
  4. Forge a JWT with admin role using HS256 + the public key as secret
  5. Use forged token to access /chains/jwt/admin/export (data exfiltration)

Detection windows:
  - Step 2: accessing .well-known/jwks.json (recon)
  - Step 4: JWT with "alg":"HS256" but user claims admin role
  - Step 5: admin endpoint access with suspicious token
"""

from __future__ import annotations

import os
import time

import jwt as pyjwt
from fastapi import APIRouter, HTTPException, Header

router = APIRouter(prefix="/chains/jwt", tags=["jwt-forgery"])

CHAIN_META = {
    "name": "JWT Algorithm Confusion",
    "steps": 5,
    "difficulty": "hard",
    "attack_types": ["jwt_manipulation", "algorithm_confusion", "privilege_escalation"],
    "detection_signals": ["jwks_access", "algorithm_mismatch", "forged_admin_token"],
}

# In a real app these would be proper RSA keys. We use a simple secret
# but simulate the confusion by accepting both RS256 and HS256.
JWT_SECRET = os.environ.get("JWT_SECRET", "crapi")

# The "public key" that gets exposed — in this simplified version,
# it's the same secret (simulating the algorithm confusion where
# HS256(public_key) == RS256(private_key) verification)
EXPOSED_PUBLIC_KEY = JWT_SECRET

_users = {
    "fleet.viewer@vehitrack.io": {"password": "Dusk!maze22", "role": "user", "name": "Casey Moreno"},
    "ops.lead@vehitrack.io": {"password": "Birch#lamp91", "role": "staff", "name": "Jordan Pratt"},
}


class LoginBody(dict):
    pass


@router.post("/login")
async def login(body: dict):
    """Step 1: Normal login. Returns a JWT with role claim."""
    email = body.get("email", "")
    password = body.get("password", "")
    user = _users.get(email)
    if not user or user["password"] != password:
        raise HTTPException(status_code=401, detail="invalid credentials")

    token = pyjwt.encode(
        {
            "sub": email,
            "role": user["role"],
            "name": user["name"],
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        },
        JWT_SECRET,
        algorithm="HS256",
    )
    return {"token": token, "role": user["role"]}


@router.get("/.well-known/jwks.json")
async def jwks():
    """Step 2: Exposes the 'public key'. In a real RS256 setup this
    would be the RSA public key; attacker uses it as HS256 secret."""
    return {
        "keys": [
            {
                "kty": "oct",
                "kid": "crapi-key-1",
                "k": EXPOSED_PUBLIC_KEY,
                "alg": "RS256",
                "use": "sig",
                "note": "Internal key — rotate before production",
            }
        ]
    }


@router.get("/profile")
async def profile(authorization: str = Header(default="")):
    """Normal profile endpoint — requires valid JWT."""
    payload = _verify_token(authorization)
    return {"email": payload["sub"], "role": payload["role"], "name": payload["name"]}


@router.get("/admin/export")
async def admin_export(authorization: str = Header(default="")):
    """Step 5: Admin-only data export. Requires role=admin in JWT."""
    payload = _verify_token(authorization)
    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="admin role required")
    return {
        "flag": "XVEH{jwt_alg_swap_priv_esc_c81d}",
        "exported_users": list(_users.keys()),
        "internal_config": {"db_connection": "postgres://fleet_svc:N0rth$tar55@postgresdb/vehitrack"},
    }


def _verify_token(auth_header: str) -> dict:
    """Vulnerable verification — accepts both HS256 and RS256."""
    token = auth_header.replace("Bearer ", "").strip()
    if not token:
        raise HTTPException(status_code=401, detail="missing token")
    try:
        # Vulnerability: accepts HS256 tokens signed with the "public key"
        return pyjwt.decode(token, JWT_SECRET, algorithms=["HS256", "RS256"])
    except pyjwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"invalid token: {e}")
