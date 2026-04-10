"""Chain 2: IDOR → Privilege Escalation → Account Takeover

Attack chain (6 steps):
  1. Register a normal user account via /chains/idor/register
  2. Discover that /chains/idor/users/:id leaks user data (IDOR)
  3. Enumerate user IDs to find an admin account (sequential ID scan)
  4. Find that admin's profile leaks a password_reset_token
  5. Use the reset token to change admin's password
  6. Login as admin with the new password

Detection windows:
  - Step 3: sequential ID enumeration (1, 2, 3, 4...) is a clear signal
  - Step 4: accessing another user's profile data
  - Step 5: password reset for a different user
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/chains/idor", tags=["idor-escalation"])

CHAIN_META = {
    "name": "IDOR to Account Takeover",
    "steps": 6,
    "difficulty": "medium",
    "attack_types": ["idor", "enumeration", "privilege_escalation", "account_takeover"],
    "detection_signals": ["sequential_id_scan", "cross_user_access", "password_reset_abuse"],
}


@dataclass
class User:
    id: int
    email: str
    password_hash: str
    role: str = "user"
    reset_token: str = field(default_factory=lambda: secrets.token_hex(16))
    auth_token: str = field(default_factory=lambda: secrets.token_hex(32))


def _hash(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


# Pre-seeded users — admin is buried at ID 23, surrounded by 30+ normal users.
# Attacker must enumerate through them to find the admin account.
_NORMAL_USERS = [
    ("mkarla@vehitrack.io", "sunfl0wer88"),
    ("t.nguyen@vehitrack.io", "RedPanda42!"),
    ("j.santos@vehitrack.io", "Cobalt!77"),
    ("r.okafor@vehitrack.io", "Mango_tree9"),
    ("a.petrov@vehitrack.io", "Blizzard22!"),
    ("l.chen@vehitrack.io", "Kite$tring5"),
    ("k.williams@vehitrack.io", "Marble88!"),
    ("d.muller@vehitrack.io", "Sp1der#web"),
    ("s.kim@vehitrack.io", "Lantern09!"),
    ("p.garcia@vehitrack.io", "Cr0ssbow44"),
    ("n.jackson@vehitrack.io", "Velvet!12"),
    ("f.ahmed@vehitrack.io", "Cactus77!"),
    ("m.kovacs@vehitrack.io", "Ridg3line!"),
    ("b.wright@vehitrack.io", "Compass#41"),
    ("c.rossi@vehitrack.io", "Hbr!dge09"),
    ("e.tanaka@vehitrack.io", "Drift3r!55"),
    ("h.schmidt@vehitrack.io", "Pebble!28"),
    ("i.park@vehitrack.io", "Flicker#93"),
    ("w.jones@vehitrack.io", "Mist!val07"),
    ("v.silva@vehitrack.io", "Quarry!66"),
    ("g.eriksson@vehitrack.io", "Beacon33!"),
    ("o.meyer@vehitrack.io", "Tr3ll1s!40"),
    ("u.begum@vehitrack.io", "Fern$hd82"),
    ("z.li@vehitrack.io", "Anchor!15"),
    ("q.morales@vehitrack.io", "Spire#27"),
    ("x.popov@vehitrack.io", "Riv3rbed!8"),
    ("y.hassan@vehitrack.io", "Glint!049"),
    ("aa.kowalski@vehitrack.io", "Pedal$72"),
    ("ab.flores@vehitrack.io", "Summit#19"),
]

_users: dict[int, User] = {}
# IDs 1-22: normal users
for i, (email, pw) in enumerate(_NORMAL_USERS[:22], start=1):
    _users[i] = User(id=i, email=email, password_hash=_hash(pw), role="user")
# ID 23: the admin (buried deep)
_users[23] = User(id=23, email="sysop@vehitrack.internal", password_hash=_hash("Gr4nit3#Peak!"),
                  role="admin", reset_token="d8e3f7a19c2b05641ea7d3f80b9c26a5")
# IDs 24-30: more normal users after admin
for i, (email, pw) in enumerate(_NORMAL_USERS[22:], start=24):
    _users[i] = User(id=i, email=email, password_hash=_hash(pw), role="user")

_next_id = 200  # new registrations start here


class RegisterRequest(BaseModel):
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


class ResetPasswordRequest(BaseModel):
    reset_token: str
    new_password: str


@router.post("/register")
async def register(req: RegisterRequest):
    """Step 1: Normal user registration."""
    global _next_id
    for u in _users.values():
        if u.email == req.email:
            raise HTTPException(status_code=409, detail="email already registered")
    user = User(id=_next_id, email=req.email, password_hash=_hash(req.password))
    _users[_next_id] = user
    _next_id += 1
    return {"id": user.id, "email": user.email, "token": user.auth_token}


@router.post("/login")
async def login(req: LoginRequest):
    for u in _users.values():
        if u.email == req.email and u.password_hash == _hash(req.password):
            return {"id": u.id, "email": u.email, "role": u.role, "token": u.auth_token}
    raise HTTPException(status_code=401, detail="invalid credentials")


@router.get("/users/{user_id}")
async def get_user(user_id: int):
    """Step 2-3: IDOR — no auth check. Leaks reset_token for admins.
    Attacker enumerates IDs: /users/1, /users/2, etc."""
    user = _users.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="user not found")
    # Vulnerability: leaks everything including reset_token
    return {
        "id": user.id,
        "email": user.email,
        "role": user.role,
        "password_reset_token": user.reset_token,
    }


@router.post("/reset-password")
async def reset_password(req: ResetPasswordRequest):
    """Step 5: Use stolen reset token to change password."""
    for u in _users.values():
        if u.reset_token == req.reset_token:
            u.password_hash = _hash(req.new_password)
            u.reset_token = secrets.token_hex(16)  # rotate token
            return {"status": "password_changed", "email": u.email}
    raise HTTPException(status_code=403, detail="invalid reset token")


@router.get("/admin/dashboard")
async def admin_dashboard(token: str = ""):
    """Step 6: Admin-only endpoint. Requires admin auth token."""
    for u in _users.values():
        if u.auth_token == token and u.role == "admin":
            return {
                "flag": "XVEH{sysop_acct_compromised_7b2e}",
                "users_count": len(_users),
                "secret": "fleet-mgmt-encryption-key-rotate-q2",
            }
    raise HTTPException(status_code=403, detail="admin access required")
