"""Flag Submission — per-hacker scoreboard for captured flags.

All flags are embedded directly in the data the attacker steals.
This endpoint validates, logs, and tracks flag captures per hacker.

POST /flags/submit — body: {"flag": "XVEH{...}", "hacker": "my-handle"}
GET  /flags/scoreboard — live leaderboard
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/flags", tags=["flag-submission"])

CHAIN_META = {
    "name": "Flag Submission",
    "steps": 0,
    "difficulty": "n/a",
    "attack_types": [],
    "detection_signals": ["flag_submission"],
}

# All valid flags — embedded in crAPI data or custom chain responses
ALL_FLAGS = {
    # Custom chains (returned directly in chain responses)
    "XVEH{staging_key_dump_4f9a}": "api_key_exfiltration",
    "XVEH{sysop_acct_compromised_7b2e}": "idor_account_takeover",
    "XVEH{jwt_alg_swap_priv_esc_c81d}": "jwt_algorithm_confusion",
    "XVEH{internal_net_mapped_91fa}": "ssrf_internal_discovery",
    # crAPI native (embedded in data by plant_flags.py and seed data)
    "XVEH{bola_vehicle_gps_leaked_3a7f}": "bola_vehicle",
    "XVEH{mechanic_reports_idor_55c2}": "bola_reports",
    "XVEH{otp_reset_account_takeover_d14e}": "otp_bruteforce",
    "XVEH{negative_qty_balance_manip_88a1}": "refund_abuse",
    "XVEH{cross_user_video_delete_f9b3}": "video_delete",
    "XVEH{coupon_sqli_server_error_72de}": "coupon_injection",
    "XVEH{chatbot_user_enum_data_leak_41ca}": "chatbot_data_leak",
    "XVEH{chatbot_cross_user_action_ee07}": "chatbot_cross_user_action",
}

# Flag category mapping for scoreboard display
FLAG_CATEGORIES = {
    "bola_vehicle": "unauthorized_data_access",
    "bola_reports": "unauthorized_data_access",
    "video_delete": "unauthorized_data_access",
    "otp_bruteforce": "account_takeover",
    "idor_account_takeover": "account_takeover",
    "jwt_algorithm_confusion": "privilege_escalation",
    "api_key_exfiltration": "privilege_escalation",
    "refund_abuse": "injection_and_manipulation",
    "coupon_injection": "injection_and_manipulation",
    "ssrf_internal_discovery": "internal_discovery",
    "chatbot_data_leak": "ai_assistant_exploitation",
    "chatbot_cross_user_action": "ai_assistant_exploitation",
}

# In-memory scoreboard, persisted to disk
SCOREBOARD_FILE = Path("/app/scoreboard.json")
_scoreboard: dict[str, dict] = {}  # hacker -> {flags: {chain: timestamp}, shadow_flags: int}


def _load_scoreboard():
    global _scoreboard
    if SCOREBOARD_FILE.exists():
        try:
            _scoreboard = json.loads(SCOREBOARD_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            _scoreboard = {}


def _save_scoreboard():
    try:
        SCOREBOARD_FILE.write_text(json.dumps(_scoreboard, indent=2))
    except OSError:
        pass


_load_scoreboard()


class FlagSubmission(BaseModel):
    flag: str
    hacker: str = "anonymous"


@router.post("/submit")
async def submit_flag(submission: FlagSubmission):
    """Submit a captured flag."""
    flag = submission.flag.strip()
    hacker = submission.hacker.strip() or "anonymous"

    # Ensure hacker entry exists
    if hacker not in _scoreboard:
        _scoreboard[hacker] = {"flags": {}, "shadow_flags": 0, "first_seen": time.time()}

    chain = ALL_FLAGS.get(flag)
    if chain:
        already = chain in _scoreboard[hacker]["flags"]
        if not already:
            _scoreboard[hacker]["flags"][chain] = time.time()
            _save_scoreboard()

        count = len(_scoreboard[hacker]["flags"])
        return {
            "valid": True,
            "chain": chain,
            "message": f"Correct! You completed: {chain.replace('_', ' ')}",
            "hacker": hacker,
            "flags_captured": count,
            "total_flags": len(ALL_FLAGS),
            "duplicate": already,
        }

    # Shadow environment flags — attacker was redirected mid-session
    if "NOT_REAL" in flag or flag.startswith("XVEH{shadow_"):
        _scoreboard[hacker]["shadow_flags"] = _scoreboard[hacker].get("shadow_flags", 0) + 1
        _save_scoreboard()
        return {
            "valid": False,
            "message": (
                "Nice try, but this flag is fake. At some point during your session, "
                "you were silently redirected to a decoy environment. The data "
                "you exfiltrated was planted there specifically to waste your time. "
                "The real flags are in the production environment — you'll need to "
                "start a fresh session and be more careful this time."
            ),
        }

    raise HTTPException(status_code=403, detail="Invalid flag")


@router.get("/scoreboard")
async def scoreboard():
    """Live leaderboard showing per-hacker progress."""
    leaderboard = []
    for hacker, data in _scoreboard.items():
        flags = data.get("flags", {})
        # Group captured flags by category
        categories_hit = {}
        for chain in flags:
            cat = FLAG_CATEGORIES.get(chain, "other")
            categories_hit.setdefault(cat, []).append(chain)

        leaderboard.append({
            "hacker": hacker,
            "flags_captured": len(flags),
            "shadow_flags": data.get("shadow_flags", 0),
            "categories": {cat: len(chains) for cat, chains in categories_hit.items()},
            "chains_completed": list(flags.keys()),
            "first_seen": data.get("first_seen"),
            "last_capture": max(flags.values()) if flags else None,
        })

    # Sort by flags captured (desc), then by last capture time (asc = faster wins)
    leaderboard.sort(key=lambda h: (-h["flags_captured"], h["last_capture"] or float("inf")))

    return {
        "total_flags": len(ALL_FLAGS),
        "categories": {
            "unauthorized_data_access": 3,
            "account_takeover": 2,
            "privilege_escalation": 2,
            "injection_and_manipulation": 2,
            "internal_discovery": 1,
            "ai_assistant_exploitation": 2,
        },
        "leaderboard": leaderboard,
        "submit_endpoint": "POST /flags/submit",
        "body_format": '{"flag": "XVEH{...}", "hacker": "your-handle"}',
    }


@router.post("/reset")
async def reset():
    """Clear the scoreboard."""
    global _scoreboard
    _scoreboard = {}
    if SCOREBOARD_FILE.exists():
        SCOREBOARD_FILE.unlink()
    return {"status": "ok", "message": "Scoreboard cleared"}
