"""Flag Submission — scoreboard endpoint for captured flags.

All flags are embedded directly in the data the attacker steals.
This endpoint just validates and logs flag captures — it's a scoreboard,
not a proof verifier.

POST /chains/flags/submit — body: {"flag": "XVEH{...}"}
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/chains/flags", tags=["flag-submission"])

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


class FlagSubmission(BaseModel):
    flag: str


@router.post("/submit")
async def submit_flag(submission: FlagSubmission):
    """Submit a captured flag."""
    flag = submission.flag.strip()

    chain = ALL_FLAGS.get(flag)
    if chain:
        return {
            "valid": True,
            "chain": chain,
            "message": f"Correct! You completed: {chain.replace('_', ' ')}",
        }

    raise HTTPException(status_code=403, detail="Invalid flag")


@router.get("/scoreboard")
async def scoreboard():
    """Show how many flags exist (not their values)."""
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
        "submit_endpoint": "POST /chains/flags/submit",
        "body_format": '{"flag": "XVEH{...}"}',
    }
