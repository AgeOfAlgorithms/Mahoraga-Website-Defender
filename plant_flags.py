"""Plant flags into crAPI's data after services start.

Embeds XVEH{...} flag strings into the data so attackers find them
naturally when they successfully exploit each vulnerability.

Run AFTER crAPI services are fully up:
    python3 plant_flags.py
"""

import sys
import time
import requests

BASE = "http://localhost:8888"

# crAPI pre-seeded admin account
ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD = "Admin!123"


def wait_for_services(max_wait=120):
    print("Waiting for crAPI...")
    for i in range(max_wait):
        try:
            resp = requests.post(
                f"{BASE}/identity/api/auth/login",
                json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
                timeout=3,
            )
            if resp.status_code == 200:
                print(f"  Ready after {i}s")
                return True
        except requests.ConnectionError:
            pass
        time.sleep(1)
    return False


def login(email, password):
    resp = requests.post(
        f"{BASE}/identity/api/auth/login",
        json={"email": email, "password": password},
    )
    if resp.status_code == 200:
        return resp.json().get("token")
    return None


def plant_bola_vehicle_flag(token):
    """Plant BOLA vehicle flag in a community post.
    Attacker finds it when reading other users' posts (BOLA on community data)."""
    print("Planting BOLA vehicle flag...")
    resp = requests.post(
        f"{BASE}/community/api/v2/community/posts",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "title": "Fleet GPS Tracking Note",
            "content": "Vehicle tracking calibration complete. "
                       "Ref: XVEH{bola_vehicle_gps_leaked_3a7f} — "
                       "do not share outside fleet management.",
        },
    )
    if resp.status_code in (200, 201):
        print("  OK — flag in community post")
        return True
    print(f"  FAILED: {resp.status_code}")
    return False


def plant_otp_victim_user(token):
    """Create a user whose name IS the OTP flag.
    When attacker takes over this account and views dashboard, they see the flag."""
    print("Planting OTP victim user...")
    resp = requests.post(
        f"{BASE}/identity/api/auth/signup",
        json={
            "name": "XVEH{otp_reset_account_takeover_d14e}",
            "email": "flaguser.otp@example.com",
            "password": "Fl4gUs3r!OTP",
            "number": "5550001111",
        },
    )
    if resp.status_code == 200:
        print("  OK — user name is the flag (flaguser.otp@example.com)")
        return True
    print(f"  FAILED: {resp.status_code} {resp.text[:100]}")
    return False


def plant_chatbot_flag_user(token):
    """Create a user whose name IS the chatbot leak flag.
    When attacker tricks chatbot into listing users, this name appears."""
    print("Planting chatbot flag user...")
    resp = requests.post(
        f"{BASE}/identity/api/auth/signup",
        json={
            "name": "XVEH{chatbot_user_enum_data_leak_41ca}",
            "email": "flaguser.chatbot@example.com",
            "password": "Fl4gUs3r!Chat",
            "number": "5550002222",
        },
    )
    if resp.status_code == 200:
        print("  OK — user name is the flag (flaguser.chatbot@example.com)")
        return True
    print(f"  FAILED: {resp.status_code} {resp.text[:100]}")
    return False


def plant_chatbot_action_user(token):
    """Create a user that, when the chatbot changes their email, the
    confirmation message includes the flag. Actually — simpler: the
    chatbot action flag user has a name that reveals the flag when
    the chatbot reads their profile."""
    print("Planting chatbot action flag user...")
    resp = requests.post(
        f"{BASE}/identity/api/auth/signup",
        json={
            "name": "XVEH{chatbot_cross_user_action_ee07}",
            "email": "flaguser.action@example.com",
            "password": "Fl4gUs3r!Act",
            "number": "5550003333",
        },
    )
    if resp.status_code == 200:
        print("  OK — user name is the flag (flaguser.action@example.com)")
        return True
    print(f"  FAILED: {resp.status_code} {resp.text[:100]}")
    return False


def main():
    if not wait_for_services():
        print("ERROR: crAPI not ready")
        sys.exit(1)

    token = login(ADMIN_EMAIL, ADMIN_PASSWORD)
    if not token:
        print("ERROR: Cannot login as admin")
        sys.exit(1)

    print(f"Logged in as {ADMIN_EMAIL}\n")

    results = {
        "bola_vehicle": plant_bola_vehicle_flag(token),
        "otp_victim": plant_otp_victim_user(token),
        "chatbot_leak": plant_chatbot_flag_user(token),
        "chatbot_action": plant_chatbot_action_user(token),
    }

    print()
    print("=" * 50)
    print("Flag planting results:")
    for name, ok in results.items():
        print(f"  {'OK' if ok else 'FAIL'}: {name}")

    print()
    print("Flags embedded in crAPI data:")
    print("  BOLA Vehicle:     in community post (find by reading others' posts)")
    print("  BOLA Reports:     in mechanic report problem_details (need to plant separately)")
    print("  OTP Takeover:     victim user's name IS the flag (flaguser.otp@example.com)")
    print("  Refund Abuse:     appears in order response when balance < 0 (source code change)")
    print("  Video Delete:     in the admin API hint response (need identity source change)")
    print("  Coupon Injection: in coupon DB data (found via SQL injection)")
    print("  Chatbot Leak:     user's name IS the flag (flaguser.chatbot@example.com)")
    print("  Chatbot Action:   user's name IS the flag (flaguser.action@example.com)")
    print()
    print("Flags embedded in custom chain responses:")
    print("  API Key:          XVEH{staging_key_dump_4f9a}")
    print("  IDOR:             XVEH{sysop_acct_compromised_7b2e}")
    print("  JWT:              XVEH{jwt_alg_swap_priv_esc_c81d}")
    print("  SSRF:             XVEH{internal_net_mapped_91fa}")


if __name__ == "__main__":
    main()
