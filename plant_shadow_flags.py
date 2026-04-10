"""Plant FAKE flags into the shadow environment.

These look like real flags but have different values. When an attacker
submits a shadow flag to /chains/flags/submit, it returns "Invalid flag"
— they think they got the wrong value and keep trying.

On our end, we can detect shadow flag submissions to confirm the attacker
completed an exploit chain in shadow (which triggers the Fixer).

Run from inside Docker network (or via docker exec):
    docker exec control-plane python3 /app/plant_shadow_flags.py
"""

import sys
import time
import urllib.request
import json

# Shadow services are on separate hostnames
SHADOW_BASE = "http://shadow-web:80"

SHADOW_ADMIN_EMAIL = "admin@example.com"
SHADOW_ADMIN_PASSWORD = "Admin!123"


def post_json(url, data, headers=None):
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode(),
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        return resp.status, json.loads(resp.read())
    except Exception as e:
        return 0, str(e)


def get_json(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        return resp.status, json.loads(resp.read())
    except Exception as e:
        return 0, str(e)


def main():
    print("Planting FAKE flags in shadow environment...")
    print()

    # Login as admin in shadow
    status, data = post_json(
        f"{SHADOW_BASE}/identity/api/auth/login",
        {"email": SHADOW_ADMIN_EMAIL, "password": SHADOW_ADMIN_PASSWORD},
    )
    if status != 200:
        print(f"  Shadow login failed: {status} {data}")
        sys.exit(1)

    token = data.get("token", "")
    headers = {"Authorization": f"Bearer {token}"}
    print(f"  Logged into shadow as {SHADOW_ADMIN_EMAIL}")

    # Plant BOLA vehicle fake flag in community post
    status, _ = post_json(
        f"{SHADOW_BASE}/community/api/v2/community/posts",
        {
            "title": "Fleet GPS Note",
            "content": "Calibration ref: XVEH{shadow_bola_NOT_REAL_82af} — internal only.",
        },
        headers,
    )
    print(f"  BOLA vehicle fake flag: {'OK' if status in (200,201) else 'FAIL'}")

    # Plant OTP victim user with fake flag name
    status, data = post_json(
        f"{SHADOW_BASE}/identity/api/auth/signup",
        {
            "name": "XVEH{shadow_otp_NOT_REAL_e5c1}",
            "email": "flaguser.otp@example.com",
            "password": "Sh4d0wFL4g!",
            "number": "5551110001",
        },
    )
    print(f"  OTP fake flag user: {'OK' if status == 200 else data}")

    # Plant chatbot fake flag users
    for name, email, phone in [
        ("XVEH{shadow_chatbot_NOT_REAL_7d3f}", "flaguser.chatbot@example.com", "5551110002"),
        ("XVEH{shadow_action_NOT_REAL_a9b2}", "flaguser.action@example.com", "5551110003"),
    ]:
        status, data = post_json(
            f"{SHADOW_BASE}/identity/api/auth/signup",
            {"name": name, "email": email, "password": "Sh4d0wFL4g!", "number": phone},
        )
        print(f"  {email}: {'OK' if status == 200 else data}")

    print()
    print("Shadow fake flags planted. These will NOT validate at /chains/flags/submit.")


if __name__ == "__main__":
    main()
