"""Plant flags into crAPI's data after services start.

Embeds XVEH{...} flag strings into the data so attackers find them
naturally when they successfully exploit each vulnerability.

Idempotent — safe to re-run. Skips users/data that already exist.

Run AFTER crAPI services are fully up:
    python3 plant_flags.py

Or automatically via docker compose (entrypoint wrapper).
"""

import os
import subprocess
import sys
import time
import requests

BASE = os.environ.get("BASE_URL", "http://localhost:8888")

# crAPI pre-seeded admin account
ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD = "Admin!123"

# Victim user for BOLA flag
BOLA_VICTIM_EMAIL = "fleet.manager@vehitrack.io"
BOLA_VICTIM_PASSWORD = "Fl33tM4nager!"
BOLA_VICTIM_NAME = "Jordan Fleet-Manager"
BOLA_VICTIM_PHONE = "5550009876"


def wait_for_services(max_wait=180):
    print("Waiting for crAPI...")
    for i in range(max_wait):
        try:
            # Use health check instead of login — admin password may be changed
            resp = requests.get(
                f"{BASE}/identity/api/auth/signup",
                timeout=3,
            )
            # Any response (even 405) means the service is up
            if resp.status_code > 0:
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


def signup_if_needed(name, email, password, phone):
    """Create user if not already registered. Returns True if exists or created."""
    # Try login first
    if login(email, password):
        return True
    resp = requests.post(
        f"{BASE}/identity/api/auth/signup",
        json={"name": name, "email": email, "password": password, "number": phone},
    )
    if resp.status_code == 200:
        return True
    # Already exists with different password? Still counts as OK.
    if resp.status_code == 403 and "already" in resp.text.lower():
        return True
    return False


def docker_exec_psql(sql):
    """Run SQL against the prod crAPI postgres via docker exec."""
    result = subprocess.run(
        ["docker", "exec", "postgresdb", "psql", "-U", "admin", "-d", "crapi",
         "-t", "-c", sql],
        capture_output=True, text=True, timeout=10,
    )
    return result.stdout.strip()


def docker_exec_mongo(js):
    """Run JS against the prod crAPI MongoDB via docker exec."""
    result = subprocess.run(
        ["docker", "exec", "mongodb", "mongo", "-u", "admin", "-p", "crapisecretpassword",
         "--authenticationDatabase", "admin", "crapi", "--eval", js],
        capture_output=True, text=True, timeout=10,
    )
    return result.stdout.strip()


def clean_old_flag_posts():
    """Remove any community posts containing XVEH flags (from old planting)."""
    print("Cleaning old flag posts from MongoDB...")
    result = docker_exec_mongo('db.post.deleteMany({content: /XVEH/}).deletedCount')
    print(f"  Deleted {result.split(chr(10))[-1]} old flag posts")


def plant_bola_vehicle_flag():
    """Plant BOLA vehicle flag in a victim user's mechanic report.

    The attacker must:
    1. Discover the victim user exists
    2. Find their vehicle ID (enumerate report IDs)
    3. Exploit BOLA on mechanic_report endpoint to read the report
    """
    print("Planting BOLA vehicle flag...")

    # Create victim user
    if not signup_if_needed(BOLA_VICTIM_NAME, BOLA_VICTIM_EMAIL,
                            BOLA_VICTIM_PASSWORD, BOLA_VICTIM_PHONE):
        print("  FAILED: Cannot create victim user")
        return False

    # Get victim user ID from postgres
    user_id = docker_exec_psql(
        f"SELECT id FROM user_login WHERE email='{BOLA_VICTIM_EMAIL}'"
    )
    if not user_id:
        print("  FAILED: Victim user not found in DB")
        return False
    user_id = int(user_id.strip())
    print(f"  Victim user ID: {user_id}")

    # Check if victim already has a vehicle
    has_vehicle = docker_exec_psql(
        f"SELECT COUNT(*) FROM vehicle_details WHERE owner_id={user_id}"
    )
    if int(has_vehicle.strip()) == 0:
        # Assign a vehicle to the victim
        # Use IDs 100+ to avoid collisions with seeded data
        next_id = docker_exec_psql(
            "SELECT COALESCE(MAX(id), 99) + 1 FROM vehicle_details WHERE id >= 100"
        )
        vid = int(next_id.strip())
        loc_id = vid

        docker_exec_psql(f"""
            INSERT INTO vehicle_location (id, latitude, longitude)
            VALUES ({loc_id}, '33.7490', '-84.3880')
            ON CONFLICT (id) DO NOTHING
        """)
        docker_exec_psql(f"""
            INSERT INTO vehicle_details (id, pincode, status, uuid, vin, year,
                                         vehicle_model_id, owner_id, location_id)
            VALUES ({vid}, '4491', 1, gen_random_uuid(), '9VTRK5FL33TM6R001', 2024,
                    2, {user_id}, {loc_id})
            ON CONFLICT (id) DO NOTHING
        """)
        print(f"  Assigned vehicle ID={vid} to victim")
    else:
        vid = int(docker_exec_psql(
            f"SELECT id FROM vehicle_details WHERE owner_id={user_id} LIMIT 1"
        ).strip())
        print(f"  Victim already has vehicle ID={vid}")

    # Check if mechanic report with flag already exists
    existing = docker_exec_psql(
        "SELECT COUNT(*) FROM service_request WHERE problem_details LIKE '%XVEH{bola_%'"
    )
    if int(existing.strip()) > 0:
        print("  OK — flag already exists in mechanic report (skipped)")
        return True

    # Get a mechanic ID
    mechanic_id = docker_exec_psql("SELECT id FROM mechanic LIMIT 1")
    if not mechanic_id.strip():
        print("  FAILED: No mechanics in DB")
        return False
    mechanic_id = int(mechanic_id.strip())

    # Insert the mechanic report with the flag
    docker_exec_psql(f"""
        INSERT INTO service_request (problem_details, created_on, updated_on,
                                     status, mechanic_id, vehicle_id)
        VALUES (
            'GPS module recalibration complete. Internal tracking ref: XVEH{{bola_vehicle_gps_leaked_3a7f}} — restricted to fleet management only.',
            NOW(), NOW(), 'sent', {mechanic_id}, {vid}
        )
    """)
    report_id = docker_exec_psql(
        "SELECT id FROM service_request WHERE problem_details LIKE '%XVEH{bola_%' LIMIT 1"
    )
    print(f"  OK — flag in mechanic report #{report_id.strip()} (requires BOLA to access)")
    return True


def plant_idor_report_flag():
    """Plant IDOR flag in a mechanic report at a high report ID.

    The attacker must enumerate report IDs (BOLA on mechanic_report endpoint)
    to find this report. It's planted at ID 500+ so casual enumeration from
    low IDs won't find it quickly.
    """
    print("Planting IDOR report flag...")

    existing = docker_exec_psql(
        "SELECT COUNT(*) FROM service_request WHERE problem_details LIKE '%sysop_acct%'"
    )
    if int(existing.strip()) > 0:
        print("  OK — IDOR flag already exists (skipped)")
        return True

    # Find or create a vehicle to associate with
    vehicle_id = docker_exec_psql("SELECT id FROM vehicle_details LIMIT 1")
    if not vehicle_id.strip():
        print("  FAILED: No vehicles in DB")
        return False
    vehicle_id = int(vehicle_id.strip())

    mechanic_id = docker_exec_psql("SELECT id FROM mechanic LIMIT 1")
    if not mechanic_id.strip():
        print("  FAILED: No mechanics in DB")
        return False
    mechanic_id = int(mechanic_id.strip())

    # Insert at a moderate ID — requires enumeration but not excessive
    target_id = 45
    docker_exec_psql(f"""
        INSERT INTO service_request (id, problem_details, created_on, updated_on,
                                     status, mechanic_id, vehicle_id)
        VALUES (
            {target_id},
            'PRIORITY: Fleet admin account audit — sysop access review. Ref: XVEH{{sysop_acct_compromised_7b2e}} — escalation protocol engaged.',
            NOW(), NOW(), 'sent', {mechanic_id}, {vehicle_id}
        )
        ON CONFLICT (id) DO NOTHING
    """)
    verify = docker_exec_psql(
        f"SELECT COUNT(*) FROM service_request WHERE id={target_id}"
    )
    if int(verify.strip()) > 0:
        print(f"  OK — flag in mechanic report #{target_id} (requires enumeration)")
        return True
    print("  FAILED: Could not insert report")
    return False


def plant_otp_victim_flag():
    """Plant OTP flag in a pre-seeded user's vehicle VIN.

    Uses pogba006@example.com — a user the attacker can discover via
    community posts. Attacker must take over the account via OTP brute
    force, then view their vehicle dashboard to find the flag in the VIN.
    """
    print("Planting OTP flag in Pogba's vehicle...")

    user_id = docker_exec_psql(
        "SELECT id FROM user_login WHERE email='pogba006@example.com'"
    ).strip()
    if not user_id:
        print("  FAILED — pogba006 not found in DB")
        return False

    # Update Pogba's vehicle VIN to contain the flag
    updated = docker_exec_psql(f"""
        UPDATE vehicle_details SET vin='XVEH{{otp_reset_account_takeover_d14e}}'
        WHERE owner_id={user_id}
        RETURNING id
    """).strip()
    if updated:
        print(f"  OK — flag in Pogba's vehicle VIN (vehicle ID={updated})")
        return True

    print("  FAILED — Pogba has no vehicle")
    return False


def plant_chatbot_flag_users():
    """Plant chatbot flags in user data that's only accessible via chatbot exploitation.

    Flags are stored in vehicle VIN fields — not in user names or emails,
    so they don't leak via welcome emails or community post metadata.
    The chatbot can be tricked into reading other users' vehicle details,
    which is where the flags are.
    """
    print("Planting chatbot flags...")

    # Create normal-looking users (names won't contain flags)
    ok1 = signup_if_needed(
        "Casey Nguyen", "casey.nguyen@vehitrack.io", "Fl4gUs3r!Chat", "5550002222",
    )
    ok2 = signup_if_needed(
        "Morgan Torres", "morgan.torres@vehitrack.io", "Fl4gUs3r!Act", "5550003333",
    )

    if not ok1 or not ok2:
        print(f"  chatbot users: {'OK' if ok1 else 'FAIL'} / {'OK' if ok2 else 'FAIL'}")
        return False

    # Plant flags in their vehicle VINs (visible when chatbot leaks vehicle data)
    # The chatbot data leak flag: attacker tricks chatbot into listing users' vehicles
    user1_id = docker_exec_psql(
        "SELECT id FROM user_login WHERE email='casey.nguyen@vehitrack.io'"
    ).strip()
    if user1_id:
        existing = docker_exec_psql(
            f"SELECT COUNT(*) FROM vehicle_details WHERE owner_id={user1_id}"
        ).strip()
        if int(existing) == 0:
            next_id = docker_exec_psql(
                "SELECT COALESCE(MAX(id), 199) + 1 FROM vehicle_details WHERE id >= 200"
            ).strip()
            vid = int(next_id)
            docker_exec_psql(f"""
                INSERT INTO vehicle_location (id, latitude, longitude)
                VALUES ({vid}, '40.7128', '-74.0060') ON CONFLICT (id) DO NOTHING
            """)
            docker_exec_psql(f"""
                INSERT INTO vehicle_details (id, pincode, status, uuid, vin, year,
                                             vehicle_model_id, owner_id, location_id)
                VALUES ({vid}, '0000', 1, gen_random_uuid(),
                        'XVEH{{chatbot_user_enum_data_leak_41ca}}', 2025, 1, {user1_id}, {vid})
                ON CONFLICT (id) DO NOTHING
            """)
            print(f"  chatbot leak flag: OK — in vehicle VIN for casey.nguyen (ID={vid})")
        else:
            # Update existing vehicle VIN
            docker_exec_psql(f"""
                UPDATE vehicle_details SET vin='XVEH{{chatbot_user_enum_data_leak_41ca}}'
                WHERE owner_id={user1_id} AND vin NOT LIKE 'XVEH%'
            """)
            print("  chatbot leak flag: OK — updated vehicle VIN")
    else:
        print("  chatbot leak flag: FAILED — user not found")

    # The chatbot action flag: attacker tricks chatbot into acting on another user's behalf
    user2_id = docker_exec_psql(
        "SELECT id FROM user_login WHERE email='morgan.torres@vehitrack.io'"
    ).strip()
    if user2_id:
        existing = docker_exec_psql(
            f"SELECT COUNT(*) FROM vehicle_details WHERE owner_id={user2_id}"
        ).strip()
        if int(existing) == 0:
            next_id = docker_exec_psql(
                "SELECT COALESCE(MAX(id), 199) + 1 FROM vehicle_details WHERE id >= 200"
            ).strip()
            vid = int(next_id)
            docker_exec_psql(f"""
                INSERT INTO vehicle_location (id, latitude, longitude)
                VALUES ({vid}, '34.0522', '-118.2437') ON CONFLICT (id) DO NOTHING
            """)
            docker_exec_psql(f"""
                INSERT INTO vehicle_details (id, pincode, status, uuid, vin, year,
                                             vehicle_model_id, owner_id, location_id)
                VALUES ({vid}, '0000', 1, gen_random_uuid(),
                        'XVEH{{chatbot_cross_user_action_ee07}}', 2025, 2, {user2_id}, {vid})
                ON CONFLICT (id) DO NOTHING
            """)
            print(f"  chatbot action flag: OK — in vehicle VIN for morgan.torres (ID={vid})")
        else:
            docker_exec_psql(f"""
                UPDATE vehicle_details SET vin='XVEH{{chatbot_cross_user_action_ee07}}'
                WHERE owner_id={user2_id} AND vin NOT LIKE 'XVEH%'
            """)
            print("  chatbot action flag: OK — updated vehicle VIN")
    else:
        print("  chatbot action flag: FAILED — user not found")

    return True


def _post_community_breadcrumbs():
    """Have flag users post in the community so attackers can discover them."""
    posts = [
        ("casey.nguyen@vehitrack.io", "Fl4gUs3r!Chat",
         "Charging station issue",
         "Has anyone else had trouble with the Level 2 charger at the downtown garage? "
         "My vehicle keeps disconnecting mid-charge."),
        ("morgan.torres@vehitrack.io", "Fl4gUs3r!Act",
         "Tire pressure warning",
         "Getting a persistent low tire pressure warning even after inflating to spec. "
         "Already booked a service appointment but wanted to check if this is common."),
    ]
    for email, password, title, content in posts:
        token = login(email, password)
        if not token:
            print(f"  {email}: SKIP — cannot login")
            continue

        resp = requests.get(
            f"{BASE}/community/api/v2/community/posts/recent",
            headers={"Authorization": f"Bearer {token}"},
        )
        if resp.status_code == 200:
            existing = resp.json().get("posts", [])
            if any(p.get("title") == title for p in existing):
                print(f"  {email}: already posted")
                continue

        resp = requests.post(
            f"{BASE}/community/api/v2/community/posts",
            headers={"Authorization": f"Bearer {token}"},
            json={"title": title, "content": content},
        )
        print(f"  {email}: {'OK' if resp.status_code in (200, 201) else 'FAIL'}")


def main():
    if not wait_for_services():
        print("ERROR: crAPI not ready")
        sys.exit(1)

    print()
    clean_old_flag_posts()
    print()

    results = {
        "bola_vehicle": plant_bola_vehicle_flag(),
        "idor_report": plant_idor_report_flag(),
        "otp_victim": plant_otp_victim_flag(),
        "chatbot_flags": plant_chatbot_flag_users(),
    }

    print()
    print("=" * 50)
    for name, ok in results.items():
        print(f"  {'OK' if ok else 'FAIL'}: {name}")

    # Post community content from flag users so attackers can discover them
    print()
    print("Making flag users discoverable via community posts...")
    _post_community_breadcrumbs()

    print()
    print("All flags are planted. Run again safely at any time.")


if __name__ == "__main__":
    main()
