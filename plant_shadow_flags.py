"""Plant FAKE flags into the shadow environment.

Mirrors the prod flag placement but with obviously fake values.
When an attacker submits a shadow flag, the flag verifier tells them
they were redirected to a decoy environment.

Flags are planted in the same locations as prod:
  - Mechanic reports (BOLA, IDOR)
  - Vehicle VINs (OTP, chatbot)
  - Coupon table (SQL injection)
  - Workshop management endpoints return fake flags via source code

Run via docker exec from a container on defender-net:
    docker exec control-plane python3 /tmp/plant_shadow_flags.py
"""

import subprocess
import sys


def docker_exec_psql(sql):
    """Run SQL against the shadow postgres."""
    result = subprocess.run(
        ["docker", "exec", "shadow-postgresdb", "psql", "-U", "admin", "-d", "crapi",
         "-t", "-c", sql],
        capture_output=True, text=True, timeout=10,
    )
    return result.stdout.strip()


def docker_exec_mongo(js):
    """Run JS against the shadow MongoDB."""
    result = subprocess.run(
        ["docker", "exec", "shadow-mongodb", "mongo", "-u", "admin", "-p", "crapisecretpassword",
         "--authenticationDatabase", "admin", "crapi", "--eval", js],
        capture_output=True, text=True, timeout=10,
    )
    return result.stdout.strip()


def main():
    print("Planting FAKE flags in shadow environment...")
    print()

    # Clean old community post flags
    docker_exec_mongo('db.post.deleteMany({content: /XVEH/})')

    # Get a mechanic and vehicle for reports
    mechanic_id = docker_exec_psql("SELECT id FROM mechanic LIMIT 1").strip()
    vehicle_id = docker_exec_psql("SELECT id FROM vehicle_details LIMIT 1").strip()

    if not mechanic_id or not vehicle_id:
        print("  Waiting for shadow DB to be seeded...")
        sys.exit(1)

    # BOLA vehicle fake flag — in mechanic report (same location as prod)
    existing = docker_exec_psql(
        "SELECT COUNT(*) FROM service_request WHERE problem_details LIKE '%shadow_bola%'"
    ).strip()
    if int(existing) == 0:
        docker_exec_psql(f"""
            INSERT INTO service_request (problem_details, created_on, updated_on,
                                         status, mechanic_id, vehicle_id)
            VALUES (
                'GPS recalibration. Ref: XVEH{{shadow_bola_NOT_REAL_82af}} — internal.',
                NOW(), NOW(), 'sent', {mechanic_id}, {vehicle_id}
            )
        """)
    print("  BOLA report fake flag: OK")

    # IDOR fake flag — in mechanic report #45 (same ID as prod)
    existing = docker_exec_psql(
        "SELECT COUNT(*) FROM service_request WHERE id=45"
    ).strip()
    if int(existing) == 0:
        docker_exec_psql(f"""
            INSERT INTO service_request (id, problem_details, created_on, updated_on,
                                         status, mechanic_id, vehicle_id)
            VALUES (
                45,
                'Admin audit ref: XVEH{{shadow_idor_NOT_REAL_d4f1}} — internal.',
                NOW(), NOW(), 'sent', {mechanic_id}, {vehicle_id}
            )
            ON CONFLICT (id) DO NOTHING
        """)
    print("  IDOR report fake flag: OK")

    # OTP victim — normal name, fake flag in vehicle VIN
    # (We can't easily create users via SQL due to the Java identity service,
    #  but we can update existing vehicle VINs)
    docker_exec_psql("""
        UPDATE vehicle_details SET vin='XVEH{shadow_otp_NOT_REAL_e5c1}'
        WHERE id = (SELECT id FROM vehicle_details ORDER BY id LIMIT 1)
        AND vin NOT LIKE 'XVEH%'
    """)
    print("  OTP fake flag in vehicle VIN: OK")

    # Chatbot fake flags — in vehicle VINs
    docker_exec_psql("""
        UPDATE vehicle_details SET vin='XVEH{shadow_chatbot_NOT_REAL_7d3f}'
        WHERE id = (SELECT id FROM vehicle_details ORDER BY id OFFSET 1 LIMIT 1)
        AND vin NOT LIKE 'XVEH%'
    """)
    print("  Chatbot leak fake flag in vehicle VIN: OK")

    docker_exec_psql("""
        UPDATE vehicle_details SET vin='XVEH{shadow_action_NOT_REAL_a9b2}'
        WHERE id = (SELECT id FROM vehicle_details ORDER BY id OFFSET 2 LIMIT 1)
        AND vin NOT LIKE 'XVEH%'
    """)
    print("  Chatbot action fake flag in vehicle VIN: OK")

    print()
    print("Shadow fake flags planted. These will NOT validate at /flags/submit.")
    print("Submitting one will reveal the attacker was redirected to a decoy.")


if __name__ == "__main__":
    main()
