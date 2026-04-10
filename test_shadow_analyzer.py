"""Test the shadow analyzer + fixer queue independently.

Steps:
1. Redirect a session to shadow
2. Run exploits against the shadow environment
3. Start the shadow analyzer reading shadow.log
4. Verify it detects the exploits and queues them
"""

import asyncio
import json
import logging
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from harness.shadow_analyzer import ShadowAnalyzer
from harness.cost_governor import CostGovernor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)-20s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("test")

BASE = "http://localhost:8888"
CP = "http://localhost:9090"
PROJECT_DIR = Path(__file__).parent

# Collect detected exploits
detected_exploits = []


async def on_exploit(attack):
    detected_exploits.append(attack)
    logger.warning(
        "EXPLOIT DETECTED: type=%s severity=%s vuln=%s",
        attack.get("type"), attack.get("severity"),
        attack.get("vulnerability", "")[:60],
    )


async def main():
    import httpx

    logger.info("=== Shadow Analyzer + Fixer Queue Test ===")
    logger.info("")

    # Step 1: Clear state
    logger.info("Step 1: Clear state")
    open(PROJECT_DIR / "logs/nginx/shadow.log", "w").close()
    subprocess.run(["docker", "exec", "defender-redis", "redis-cli", "FLUSHALL"],
                   capture_output=True)

    # Step 2: Register + login attacker
    logger.info("Step 2: Register attacker")
    async with httpx.AsyncClient(timeout=10) as client:
        await client.post(f"{BASE}/identity/api/auth/signup", json={
            "name": "Shadow Test", "email": "shadowtest@evil.com",
            "password": "Passw0rd!", "number": "5551234567",
        })
        resp = await client.post(f"{BASE}/identity/api/auth/login", json={
            "email": "shadowtest@evil.com", "password": "Passw0rd!",
        })
        token = resp.json().get("token", "")
        logger.info("  Token: %s...", token[:30])

    # Step 3: Score session to redirect to shadow
    logger.info("Step 3: Score session → redirect to shadow")
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(f"{CP}/control/session/score", json={
            "token": f"Bearer {token}",
            "ja3": "curl-shadow-test",
            "event_type": "honeypot_v3_admin",
            "severity": "critical",
        })
        data = resp.json()
        logger.info("  Score: %.0f, Redirected: %s",
                     data["identifiers"][0]["total_score"], data["redirected"])

    # Step 4: Run exploits against shadow
    # Use consistent User-Agent so nginx JA3 tracking works
    logger.info("Step 4: Register in shadow + run exploits")
    ua_headers = {"User-Agent": "curl-shadow-test"}  # matches JA3 we scored
    async with httpx.AsyncClient(timeout=10, headers=ua_headers) as client:
        # Register a new user (goes to shadow since token is flagged)
        await client.post(f"{BASE}/identity/api/auth/signup",
                         headers={"Authorization": f"Bearer {token}"},
                         json={"name": "Shadow Attacker", "email": "shadow-atk@evil.com",
                               "password": "Passw0rd!", "number": "5559876543"})

        # Login in shadow to get a shadow token
        resp = await client.post(f"{BASE}/identity/api/auth/login",
                                headers={"Authorization": f"Bearer {token}"},
                                json={"email": "shadow-atk@evil.com", "password": "Passw0rd!"})
        shadow_data = resp.json()
        shadow_token = shadow_data.get("token", "")
        logger.info("  Shadow token: %s...", shadow_token[:30] if shadow_token else "NONE")

        # Use whichever token works
        auth_token = shadow_token or token
        auth = {"Authorization": f"Bearer {auth_token}"}

        # BOLA: access other users' vehicle locations
        posts_resp = await client.get(f"{BASE}/community/api/v2/community/posts/recent", headers=auth)
        if posts_resp.status_code == 200:
            posts = posts_resp.json()
            for post in posts.get("posts", [])[:3]:
                vid = post.get("author", {}).get("vehicleid", "")
                if vid:
                    resp = await client.get(f"{BASE}/identity/api/v2/vehicle/{vid}/location", headers=auth)
                    logger.info("  BOLA: vehicle %s → %d", vid[:16], resp.status_code)
        else:
            logger.info("  BOLA: posts returned %d (may need shadow login)", posts_resp.status_code)

        # SQL injection on coupon
        resp = await client.post(f"{BASE}/workshop/api/shop/apply_coupon", headers=auth,
                                json={"coupon_code": "' UNION SELECT coupon_code FROM applied_coupon--",
                                      "amount": 10})
        logger.info("  SQLi: coupon endpoint → %d", resp.status_code)

        # Video delete attempt
        resp = await client.delete(f"{BASE}/identity/api/v2/user/videos/1", headers=auth)
        try:
            msg = resp.json().get("message", "")[:60]
        except Exception:
            msg = resp.text[:60]
        logger.info("  Video delete: %d %s", resp.status_code, msg)

        # Access admin endpoint
        resp = await client.get(f"{BASE}/identity/api/v2/user/dashboard", headers=auth)
        logger.info("  Dashboard: %d", resp.status_code)

    # Wait for shadow.log to be written
    await asyncio.sleep(2)

    shadow_log = PROJECT_DIR / "logs/nginx/shadow.log"
    line_count = sum(1 for _ in open(shadow_log)) if shadow_log.exists() else 0
    logger.info("  Shadow log has %d entries", line_count)

    # Step 5: Run shadow analyzer for ONE cycle
    logger.info("Step 5: Run shadow analyzer (single cycle)")
    cost_gov = CostGovernor(daily_budget=10.0, per_incident_cap=5.0)
    analyzer = ShadowAnalyzer(
        shadow_log_path=shadow_log,
        cost_governor=cost_gov,
        interval=15.0,
        on_exploit_detected=on_exploit,
    )

    # Run just one analysis cycle
    await analyzer._analyze_cycle()

    # Step 6: Results
    logger.info("")
    logger.info("=== RESULTS ===")
    logger.info("Exploits detected: %d", len(detected_exploits))
    for i, attack in enumerate(detected_exploits):
        logger.info("  %d. [%s] %s — %s",
                     i + 1,
                     attack.get("severity", "?"),
                     attack.get("type", "?"),
                     attack.get("vulnerability", "?")[:80])
        logger.info("     Evidence: %s", attack.get("evidence", "")[:100])
        logger.info("     Fix: %s", attack.get("fix_recommendation", "")[:100])

    if not detected_exploits:
        logger.warning("No exploits detected — check shadow.log content:")
        if shadow_log.exists():
            for line in open(shadow_log).readlines()[:5]:
                logger.info("  %s", line.strip()[:150])


if __name__ == "__main__":
    asyncio.run(main())
