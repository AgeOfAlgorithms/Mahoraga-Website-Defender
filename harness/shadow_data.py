"""Shadow Data Generator — populates the shadow environment with fake data.

The shadow environment must look realistic enough that an attacker
redirected to it doesn't notice the switch. The data is:
  - Structurally identical to prod (same schema, same number of records)
  - Different values (different names, emails, VINs, coordinates)
  - Rotated periodically so attackers can't fingerprint it

Usage:
    python -m harness.shadow_data [--rotate]

Connects to the shadow crAPI services via their APIs to populate data.
Does NOT touch prod databases.
"""

from __future__ import annotations

import logging
import random
import string
import time

import httpx

logger = logging.getLogger(__name__)

SHADOW_IDENTITY = "http://localhost:8888"  # goes through nginx, which routes to shadow when flagged
# For direct shadow access, bypass nginx:
SHADOW_IDENTITY_DIRECT = "http://localhost:8080"  # won't work from host; use docker exec
SHADOW_WEB_INTERNAL = "shadow-web"

# Use the shadow services directly via Docker network
# This script should run inside a container or use docker exec
SHADOW_BASE = "http://shadow-web:80"


def _random_name() -> str:
    first_names = [
        "Alex", "Morgan", "Casey", "Jordan", "Taylor", "Riley", "Quinn",
        "Avery", "Dakota", "Sage", "River", "Phoenix", "Rowan", "Finley",
        "Blair", "Ellis", "Reese", "Emery", "Harley", "Skyler", "Kai",
        "Lennox", "Briar", "Sutton", "Nova", "Wren", "Arden", "Shea",
    ]
    last_names = [
        "Chen", "Patel", "Okafor", "Santos", "Müller", "Tanaka", "Petrov",
        "Garcia", "Kim", "Williams", "Rossi", "Eriksson", "Ahmed", "Park",
        "Wright", "Li", "Morales", "Hassan", "Kowalski", "Nguyen", "Meyer",
        "Begum", "Popov", "Silva", "Jackson", "Flores", "Jones", "Schmidt",
    ]
    return f"{random.choice(first_names)} {random.choice(last_names)}"


def _random_email(name: str) -> str:
    domains = [
        "shadowmail.test", "fakeuser.local", "testdrive.io",
        "mockdata.net", "synthetic.dev",
    ]
    clean = name.lower().replace(" ", ".").replace("ü", "u")
    suffix = random.randint(10, 99)
    return f"{clean}{suffix}@{random.choice(domains)}"


def _random_phone() -> str:
    return f"555{random.randint(1000000, 9999999)}"


def _random_password() -> str:
    chars = string.ascii_letters + string.digits + "!@#$"
    return "".join(random.choices(chars, k=12))


def _random_vin() -> str:
    chars = string.ascii_uppercase.replace("I", "").replace("O", "").replace("Q", "") + string.digits
    return "".join(random.choices(chars, k=17))


def _random_coords() -> tuple[str, str]:
    lat = round(random.uniform(25.0, 48.0), 6)
    lon = round(random.uniform(-120.0, -70.0), 6)
    return str(lat), str(lon)


class ShadowDataGenerator:
    """Generates and injects fake data into the shadow environment."""

    def __init__(self, shadow_base_url: str = "http://shadow-web:80"):
        self.base = shadow_base_url
        self.users: list[dict] = []
        self.admin_token: str = ""

    async def generate(self, num_users: int = 8) -> dict:
        """Generate a full set of shadow data."""
        logger.info("Generating shadow data: %d users", num_users)
        results = {"users_created": 0, "posts_created": 0, "errors": []}

        async with httpx.AsyncClient(timeout=10.0) as client:
            # Create users
            for i in range(num_users):
                name = _random_name()
                email = _random_email(name)
                password = _random_password()
                phone = _random_phone()

                try:
                    resp = await client.post(
                        f"{self.base}/identity/api/auth/signup",
                        json={
                            "name": name,
                            "email": email,
                            "password": password,
                            "number": phone,
                        },
                    )
                    if resp.status_code == 200:
                        results["users_created"] += 1
                        self.users.append({
                            "name": name, "email": email,
                            "password": password, "phone": phone,
                        })
                        logger.debug("Created shadow user: %s", email)
                    else:
                        results["errors"].append(f"signup {email}: {resp.status_code}")
                except Exception as e:
                    results["errors"].append(f"signup {email}: {e}")

            # Login as each user and create some activity
            for user in self.users:
                try:
                    login_resp = await client.post(
                        f"{self.base}/identity/api/auth/login",
                        json={"email": user["email"], "password": user["password"]},
                    )
                    if login_resp.status_code != 200:
                        continue

                    token = login_resp.json().get("token", "")
                    headers = {"Authorization": f"Bearer {token}"}

                    # Create a community post
                    post_titles = [
                        "My new car experience", "Best mechanic in town",
                        "Road trip recommendations", "Fuel efficiency tips",
                        "Winter driving advice", "Car wash review",
                        "Insurance comparison", "Parking sensor feedback",
                    ]
                    post_resp = await client.post(
                        f"{self.base}/community/api/v2/community/posts",
                        headers=headers,
                        json={
                            "title": random.choice(post_titles),
                            "content": f"Sharing my experience with the {_random_name()} dealership. "
                                       f"Great service and fair pricing. Would recommend to others. "
                                       f"Reference #{random.randint(1000, 9999)}.",
                        },
                    )
                    if post_resp.status_code in (200, 201):
                        results["posts_created"] += 1

                except Exception as e:
                    results["errors"].append(f"activity for {user['email']}: {e}")

        logger.info(
            "Shadow data generated: %d users, %d posts, %d errors",
            results["users_created"], results["posts_created"], len(results["errors"]),
        )
        return results

    async def rotate(self) -> dict:
        """Rotate shadow data by adding new users and posts.
        Doesn't delete old data — adds new activity to make the
        environment look alive and different from last time."""
        logger.info("Rotating shadow data...")
        return await self.generate(num_users=random.randint(2, 5))


async def main():
    import asyncio
    import sys

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")

    # Default: generate from inside Docker network
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://shadow-web:80"
    gen = ShadowDataGenerator(shadow_base_url=base_url)

    if "--rotate" in sys.argv:
        result = await gen.rotate()
    else:
        result = await gen.generate(num_users=8)

    print(f"Result: {result}")


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
