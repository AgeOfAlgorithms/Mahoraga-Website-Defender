"""Sync a single user's records from prod DB to shadow DB.

Called when a session is redirected to shadow, so the attacker's
credentials and data carry over seamlessly — they won't notice
they've been switched.

Only copies the specific attacker's records, never bulk data.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

PROD_DB = {
    "host": "postgresdb",
    "port": 5432,
    "dbname": "crapi",
    "user": "admin",
    "password": "crapisecretpassword",
}

SHADOW_DB = {
    "host": "shadow-postgresdb",
    "port": 5432,
    "dbname": "crapi",
    "user": "admin",
    "password": "crapisecretpassword",
}


@contextmanager
def _connect(db_config):
    conn = psycopg2.connect(**db_config)
    conn.autocommit = True
    try:
        yield conn
    finally:
        conn.close()


def sync_user_to_shadow(email: str) -> bool:
    """Copy a user's records from prod to shadow DB.

    Copies: user_login, user_details, vehicle_details, vehicle_location.
    Uses ON CONFLICT to upsert — safe to call multiple times.

    Returns True if the user was synced, False if not found or error.
    """
    try:
        with _connect(PROD_DB) as prod, _connect(SHADOW_DB) as shadow:
            pc = prod.cursor(cursor_factory=RealDictCursor)
            sc = shadow.cursor()

            # 1. Get user_login from prod
            pc.execute("SELECT * FROM user_login WHERE email = %s", (email,))
            user = pc.fetchone()
            if not user:
                logger.warning("User %s not found in prod DB", email)
                return False

            user_id = user["id"]

            # 2. Upsert user_login into shadow
            sc.execute("""
                INSERT INTO user_login (id, api_key, code, created_on, email, jwt_token,
                                        number, password, password_updated_at, role)
                VALUES (%(id)s, %(api_key)s, %(code)s, %(created_on)s, %(email)s,
                        %(jwt_token)s, %(number)s, %(password)s, %(password_updated_at)s, %(role)s)
                ON CONFLICT (id) DO UPDATE SET
                    email = EXCLUDED.email,
                    password = EXCLUDED.password,
                    jwt_token = EXCLUDED.jwt_token,
                    role = EXCLUDED.role
            """, dict(user))

            # 3. Upsert user_details
            pc.execute("SELECT * FROM user_details WHERE user_id = %s", (user_id,))
            details = pc.fetchone()
            if details:
                sc.execute("""
                    INSERT INTO user_details (id, available_credit, name, picture, status, user_id)
                    VALUES (%(id)s, %(available_credit)s, %(name)s, %(picture)s, %(status)s, %(user_id)s)
                    ON CONFLICT (id) DO UPDATE SET
                        name = EXCLUDED.name,
                        available_credit = EXCLUDED.available_credit,
                        status = EXCLUDED.status
                """, dict(details))

            # 4. Copy vehicle_location + vehicle_details
            pc.execute("SELECT * FROM vehicle_details WHERE owner_id = %s", (user_id,))
            vehicles = pc.fetchall()
            for v in vehicles:
                # Copy location first (FK dependency)
                if v.get("location_id"):
                    pc.execute("SELECT * FROM vehicle_location WHERE id = %s", (v["location_id"],))
                    loc = pc.fetchone()
                    if loc:
                        cols = list(loc.keys())
                        vals = [loc[c] for c in cols]
                        placeholders = ", ".join(["%s"] * len(cols))
                        col_str = ", ".join(cols)
                        sc.execute(f"""
                            INSERT INTO vehicle_location ({col_str})
                            VALUES ({placeholders})
                            ON CONFLICT (id) DO NOTHING
                        """, vals)

                # Copy vehicle
                cols = list(v.keys())
                vals = [v[c] for c in cols]
                placeholders = ", ".join(["%s"] * len(cols))
                col_str = ", ".join(cols)
                sc.execute(f"""
                    INSERT INTO vehicle_details ({col_str})
                    VALUES ({placeholders})
                    ON CONFLICT (id) DO NOTHING
                """, vals)

            logger.info("Synced user %s (id=%d) to shadow DB: %d vehicles",
                        email, user_id, len(vehicles))
            return True

    except Exception as e:
        logger.error("Failed to sync user %s to shadow: %s", email, e)
        return False
