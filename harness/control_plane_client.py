"""Client for the Control Plane API.

Used by the orchestrator to:
- Score sessions (triggers shadow redirect when threshold exceeded)
- Query shadow and system status
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)


@dataclass
class ControlPlaneClient:
    base_url: str = "http://localhost:9090"

    # ── Session scoring ───────────────────────────────────────────

    async def score_session(
        self, event_type: str, severity: str,
        token: str = "", ja3: str = "", points: int = 0,
    ) -> dict:
        """Add threat score to a session. May trigger shadow redirect."""
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.base_url}/control/session/score",
                json={
                    "token": token,
                    "ja3": ja3,
                    "event_type": event_type,
                    "severity": severity,
                    "points": points,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            if data.get("redirected"):
                logger.warning(
                    "SESSION REDIRECTED TO SHADOW: %s (score exceeded %d)",
                    event_type, data.get("threshold", 0),
                )
            return data

    # ── Status ────────────────────────────────────────────────────

    async def get_session_score(self, token: str) -> dict:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{self.base_url}/control/session/score/{token}")
            return resp.json()

    async def get_shadow_status(self) -> dict:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{self.base_url}/control/shadow/status")
            return resp.json()

    async def get_status(self) -> dict:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{self.base_url}/control/status")
            return resp.json()
