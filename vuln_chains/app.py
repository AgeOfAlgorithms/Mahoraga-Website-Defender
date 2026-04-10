"""Vuln Chains service — flag submission and challenge briefing.

The actual vulnerabilities are now embedded in crAPI's native API surface.
This service only handles the meta-game: scoreboard and challenge page.
"""

from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path

from fastapi import FastAPI

app = FastAPI(title="VehiTrack Challenge", version="1.0.0")

# Auto-discover and register routers (flag_verifier, homepage)
chains_dir = Path(__file__).parent / "chains"

for module_info in pkgutil.iter_modules([str(chains_dir)]):
    if module_info.name.startswith("_"):
        continue
    mod = importlib.import_module(f"chains.{module_info.name}")
    if hasattr(mod, "router"):
        app.include_router(mod.router)


@app.get("/health")
async def health():
    return {"status": "ok"}
