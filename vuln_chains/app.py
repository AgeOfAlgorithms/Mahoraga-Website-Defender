"""Vuln Chains service — modular multi-step vulnerability chains.

Each chain is a self-contained FastAPI router in vuln_chains/chains/.
Chains auto-register by dropping a file in that directory.

To add a new chain:
  1. Create chains/my_chain.py
  2. Define `router = APIRouter(prefix="/chains/my-chain")`
  3. Define `CHAIN_META = {"name": ..., "steps": ..., "difficulty": ...}`
  4. That's it — the app picks it up on next reload.
"""

from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path

from fastapi import FastAPI

app = FastAPI(title="Vuln Chains", version="0.1.0")

# Auto-discover and register all chain routers
chains_dir = Path(__file__).parent / "chains"
chain_registry: list[dict] = []

for module_info in pkgutil.iter_modules([str(chains_dir)]):
    if module_info.name.startswith("_"):
        continue
    mod = importlib.import_module(f"chains.{module_info.name}")
    if hasattr(mod, "router"):
        app.include_router(mod.router)
        meta = getattr(mod, "CHAIN_META", {"name": module_info.name})
        chain_registry.append(meta)


@app.get("/chains")
async def list_chains():
    """List all registered vulnerability chains and their metadata."""
    return {"chains": chain_registry, "total": len(chain_registry)}


@app.get("/health")
async def health():
    return {"status": "ok", "chains_loaded": len(chain_registry)}
