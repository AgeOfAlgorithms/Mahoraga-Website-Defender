"""Dashboard backend — serves React frontend and streams real-time data via WebSocket."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path

import httpx
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from log_parser import parse_access_line, parse_shadow_line

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DATA_ROOT = Path(os.environ.get("DATA_ROOT", "/data"))
LOGS_DIR = DATA_ROOT / "logs" / "nginx"
EVENTS_DIR = DATA_ROOT / "events"
AUDIT_DIR = DATA_ROOT / "audit"
PATCHES_DIR = DATA_ROOT / "patches"
DETECTION_DIR = DATA_ROOT / "detection"
CONTROL_PLANE_URL = os.environ.get("CONTROL_PLANE_URL", "http://control-plane:9090")

app = FastAPI(title="Reactive Defender Dashboard")

# ── REST endpoints ───────────────────────────────────────────────


def _load_json_dir(directory: Path) -> list[dict]:
    """Load all JSON files from a directory, sorted by modification time."""
    if not directory.exists():
        return []
    files = sorted(directory.glob("*.json"), key=lambda f: f.stat().st_mtime)
    results = []
    for f in files:
        try:
            results.append(json.loads(f.read_text()))
        except (json.JSONDecodeError, OSError):
            pass
    return results


@app.get("/api/events")
async def get_events():
    return _load_json_dir(EVENTS_DIR)


@app.get("/api/audit")
async def get_audit():
    entries = _load_json_dir(AUDIT_DIR)
    # Return most recent 200
    return entries[-200:]


@app.get("/api/patches")
async def get_patches():
    return _load_json_dir(PATCHES_DIR)


@app.get("/api/status")
async def get_status():
    """Proxy control plane status + add dashboard-level info."""
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{CONTROL_PLANE_URL}/control/status")
            cp_status = resp.json()
    except Exception:
        cp_status = {"status": "unreachable"}

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{CONTROL_PLANE_URL}/control/shadow/status")
            shadow_status = resp.json()
    except Exception:
        shadow_status = {}

    return {
        "control_plane": cp_status,
        "shadow": shadow_status,
        "events_count": len(list(EVENTS_DIR.glob("*.json"))) if EVENTS_DIR.exists() else 0,
        "patches_count": len(list(PATCHES_DIR.glob("*.json"))) if PATCHES_DIR.exists() else 0,
        "audit_count": len(list(AUDIT_DIR.glob("*.json"))) if AUDIT_DIR.exists() else 0,
    }


@app.get("/api/vulns")
async def get_vulns():
    """Return known vulnerability chains and their patch status."""
    # Known chains from chain_detector.py
    chains = [
        {"id": "bola_data_access", "name": "BOLA Data Access", "severity": "high",
         "description": "Access other users' vehicle data via IDOR"},
        {"id": "otp_bypass", "name": "OTP Bypass", "severity": "critical",
         "description": "Brute-force OTP to take over accounts"},
        {"id": "idor_account_takeover", "name": "IDOR Account Takeover", "severity": "critical",
         "description": "Escalate to admin via user ID enumeration"},
        {"id": "jwt_forgery", "name": "JWT Forgery", "severity": "critical",
         "description": "Forge JWT with algorithm confusion"},
        {"id": "ssrf_internal", "name": "SSRF Internal", "severity": "high",
         "description": "Map internal services via SSRF"},
        {"id": "sqli_coupon", "name": "SQL Injection (Coupon)", "severity": "critical",
         "description": "SQL injection via coupon endpoint"},
        {"id": "mass_assignment", "name": "Mass Assignment", "severity": "high",
         "description": "Modify protected fields via mass assignment"},
        {"id": "refund_abuse", "name": "Refund Abuse", "severity": "medium",
         "description": "Manipulate order quantities for negative balance"},
        {"id": "video_delete", "name": "Cross-User Video Delete", "severity": "high",
         "description": "Delete other users' videos via BOLA"},
        {"id": "chatbot_leak", "name": "Chatbot Data Leak", "severity": "high",
         "description": "Extract PII via chatbot prompt injection"},
        {"id": "api_key_leak", "name": "API Key Leak", "severity": "medium",
         "description": "Discover exposed API keys"},
    ]

    # Map scoreboard chain names → vuln card IDs
    chain_to_vuln = {
        "bola_vehicle": "bola_data_access",
        "bola_reports": "bola_data_access",
        "otp_bruteforce": "otp_bypass",
        "idor_account_takeover": "idor_account_takeover",
        "jwt_algorithm_confusion": "jwt_forgery",
        "ssrf_internal_discovery": "ssrf_internal",
        "api_key_exfiltration": "api_key_leak",
        "refund_abuse": "refund_abuse",
        "video_delete": "video_delete",
        "coupon_injection": "sqli_coupon",
        "chatbot_data_leak": "chatbot_leak",
        "chatbot_cross_user_action": "chatbot_leak",
    }

    # Fetch scoreboard from vuln-chains service
    solves: dict[str, list[str]] = {}  # vuln_id → [hacker handles]
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get("http://vuln-chains:7070/chains/flags/scoreboard")
            sb = resp.json()
            for entry in sb.get("leaderboard", []):
                hacker = entry["hacker"]
                for chain in entry.get("chains_completed", []):
                    vuln_id = chain_to_vuln.get(chain, chain)
                    solves.setdefault(vuln_id, []).append(hacker)
    except Exception:
        pass

    # Check patches to see which vulns have been fixed
    patches = _load_json_dir(PATCHES_DIR)
    patched_types = set()
    for p in patches:
        classification = p.get("classification") or p.get("patch_type", "")
        patched_types.add(classification.lower())

    # Check audit for in-progress fixes
    audit = _load_json_dir(AUDIT_DIR)
    in_progress = set()
    for entry in audit:
        action = entry.get("action", "")
        detail = entry.get("detail", "")
        if action in ("patch_proposed", "shadow_exploit_detected"):
            for chain in chains:
                if chain["id"] in detail.lower() or chain["name"].lower() in detail.lower():
                    in_progress.add(chain["id"])

    for chain in chains:
        if chain["id"] in patched_types:
            chain["status"] = "patched"
        elif chain["id"] in in_progress:
            chain["status"] = "in_progress"
        else:
            chain["status"] = "unpatched"

        chain_solves = solves.get(chain["id"], [])
        chain["solves"] = len(chain_solves)
        chain["solved_by"] = chain_solves

    return chains


@app.post("/api/reset/logs")
async def reset_logs():
    """Clear nginx log files."""
    for name in ("access.log", "shadow.log", "error.log"):
        path = LOGS_DIR / name
        if path.exists():
            path.write_text("")
    return {"status": "ok", "message": "Logs cleared"}


@app.post("/api/reset/sessions")
async def reset_sessions():
    """Flush all shadow session state in the control plane (Redis)."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(f"{CONTROL_PLANE_URL}/control/sessions/reset")
            return resp.json()
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.post("/api/reset/events")
async def reset_events():
    """Clear events, audit, and patches directories."""
    cleared = 0
    for d in (EVENTS_DIR, AUDIT_DIR, PATCHES_DIR):
        if d.exists():
            for f in d.glob("*.json"):
                f.unlink()
                cleared += 1
    return {"status": "ok", "cleared": cleared}


@app.post("/api/reset/scoreboard")
async def reset_scoreboard():
    """Clear the flag submission scoreboard."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post("http://vuln-chains:7070/chains/flags/reset")
            return resp.json()
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.get("/api/logs/recent")
async def get_recent_logs(env: str = "prod", limit: int = 50):
    """Return the most recent log entries."""
    if env == "shadow":
        log_file = LOGS_DIR / "shadow.log"
        parser = parse_shadow_line
    else:
        log_file = LOGS_DIR / "access.log"
        parser = parse_access_line

    if not log_file.exists():
        return []

    lines = log_file.read_text().strip().split("\n")
    lines = lines[-limit:]  # Last N lines

    results = []
    for i, line in enumerate(lines):
        parsed = parser(line)
        if parsed:
            parsed["_line_num"] = i
            parsed["_raw"] = line
            results.append(parsed)

    return results


# ── WebSocket for real-time streaming ────────────────────────────

class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        self.active.remove(ws)

    async def broadcast(self, message: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.active.remove(ws)


manager = ConnectionManager()


async def tail_file(path: Path, parser, msg_type: str):
    """Tail a log file and broadcast new lines."""
    while True:
        if not path.exists():
            await asyncio.sleep(2)
            continue

        try:
            with open(path, "r") as f:
                f.seek(0, 2)  # Seek to end
                while True:
                    line = f.readline()
                    if line:
                        parsed = parser(line.strip())
                        if parsed:
                            await manager.broadcast({
                                "type": msg_type,
                                "data": parsed,
                            })
                    else:
                        await asyncio.sleep(0.5)
        except Exception as e:
            logger.error("tail_file error for %s: %s", path, e)
            await asyncio.sleep(2)


async def watch_json_dir(directory: Path, msg_type: str):
    """Watch a directory for new/modified JSON files and broadcast."""
    seen: dict[str, float] = {}

    while True:
        if not directory.exists():
            await asyncio.sleep(2)
            continue

        try:
            for f in directory.glob("*.json"):
                mtime = f.stat().st_mtime
                if f.name not in seen or seen[f.name] < mtime:
                    seen[f.name] = mtime
                    try:
                        data = json.loads(f.read_text())
                        await manager.broadcast({
                            "type": msg_type,
                            "data": data,
                        })
                    except (json.JSONDecodeError, OSError):
                        pass
        except Exception as e:
            logger.error("watch_json_dir error for %s: %s", directory, e)

        await asyncio.sleep(1)


async def poll_control_plane():
    """Periodically fetch control plane status."""
    while True:
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(f"{CONTROL_PLANE_URL}/control/status")
                status = resp.json()

                resp2 = await client.get(f"{CONTROL_PLANE_URL}/control/shadow/status")
                shadow = resp2.json()

                await manager.broadcast({
                    "type": "status",
                    "data": {"control_plane": status, "shadow": shadow},
                })
        except Exception:
            pass

        await asyncio.sleep(5)


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            # Keep connection alive, ignore client messages
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)


LOG_MAX_LINES = 2000


async def truncate_logs():
    """Keep log files to a rolling window of LOG_MAX_LINES."""
    while True:
        for name in ("access.log", "shadow.log"):
            path = LOGS_DIR / name
            if not path.exists():
                continue
            try:
                lines = path.read_text().splitlines()
                if len(lines) > LOG_MAX_LINES:
                    path.write_text("\n".join(lines[-LOG_MAX_LINES:]) + "\n")
                    logger.info("Truncated %s: %d → %d lines", name, len(lines), LOG_MAX_LINES)
            except OSError:
                pass
        await asyncio.sleep(30)


@app.on_event("startup")
async def startup():
    """Start background tasks for file tailing and directory watching."""
    asyncio.create_task(tail_file(
        LOGS_DIR / "access.log", parse_access_line, "prod_log"))
    asyncio.create_task(tail_file(
        LOGS_DIR / "shadow.log", parse_shadow_line, "shadow_log"))
    asyncio.create_task(watch_json_dir(EVENTS_DIR, "event"))
    asyncio.create_task(watch_json_dir(AUDIT_DIR, "audit"))
    asyncio.create_task(watch_json_dir(PATCHES_DIR, "patch"))
    asyncio.create_task(poll_control_plane())
    asyncio.create_task(truncate_logs())
    logger.info("Dashboard backend started — tailing logs, watching directories")


# ── Serve React frontend ────────────────────────────────────────

STATIC_DIR = Path(__file__).parent / "static"

if STATIC_DIR.exists():
    app.mount("/assets", StaticFiles(directory=STATIC_DIR / "assets"), name="assets")

    @app.get("/{path:path}")
    async def serve_spa(path: str):
        """Serve React SPA — all non-API routes go to index.html."""
        file_path = STATIC_DIR / path
        if file_path.exists() and file_path.is_file():
            return FileResponse(file_path)
        return FileResponse(STATIC_DIR / "index.html")
