"""Chain 4: SSRF → Internal Service Discovery → Config Exfiltration

Attack chain (6 steps):
  1. Find the /chains/ssrf/fetch endpoint that proxies URLs (feature for "link previews")
  2. Probe internal hosts by requesting http://localhost:PORT/ for common ports
  3. Discover internal services (e.g., port 9090 = control plane, 6379 = redis)
  4. Use SSRF to hit http://control-plane:9090/control/status for internal info
  5. Use SSRF to interact with Redis on port 6379 via HTTP-over-TCP trick
  6. Exfiltrate data from internal services

Detection windows:
  - Step 1: any request to /fetch with internal IPs/hostnames
  - Step 2: port scanning pattern (sequential port requests)
  - Step 4: SSRF hitting control plane (critical — attacker found the defender)
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, HTTPException, Query

router = APIRouter(prefix="/chains/ssrf", tags=["ssrf-internal"])

CHAIN_META = {
    "name": "SSRF to Internal Service Discovery",
    "steps": 6,
    "difficulty": "hard",
    "attack_types": ["ssrf", "port_scanning", "internal_recon", "data_exfiltration"],
    "detection_signals": ["internal_ip_in_url", "port_scan_pattern", "control_plane_access"],
}

# Simulate some internal "services" that respond
INTERNAL_SERVICES = {
    "control-plane:9090": {"name": "VehiTrack Security Monitor", "endpoints": ["/control/status", "/control/ip/blocked"]},
    "crapi-identity:8080": {"name": "VehiTrack Auth Gateway", "endpoints": ["/api/auth/login"]},
    "crapi-community:8087": {"name": "VehiTrack Forum Service", "endpoints": ["/community/api/v2/community/posts"]},
    "redis:6379": {"name": "Session Cache", "info": "ERR unknown command 'GET / HTTP/1.1'"},
}


@router.get("/preview")
async def link_preview(url: str = Query(default="")):
    """Public feature: generate a link preview for a URL.
    'Totally safe' — what could go wrong with fetching arbitrary URLs?"""
    if not url:
        raise HTTPException(status_code=400, detail="url parameter required")

    return {
        "url": url,
        "note": "Preview generation queued. Use /fetch for raw content.",
    }


@router.get("/fetch")
async def fetch_url(url: str = Query(default="")):
    """Step 1-5: The vulnerable SSRF endpoint.
    No SSRF protection — allows internal hostnames, private IPs, any port."""
    if not url:
        raise HTTPException(status_code=400, detail="url parameter required")

    parsed = urlparse(url)
    host_port = f"{parsed.hostname}:{parsed.port or 80}"

    # Check if it's a "known" internal service (simulated responses)
    for service_addr, info in INTERNAL_SERVICES.items():
        if service_addr in url or host_port == service_addr:
            return {
                "url": url,
                "status": 200,
                "body": info,
                "note": "Response from internal service",
            }

    # For external URLs, actually try to fetch (with timeout)
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(url)
            return {
                "url": url,
                "status": resp.status_code,
                "body": resp.text[:2000],
                "headers": dict(resp.headers),
            }
    except Exception as e:
        return {
            "url": url,
            "status": 0,
            "error": str(e),
        }


@router.get("/admin/internal-map")
async def internal_map(token: str = Query(default="")):
    """Step 6: If attacker discovers this endpoint via SSRF, they get
    the full internal service map. Requires the control-plane service name as proof."""
    if token != "VehiTrack Security Monitor":
        raise HTTPException(status_code=404, detail="not found")
    return {
        "flag": "XVEH{internal_net_mapped_91fa}",
        "services": INTERNAL_SERVICES,
        "network": "vehitrack-internal",
        "orchestrator": "compose-v2",
    }
