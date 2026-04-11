"""Watcher agent — tails logs and emits SecurityEvents.

Detection strategy:
  1. Generic attack signatures (SQLi, XSS, etc.) — regex
  2. crAPI-specific endpoint abuse — knows what normal vs attack traffic looks like
  3. Vuln chain detection — tracks multi-step attack progression per IP
  4. Honeypot triggers — zero false-positive signals
  5. Rate/brute-force detection — statistical
  6. Session correlation — groups requests by IP to detect recon patterns

NO LLM is used here. This is all traditional detection to keep costs at zero.
"""

from __future__ import annotations

import logging
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from harness.types import SecurityEvent, Severity

logger = logging.getLogger(__name__)


# ── Generic attack signatures ─────────────────────────────────────

GENERIC_PATTERNS: list[tuple[str, re.Pattern, Severity]] = [
    (
        "sql_injection",
        re.compile(
            r"""(?i)('|\%27)\s*(OR|AND|UNION|SELECT|INSERT|UPDATE|DELETE|DROP|--|;|/\*|\*/|xp_|exec|SLEEP|BENCHMARK)""",
        ),
        Severity.HIGH,
    ),
    (
        "xss_attempt",
        re.compile(r"""(?i)(<script|javascript:|on\w+\s*=|<img\s+.*?onerror)"""),
        Severity.HIGH,
    ),
    (
        "path_traversal",
        re.compile(r"""(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.%2e/|%2e\./)""", re.IGNORECASE),
        Severity.HIGH,
    ),
    (
        "command_injection",
        re.compile(r"""(?i)(;\s*(ls|cat|id|whoami|wget|curl|nc|bash|sh)\b|\|\s*\w|`[^`]+`)"""),
        Severity.CRITICAL,
    ),
    (
        "nosql_injection",
        re.compile(r"""(\$where|\$regex|\$gt|\$lt|\$ne|\$in|\$nin|\$or|\$and)"""),
        Severity.HIGH,
    ),
    (
        "prototype_pollution",
        re.compile(r"""(__proto__|constructor\[|prototype\[)"""),
        Severity.CRITICAL,
    ),
]


# ── crAPI-specific endpoint profiles ──────────────────────────────
# Maps endpoints to what "normal" looks like vs what "attack" looks like.
# The Watcher uses these to classify traffic without an LLM.

@dataclass
class EndpointProfile:
    """Defines normal vs suspicious behavior for a specific endpoint."""
    path_pattern: re.Pattern
    normal_methods: set[str]          # expected HTTP methods
    normal_rate_per_min: int          # typical requests/min from one IP
    suspicious_signals: list[str]     # what makes a request suspicious
    severity: Severity = Severity.MEDIUM
    attack_type: str = ""
    is_honeypot: bool = False


ENDPOINT_PROFILES: list[EndpointProfile] = [
    # ── Honeypots (zero false-positive) ───────────────────────────
    EndpointProfile(
        path_pattern=re.compile(r"^/(\.env|\.git|wp-admin|phpinfo|admin/debug|api/v1/internal)"),
        normal_methods=set(),  # no normal user hits these
        normal_rate_per_min=0,
        suspicious_signals=["any_access"],
        severity=Severity.HIGH,
        attack_type="honeypot_trigger",
        is_honeypot=True,
    ),

    # ── crAPI auth endpoints ──────────────────────────────────────
    EndpointProfile(
        path_pattern=re.compile(r"^/api/auth/login"),
        normal_methods={"POST"},
        normal_rate_per_min=3,
        suspicious_signals=["rate_exceeded", "sequential_failures"],
        severity=Severity.MEDIUM,
        attack_type="brute_force_login",
    ),
    EndpointProfile(
        path_pattern=re.compile(r"^/api/auth/signup"),
        normal_methods={"POST"},
        normal_rate_per_min=2,
        suspicious_signals=["rate_exceeded", "mass_registration"],
        severity=Severity.MEDIUM,
        attack_type="mass_registration",
    ),
    EndpointProfile(
        path_pattern=re.compile(r"^/api/auth/forget-password"),
        normal_methods={"POST"},
        normal_rate_per_min=2,
        suspicious_signals=["rate_exceeded", "different_emails"],
        severity=Severity.HIGH,
        attack_type="password_reset_abuse",
    ),

    # ── crAPI BOLA-vulnerable endpoints (challenges 1-2) ──────────
    EndpointProfile(
        path_pattern=re.compile(r"^/api/v2/vehicle/[0-9a-f-]+/location"),
        normal_methods={"GET"},
        normal_rate_per_min=5,
        suspicious_signals=["different_vehicle_ids", "rate_exceeded"],
        severity=Severity.HIGH,
        attack_type="bola_vehicle_location",
    ),
    EndpointProfile(
        path_pattern=re.compile(r"^/api/v2/mechanic/mechanic_report"),
        normal_methods={"GET"},
        normal_rate_per_min=3,
        suspicious_signals=["sequential_report_ids", "rate_exceeded"],
        severity=Severity.HIGH,
        attack_type="bola_mechanic_reports",
    ),

    # ── crAPI privilege escalation (challenge 3) ──────────────────
    EndpointProfile(
        path_pattern=re.compile(r"^/api/auth/v[23]/check-otp"),
        normal_methods={"POST"},
        normal_rate_per_min=3,
        suspicious_signals=["rate_exceeded"],
        severity=Severity.CRITICAL,
        attack_type="otp_brute_force",
    ),

    # ── crAPI data exposure (challenges 4-5) ──────────────────────
    EndpointProfile(
        path_pattern=re.compile(r"^/api/v2/user/videos"),
        normal_methods={"GET", "POST"},
        normal_rate_per_min=5,
        suspicious_signals=["rate_exceeded", "unusual_query_params"],
        severity=Severity.MEDIUM,
        attack_type="video_data_leak",
    ),

    # ── crAPI DoS (challenge 6) ───────────────────────────────────
    EndpointProfile(
        path_pattern=re.compile(r"^/api/v2/merchant/contact_mechanic"),
        normal_methods={"POST"},
        normal_rate_per_min=2,
        suspicious_signals=["rate_exceeded", "internal_url_in_body"],
        severity=Severity.HIGH,
        attack_type="dos_or_ssrf_mechanic",
    ),

    # ── crAPI coupon injection (challenges 12-13) ─────────────────
    EndpointProfile(
        path_pattern=re.compile(r"^/api/v2/coupon/validate-coupon"),
        normal_methods={"POST"},
        normal_rate_per_min=3,
        suspicious_signals=["rate_exceeded", "injection_in_body"],
        severity=Severity.HIGH,
        attack_type="coupon_injection",
    ),

    # ── crAPI chatbot (challenges 16-18) ──────────────────────────
    EndpointProfile(
        path_pattern=re.compile(r"^/api/v2/chatbot/"),
        normal_methods={"GET", "POST"},
        normal_rate_per_min=10,
        suspicious_signals=["rate_exceeded", "prompt_injection_keywords"],
        severity=Severity.MEDIUM,
        attack_type="chatbot_abuse",
    ),

    # ── crAPI JWT/auth endpoints ──────────────────────────────────
    EndpointProfile(
        path_pattern=re.compile(r"^/api/v2/user/dashboard"),
        normal_methods={"GET"},
        normal_rate_per_min=10,
        suspicious_signals=["no_auth_header", "malformed_jwt"],
        severity=Severity.MEDIUM,
        attack_type="unauthorized_access",
    ),

    # ── Management dashboard (admin JWT required) ──────────────────
    EndpointProfile(
        path_pattern=re.compile(r"^/workshop/api/management/dashboard"),
        normal_methods={"GET"},
        normal_rate_per_min=3,
        suspicious_signals=["no_auth_header", "malformed_jwt"],
        severity=Severity.HIGH,
        attack_type="admin_dashboard_access",
    ),

    # ── Management keys (API key required) ────────────────────────
    EndpointProfile(
        path_pattern=re.compile(r"^/workshop/api/management/keys"),
        normal_methods={"GET"},
        normal_rate_per_min=3,
        suspicious_signals=["any_access"],
        severity=Severity.HIGH,
        attack_type="api_key_access",
    ),
]


# ── Rate & session tracking ───────────────────────────────────────

@dataclass
class RateTracker:
    """Tracks request rates per IP to detect brute-force / DDoS."""
    window_seconds: int = 10
    threshold: int = 15
    _counts: dict[str, list[float]] = field(default_factory=lambda: defaultdict(list))

    def record(self, ip: str) -> bool:
        now = time.time()
        cutoff = now - self.window_seconds
        self._counts[ip] = [t for t in self._counts[ip] if t > cutoff]
        self._counts[ip].append(now)
        return len(self._counts[ip]) > self.threshold


@dataclass
class SessionTracker:
    """Tracks per-IP request patterns for session-level analysis."""
    window_seconds: int = 300  # 5-minute window
    not_found_threshold: int = 15  # N 404s in a window = probing
    _sessions: dict[str, list[dict[str, Any]]] = field(
        default_factory=lambda: defaultdict(list)
    )

    def record(self, ip: str, path: str, method: str, status: int) -> None:
        now = time.time()
        cutoff = now - self.window_seconds
        self._sessions[ip] = [
            r for r in self._sessions[ip] if r["time"] > cutoff
        ]
        self._sessions[ip].append({
            "time": now, "path": path, "method": method, "status": status,
        })

    def get_session(self, ip: str) -> list[dict[str, Any]]:
        return self._sessions.get(ip, [])

    def detect_sequential_ids(self, ip: str, path_prefix: str) -> bool:
        """Detect sequential numeric ID enumeration (IDOR signal)."""
        session = self.get_session(ip)
        ids = []
        for req in session:
            path = req["path"]
            if path.startswith(path_prefix):
                suffix = path[len(path_prefix):].strip("/").split("?")[0]
                if suffix.isdigit():
                    ids.append(int(suffix))
        if len(ids) >= 10:
            sorted_ids = sorted(ids)
            sequential = sum(
                1 for i in range(1, len(sorted_ids))
                if sorted_ids[i] - sorted_ids[i - 1] == 1
            )
            return sequential >= 8
        return False

    def detect_any_sequential_ids(self, ip: str) -> str | None:
        """Auto-detect sequential ID enumeration on ANY path pattern.
        Returns the path prefix if found, None otherwise."""
        session = self.get_session(ip)
        # Group paths by their "base" (everything before the last numeric segment)
        from collections import defaultdict as dd
        path_ids: dict[str, list[int]] = dd(list)
        for req in session:
            path = req["path"].split("?")[0].rstrip("/")
            parts = path.rsplit("/", 1)
            if len(parts) == 2 and parts[1].isdigit():
                path_ids[parts[0] + "/"].append(int(parts[1]))

        for prefix, ids in path_ids.items():
            if len(ids) >= 10:
                sorted_ids = sorted(set(ids))
                sequential = sum(
                    1 for i in range(1, len(sorted_ids))
                    if sorted_ids[i] - sorted_ids[i - 1] == 1
                )
                if sequential >= 8:
                    return prefix
        return None

    def detect_port_scanning(self, ip: str) -> bool:
        """Detect SSRF port scanning pattern in URL parameters."""
        session = self.get_session(ip)
        ssrf_requests = [r for r in session if "/fetch" in r["path"]]
        return len(ssrf_requests) >= 3

    def detect_not_found_probing(self, ip: str) -> tuple[bool, int, list[str]]:
        """Detect a session hitting many non-existent resources (404/not-found).
        Returns (triggered, count, sample_paths)."""
        session = self.get_session(ip)
        not_found = [r for r in session if r["status"] in (404, 405, 410)]
        if len(not_found) >= self.not_found_threshold:
            sample_paths = list(set(r["path"] for r in not_found))[:10]
            return True, len(not_found), sample_paths
        return False, 0, []

    def detect_multi_resource_access(self, ip: str, threshold: int = 10) -> list[dict]:
        """Detect one IP accessing many DIFFERENT resource IDs on the same endpoint.
        A normal user accesses their own resource; an attacker accesses many.
        Works for UUIDs, numeric IDs, or any varying path suffix.
        Returns list of {prefix, unique_ids, count} for each suspicious pattern."""
        import re as _re
        session = self.get_session(ip)

        # Group requests by endpoint "shape" — replace the last path segment
        # (the resource ID) with a placeholder to find the base pattern
        # e.g. /api/v2/vehicle/abc-123/location → /api/v2/vehicle/*/location
        from collections import defaultdict as dd
        endpoint_ids: dict[str, set[str]] = dd(set)

        for req in session:
            path = req["path"].split("?")[0]
            parts = path.strip("/").split("/")
            if len(parts) < 2:
                continue

            # Try to find which segment is the "resource ID"
            # Heuristic: it's a UUID, a long hex string, or a number
            for i, part in enumerate(parts):
                is_id = (
                    len(part) >= 8 and _re.match(r'^[0-9a-f-]+$', part, _re.IGNORECASE)  # UUID/hex
                    or part.isdigit()  # numeric ID
                )
                if is_id:
                    # Build the "shape" with the ID removed
                    shape_parts = parts[:i] + ["*"] + parts[i+1:]
                    shape = "/" + "/".join(shape_parts)
                    endpoint_ids[shape].add(part)
                    break

        results = []
        for shape, ids in endpoint_ids.items():
            if len(ids) >= threshold:
                results.append({
                    "endpoint_pattern": shape,
                    "unique_ids": len(ids),
                    "sample_ids": list(ids)[:5],
                })
        return results

    def detect_write_on_others_resources(self, ip: str) -> list[dict]:
        """Detect PUT/DELETE on resource endpoints (business logic abuse signal).
        A normal user rarely PUTs to order endpoints or DELETEs videos."""
        session = self.get_session(ip)
        suspicious = []
        for req in session:
            if req["method"] in ("PUT", "DELETE") and any(
                p in req["path"] for p in [
                    "/orders/", "/videos/", "/user/", "/vehicle/",
                    "/reset-password", "/change-email",
                ]
            ):
                suspicious.append(req)
        return suspicious

    def detect_recon_endpoints(self, ip: str) -> list[str]:
        """Detect access to known recon/discovery endpoints."""
        session = self.get_session(ip)
        recon_patterns = [
            ".well-known", "/docs", "/swagger", "/openapi",
            "/debug", "/config", "/status", "/health",
            "/metrics", "/actuator", "/info",
        ]
        hits = []
        for req in session:
            path_lower = req["path"].lower()
            for pattern in recon_patterns:
                if pattern in path_lower:
                    hits.append(req["path"])
                    break
        return list(set(hits))

    def get_unique_paths(self, ip: str) -> int:
        return len(set(r["path"] for r in self.get_session(ip)))

    def get_failure_rate(self, ip: str) -> float:
        session = self.get_session(ip)
        if not session:
            return 0.0
        failures = sum(1 for r in session if r["status"] >= 400)
        return failures / len(session)


# ── Log line parser ───────────────────────────────────────────────

# Matches nginx "detailed" log format
LOG_PATTERN = re.compile(
    r'^(?P<ip>[^\s]+(?:,\s*[^\s]+)*) - \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+) (?P<bytes>\d+) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)" '
    r'rt=(?P<rt>\S+)'
    r'(?:\s+auth="(?P<auth>[^"]*)")?'
    r'(?:\s+body="(?P<body>[^"]*)")?'
)


def parse_log_line(line: str) -> dict[str, Any] | None:
    m = LOG_PATTERN.match(line)
    if not m:
        return None
    d = m.groupdict()
    d["status"] = int(d["status"])
    return d


# ── Main Watcher ──────────────────────────────────────────────────

class Watcher:
    """Watches nginx access logs, crAPI service logs, and Postgres audit logs."""

    def __init__(
        self,
        log_path: Path,
        events_dir: Path,
        rules_dir: Path | None = None,
        extra_log_dir: Path | None = None,
    ):
        self.log_path = log_path
        self.events_dir = events_dir
        self.rate_tracker = RateTracker()
        self.session_tracker = SessionTracker()
        self._last_position = 0
        self._extra_patterns: list[tuple[str, re.Pattern, Severity]] = []
        if rules_dir:
            self._load_custom_rules(rules_dir)

        # Additional log sources (crAPI services, Postgres)
        self._extra_log_dir = extra_log_dir
        self._extra_positions: dict[str, int] = {}  # file path → last read position

        # Dedup: track what session-level alerts have already fired per IP
        # so they don't repeat every scan cycle. Keyed by (ip, event_type).
        # Entries expire after alert_cooldown_seconds.
        self._alerted: dict[tuple[str, str], float] = {}
        self._alert_cooldown = 120  # seconds before same alert can fire again

    def scan_new_lines(self) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []

        if not self.log_path.exists():
            return events

        with open(self.log_path, "r") as f:
            f.seek(self._last_position)
            new_lines = f.readlines()
            self._last_position = f.tell()

        for line in new_lines:
            line = line.strip()
            if not line:
                continue

            parsed = parse_log_line(line)
            if not parsed:
                # Fallback: try generic pattern matching on raw line
                events.extend(self._check_generic_patterns(line))
                continue

            ip = parsed["ip"]
            path = parsed["path"]
            method = parsed["method"]
            status = parsed["status"]

            # Track session
            self.session_tracker.record(ip, path, method, status)

            # 1. Check endpoint profiles (crAPI + vuln chain specific)
            for profile in ENDPOINT_PROFILES:
                if profile.path_pattern.search(path):
                    profile_events = self._check_endpoint_profile(
                        profile, parsed, line
                    )
                    events.extend(profile_events)
                    break  # first matching profile wins

            # 2. Check generic attack signatures in the full log line
            events.extend(self._check_generic_patterns(line, parsed))

            # 2b. Check POST body for injection patterns
            body = parsed.get("body", "") or ""
            if body and body != "-":
                events.extend(self._check_request_body(ip, path, body, line))

            # 2c. Inspect JWT tokens in Authorization header
            auth = parsed.get("auth", "") or ""
            if auth and auth != "-" and "." in auth:
                events.extend(self._inspect_jwt(ip, auth, path))

            # 3. Check global rate limiting
            if self.rate_tracker.record(ip):
                req_count = len(self.rate_tracker._counts.get(ip, []))
                # Extreme burst = CRITICAL (instant redirect)
                # Normal rate exceed = MEDIUM
                sev = Severity.CRITICAL if req_count > 50 else Severity.MEDIUM
                events.append(SecurityEvent(
                    event_type="global_rate_limit_exceeded",
                    severity=sev,
                    evidence={
                        "source_ip": ip,
                        "log_line": line[:500],
                        "requests_in_window": req_count,
                    },
                    context={
                        "unique_paths": self.session_tracker.get_unique_paths(ip),
                        "failure_rate": self.session_tracker.get_failure_rate(ip),
                    },
                ))

            # 4. Session-level analysis (cross-request correlation)
            events.extend(self._check_session_patterns(ip, path))

        # Deduplicate: one event per type per IP per scan cycle
        seen = set()
        deduped = []
        for event in events:
            key = (event.event_type, event.evidence.get("source_ip", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(event)

        # Persist
        for event in deduped:
            event.save(self.events_dir)
            logger.info(
                "Detected %s from %s [%s]",
                event.event_type,
                event.evidence.get("source_ip", "?"),
                event.severity.value,
            )

        # 5. Scan additional log sources (crAPI services, Postgres)
        # Extra log scanning (postgres audit, container logs) disabled —
        # too noisy with false positives from normal app queries.
        # The nginx access logs + shadow analyzer are the primary detection path.
        # events.extend(self._scan_extra_logs())

        # Deduplicate again after extra logs
        seen2 = set()
        final = []
        for event in deduped + [e for e in events if e not in deduped]:
            key = (event.event_type, event.evidence.get("source_ip", ""),
                   event.evidence.get("message", "")[:100])
            if key not in seen2:
                seen2.add(key)
                final.append(event)

        # Persist any new events from extra logs
        for event in final:
            if event not in deduped:
                event.save(self.events_dir)
                logger.info(
                    "Detected %s from %s [%s] (source: %s)",
                    event.event_type,
                    event.evidence.get("source_ip", "?"),
                    event.severity.value,
                    event.evidence.get("log_source", "extra"),
                )

        return final

    def _scan_extra_logs(self) -> list[SecurityEvent]:
        """Scan crAPI service logs and Postgres audit logs."""
        from harness.log_parsers import parse_line

        events = []
        if not self._extra_log_dir or not self._extra_log_dir.exists():
            return events

        for container_dir in self._extra_log_dir.iterdir():
            if not container_dir.is_dir():
                continue
            log_file = container_dir / "container.log"
            if not log_file.exists():
                continue

            source = container_dir.name
            file_key = str(log_file)

            # Read new lines
            last_pos = self._extra_positions.get(file_key, 0)
            with open(log_file, "r") as f:
                f.seek(last_pos)
                new_lines = f.readlines()
                self._extra_positions[file_key] = f.tell()

            for line in new_lines:
                line = line.strip()
                if not line:
                    continue

                parsed = parse_line(source, line)
                if not parsed:
                    continue

                # Check for security-relevant events
                new_events = self._analyze_service_log(source, parsed, line)
                events.extend(new_events)

        return events

    def _analyze_service_log(
        self, source: str, parsed: dict, raw_line: str
    ) -> list[SecurityEvent]:
        """Analyze a parsed service log entry for security events."""
        events = []

        # ── Postgres audit: detect suspicious queries ──────────────
        if source == "postgresdb":
            user = parsed.get("user", "")
            message = parsed.get("message", "")

            # Sensitive table access
            if parsed.get("sensitive_table"):
                events.append(SecurityEvent(
                    event_type="sensitive_db_query",
                    severity=Severity.HIGH,
                    evidence={
                        "log_source": "postgres",
                        "db_user": user,
                        "table": parsed["sensitive_table"],
                        "sql_operation": parsed.get("sql_operation", ""),
                        "message": message[:300],
                    },
                    context={"detection": "pgaudit"},
                ))

            # Schema enumeration
            if parsed.get("suspicious") == "schema_enumeration":
                events.append(SecurityEvent(
                    event_type="db_schema_enumeration",
                    severity=Severity.CRITICAL,
                    evidence={
                        "log_source": "postgres",
                        "db_user": user,
                        "message": message[:300],
                    },
                    context={"detection": "pgaudit"},
                ))

            # Mass data extraction (SELECT with no WHERE)
            if parsed.get("sql_operation") == "SELECT" and "where" not in message.lower():
                if any(t in message.lower() for t in ["user_login", "user_details", "credit_card"]):
                    events.append(SecurityEvent(
                        event_type="mass_data_extraction",
                        severity=Severity.CRITICAL,
                        evidence={
                            "log_source": "postgres",
                            "db_user": user,
                            "message": message[:300],
                        },
                        context={"detection": "pgaudit_select_no_where"},
                    ))

        # ── Chatbot: detect tool calls and suspicious actions ──────
        elif source == "crapi-chatbot":
            event_type = parsed.get("event_type", "")

            if event_type == "tool_call":
                events.append(SecurityEvent(
                    event_type="chatbot_tool_call",
                    severity=Severity.MEDIUM,
                    evidence={
                        "log_source": "crapi-chatbot",
                        "message": parsed.get("message", "")[:300],
                    },
                    context={"detection": "chatbot_audit"},
                ))

            # Chatbot making HTTP calls (MCP server → crAPI)
            if parsed.get("method") and parsed.get("path"):
                path = parsed["path"]
                method = parsed["method"]
                # Flag write operations from chatbot (POST/PUT/DELETE)
                if method in ("POST", "PUT", "DELETE") and path != "/chatbot/genai/ask":
                    events.append(SecurityEvent(
                        event_type="chatbot_write_action",
                        severity=Severity.HIGH,
                        evidence={
                            "log_source": "crapi-chatbot",
                            "method": method,
                            "path": path,
                            "message": parsed.get("message", "")[:300],
                        },
                        context={"detection": "chatbot_api_call"},
                    ))

        # ── crAPI services: detect internal API abuse ──────────────
        elif source in ("crapi-identity", "crapi-community", "crapi-workshop"):
            path = parsed.get("path", "")
            status = parsed.get("status", 0)
            method = parsed.get("method", "")

            # Detect API key / admin endpoint access from services
            if "apikey" in path.lower() or "management" in path.lower():
                events.append(SecurityEvent(
                    event_type="internal_admin_api_access",
                    severity=Severity.HIGH,
                    evidence={
                        "log_source": source,
                        "path": path,
                        "method": method,
                        "status": status,
                    },
                    context={"detection": "service_log"},
                ))

            # Detect mass 401/403 errors (brute-force visible at service level)
            if status in (401, 403):
                events.append(SecurityEvent(
                    event_type=f"{source}_auth_failure",
                    severity=Severity.LOW,
                    evidence={
                        "log_source": source,
                        "path": path,
                        "method": method,
                        "status": status,
                    },
                    context={"detection": "service_auth_failure"},
                ))

        return events

    def _check_endpoint_profile(
        self, profile: EndpointProfile, parsed: dict, line: str
    ) -> list[SecurityEvent]:
        """Check a request against its endpoint profile."""
        events = []
        ip = parsed["ip"]
        path = parsed["path"]
        method = parsed["method"]

        # Honeypot — any access is malicious
        if profile.is_honeypot:
            events.append(SecurityEvent(
                event_type=profile.attack_type,
                severity=profile.severity,
                evidence={
                    "source_ip": ip,
                    "path": path,
                    "method": method,
                    "log_line": line[:500],
                    "is_honeypot": True,
                },
                context={"detection": "honeypot_trigger"},
            ))
            return events

        # Wrong HTTP method
        if profile.normal_methods and method not in profile.normal_methods:
            events.append(SecurityEvent(
                event_type=f"{profile.attack_type}_unusual_method",
                severity=Severity.MEDIUM,
                evidence={
                    "source_ip": ip,
                    "path": path,
                    "method": method,
                    "expected_methods": list(profile.normal_methods),
                    "log_line": line[:500],
                },
                context={"detection": "method_mismatch"},
            ))

        # Rate exceeded for this specific endpoint
        session = self.session_tracker.get_session(ip)
        recent_hits = sum(
            1 for r in session
            if profile.path_pattern.search(r["path"])
            and r["time"] > time.time() - 60
        )
        if recent_hits > profile.normal_rate_per_min:
            events.append(SecurityEvent(
                event_type=f"{profile.attack_type}_rate_exceeded",
                severity=profile.severity,
                evidence={
                    "source_ip": ip,
                    "path": path,
                    "requests_per_min": recent_hits,
                    "normal_rate": profile.normal_rate_per_min,
                    "log_line": line[:500],
                },
                context={
                    "detection": "endpoint_rate_exceeded",
                    "failure_rate": self.session_tracker.get_failure_rate(ip),
                },
            ))

        # Auth header anomalies
        auth = parsed.get("auth", "")
        if "no_auth_header" in profile.suspicious_signals and not auth:
            events.append(SecurityEvent(
                event_type=f"{profile.attack_type}_no_auth",
                severity=Severity.MEDIUM,
                evidence={
                    "source_ip": ip,
                    "path": path,
                    "log_line": line[:500],
                },
                context={"detection": "missing_auth"},
            ))

        # JWT anomalies in auth header
        if auth and "malformed_jwt" in profile.suspicious_signals:
            if self._check_suspicious_jwt(auth):
                events.append(SecurityEvent(
                    event_type="suspicious_jwt",
                    severity=Severity.HIGH,
                    evidence={
                        "source_ip": ip,
                        "path": path,
                        "auth_header_preview": auth[:100],
                        "log_line": line[:500],
                    },
                    context={"detection": "jwt_anomaly"},
                ))

        return events

    @staticmethod
    def _check_suspicious_jwt(auth: str) -> bool:
        """Check if a JWT token looks suspicious (alg:none, very short, malformed)."""
        import base64
        token = auth.replace("Bearer ", "").strip()
        parts = token.split(".")
        if len(parts) < 2:
            return True  # not a valid JWT structure
        try:
            # Pad and decode header
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header = base64.urlsafe_b64decode(header_b64).decode()
            # Check for alg:none or empty signature
            if '"none"' in header.lower() or (len(parts) == 3 and parts[2] == ""):
                return True
        except Exception:
            return True  # can't decode = suspicious
        return False

    def _check_generic_patterns(
        self, line: str, parsed: dict | None = None
    ) -> list[SecurityEvent]:
        """Check generic attack signatures (SQLi, XSS, etc.).
        All matching rules fire — no early break — so honeypot-specific
        rules are always recorded alongside generic ones."""
        events = []
        ip = parsed["ip"] if parsed else line.split(" ")[0]
        matched_names = set()

        all_patterns = GENERIC_PATTERNS + self._extra_patterns
        for name, pattern, severity in all_patterns:
            if name not in matched_names and pattern.search(line):
                events.append(SecurityEvent(
                    event_type=name,
                    severity=severity,
                    evidence={
                        "source_ip": ip,
                        "log_line": line[:500],
                        "matched_pattern": name,
                    },
                    context={
                        "detection": "generic_signature",
                        "session_failure_rate": (
                            self.session_tracker.get_failure_rate(ip) if parsed else 0
                        ),
                    },
                ))
                matched_names.add(name)
        return events

    def _check_request_body(
        self, ip: str, path: str, body: str, line: str
    ) -> list[SecurityEvent]:
        """Check POST/PUT request bodies for injection and abuse patterns."""
        events = []
        body_lower = body.lower()

        # SQL injection in body
        sql_patterns = ["' or ", "union select", "' and ", "1=1", "drop table", "sleep(", "benchmark("]
        for pattern in sql_patterns:
            if pattern in body_lower:
                events.append(SecurityEvent(
                    event_type="sql_injection_in_body",
                    severity=Severity.CRITICAL,
                    evidence={
                        "source_ip": ip,
                        "path": path,
                        "matched_pattern": pattern,
                        "body_preview": body[:200],
                    },
                    context={"detection": "body_inspection"},
                ))
                break

        # NoSQL injection in body
        nosql_patterns = ["$ne", "$gt", "$lt", "$regex", "$where", "$in", "$nin"]
        for pattern in nosql_patterns:
            if pattern in body:  # case-sensitive for MongoDB operators
                events.append(SecurityEvent(
                    event_type="nosql_injection_in_body",
                    severity=Severity.HIGH,
                    evidence={
                        "source_ip": ip,
                        "path": path,
                        "matched_pattern": pattern,
                        "body_preview": body[:200],
                    },
                    context={"detection": "body_inspection"},
                ))
                break

        # Negative quantity / price manipulation (business logic)
        import re as _re
        negative_num = _re.search(r'"(?:quantity|amount|price|credit)":\s*-\d+', body)
        if negative_num:
            events.append(SecurityEvent(
                event_type="negative_value_manipulation",
                severity=Severity.HIGH,
                evidence={
                    "source_ip": ip,
                    "path": path,
                    "matched": negative_num.group(),
                    "body_preview": body[:200],
                },
                context={"detection": "body_inspection_business_logic"},
            ))

        # Prompt injection keywords in chatbot requests
        if "/chatbot" in path:
            prompt_injection_keywords = [
                "ignore previous", "ignore all", "debug mode",
                "system prompt", "you are now", "forget your instructions",
                "list all", "show me all", "dump", "enumerate",
            ]
            for kw in prompt_injection_keywords:
                if kw in body_lower:
                    events.append(SecurityEvent(
                        event_type="chatbot_prompt_injection",
                        severity=Severity.HIGH,
                        evidence={
                            "source_ip": ip,
                            "path": path,
                            "matched_keyword": kw,
                            "body_preview": body[:200],
                        },
                        context={"detection": "body_inspection_chatbot"},
                    ))
                    break

        return events

    def _should_alert(self, ip: str, event_type: str) -> bool:
        """Check if this alert should fire (dedup with cooldown)."""
        key = (ip, event_type)
        now = time.time()
        last_alert = self._alerted.get(key, 0)
        if now - last_alert < self._alert_cooldown:
            return False  # still in cooldown
        self._alerted[key] = now
        return True

    def _check_session_patterns(self, ip: str, _current_path: str = "") -> list[SecurityEvent]:
        """Cross-request analysis: detect multi-step attack patterns.
        Each detection fires ONCE per IP per cooldown window."""
        events = []

        # ── 1. Generic sequential ID enumeration on ANY path ──────
        seq_prefix = self.session_tracker.detect_any_sequential_ids(ip)
        if seq_prefix and self._should_alert(ip, f"idor_enum:{seq_prefix}"):
            events.append(SecurityEvent(
                event_type="idor_sequential_enumeration",
                severity=Severity.HIGH,
                evidence={
                    "source_ip": ip,
                    "path_prefix": seq_prefix,
                },
                context={
                    "detection": "session_correlation",
                    "session_length": len(self.session_tracker.get_session(ip)),
                },
            ))

        # ── 2. SSRF port scanning ────────────────────────────────
        if self.session_tracker.detect_port_scanning(ip) and self._should_alert(ip, "ssrf_port_scan"):
            events.append(SecurityEvent(
                event_type="ssrf_port_scanning",
                severity=Severity.CRITICAL,
                evidence={"source_ip": ip},
                context={
                    "detection": "session_correlation",
                    "ssrf_requests": len([
                        r for r in self.session_tracker.get_session(ip)
                        if "/fetch" in r["path"]
                    ]),
                },
            ))

        # ── 3. Not-found probing (the generalized rule) ──────────
        triggered, count, sample_paths = self.session_tracker.detect_not_found_probing(ip)
        if triggered and self._should_alert(ip, "not_found_probing"):
            events.append(SecurityEvent(
                event_type="not_found_probing",
                severity=Severity.HIGH,
                evidence={
                    "source_ip": ip,
                    "not_found_count": count,
                    "sample_paths": sample_paths,
                },
                context={
                    "detection": "session_correlation",
                    "session_length": len(self.session_tracker.get_session(ip)),
                    "note": "Session has hit many non-existent resources — likely enumeration or directory scanning",
                },
            ))

        # ── 4. Business logic abuse (PUT/DELETE on resource endpoints) ──
        write_abuse = self.session_tracker.detect_write_on_others_resources(ip)
        if len(write_abuse) >= 2 and self._should_alert(ip, "write_abuse"):
            events.append(SecurityEvent(
                event_type="suspicious_write_operations",
                severity=Severity.HIGH,
                evidence={
                    "source_ip": ip,
                    "operations": [
                        {"method": r["method"], "path": r["path"]}
                        for r in write_abuse[:5]
                    ],
                },
                context={
                    "detection": "session_correlation",
                    "note": "Multiple PUT/DELETE on resource endpoints — possible data manipulation",
                },
            ))

        # ── 5. Recon endpoint access ─────────────────────────────
        recon_hits = self.session_tracker.detect_recon_endpoints(ip)
        if len(recon_hits) >= 2 and self._should_alert(ip, "recon_scan"):
            events.append(SecurityEvent(
                event_type="recon_endpoint_scan",
                severity=Severity.MEDIUM,
                evidence={
                    "source_ip": ip,
                    "recon_paths": recon_hits,
                },
                context={
                    "detection": "session_correlation",
                    "note": "Session accessed multiple discovery/debug endpoints",
                },
            ))

        # ── 6. Multi-resource access (BOLA on UUIDs, etc.) ────────
        multi_access = self.session_tracker.detect_multi_resource_access(ip)
        for hit in multi_access:
            alert_key = f"multi_resource:{hit['endpoint_pattern']}"
            if self._should_alert(ip, alert_key):
                events.append(SecurityEvent(
                    event_type="multi_resource_enumeration",
                    severity=Severity.HIGH,
                    evidence={
                        "source_ip": ip,
                        "endpoint_pattern": hit["endpoint_pattern"],
                        "unique_resource_ids": hit["unique_ids"],
                        "sample_ids": hit["sample_ids"],
                    },
                    context={
                        "detection": "session_correlation",
                        "note": (
                            f"One IP accessed {hit['unique_ids']} different resources "
                            f"on {hit['endpoint_pattern']} — normal users access 1-2"
                        ),
                    },
                ))

        # ── 7. High failure rate ─────────────────────────────────
        failure_rate = self.session_tracker.get_failure_rate(ip)
        session_len = len(self.session_tracker.get_session(ip))
        if session_len >= 10 and failure_rate > 0.6 and self._should_alert(ip, "high_failure"):
            events.append(SecurityEvent(
                event_type="high_failure_rate_session",
                severity=Severity.MEDIUM,
                evidence={
                    "source_ip": ip,
                    "failure_rate": round(failure_rate, 2),
                    "session_length": session_len,
                },
                context={"detection": "session_correlation"},
            ))

        return events

    def _inspect_jwt(self, ip: str, auth: str, path: str) -> list[SecurityEvent]:
        """Decode JWT header+payload (without verifying signature) to detect:
        1. Algorithm downgrade (HS256 when server uses RS256)
        2. alg:none attack
        3. Role escalation (admin claim from non-admin session)
        """
        import base64
        import json as _json

        events = []
        token = auth.replace("Bearer ", "").strip()
        if not token:
            return events

        parts = token.split(".")
        if len(parts) != 3:
            if self._should_alert(ip, "malformed_jwt"):
                events.append(SecurityEvent(
                    event_type="malformed_jwt",
                    severity=Severity.HIGH,
                    evidence={"source_ip": ip, "path": path, "token_preview": token[:50]},
                    context={"detection": "jwt_inspection"},
                ))
            return events

        try:
            # Decode header
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header = _json.loads(base64.b64decode(header_b64).decode("utf-8", errors="ignore"))

            # Decode payload
            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload = _json.loads(base64.b64decode(payload_b64).decode("utf-8", errors="ignore"))
        except Exception:
            return events

        alg = header.get("alg", "").upper()
        role = payload.get("role", "")
        sub = payload.get("sub", "")

        # 1. Algorithm downgrade: HS256 when server normally uses RS256
        #    crAPI identity uses RS256; our vuln chain uses HS256.
        #    If a token on a crAPI path uses HS256, or a token claims
        #    "admin" role with HS256, that's suspicious.
        if alg == "NONE":
            if self._should_alert(ip, "jwt_alg_none"):
                events.append(SecurityEvent(
                    event_type="jwt_algorithm_none",
                    severity=Severity.CRITICAL,
                    evidence={
                        "source_ip": ip,
                        "path": path,
                        "algorithm": alg,
                        "subject": sub,
                    },
                    context={"detection": "jwt_inspection"},
                ))

        # 2. Algorithm confusion: HS256 on a path that expects RS256
        #    crAPI identity service signs with RS256. If we see HS256
        #    on identity/workshop/community paths, it's likely forged.
        if alg == "HS256" and any(p in path for p in ["/identity/", "/workshop/", "/community/"]):
            if self._should_alert(ip, "jwt_alg_confusion"):
                events.append(SecurityEvent(
                    event_type="jwt_algorithm_confusion",
                    severity=Severity.CRITICAL,
                    evidence={
                        "source_ip": ip,
                        "path": path,
                        "algorithm": alg,
                        "expected_algorithm": "RS256",
                        "subject": sub,
                        "role": role,
                    },
                    context={
                        "detection": "jwt_inspection",
                        "note": "JWT uses HS256 on an endpoint that expects RS256 — likely algorithm confusion attack",
                    },
                ))

        # 3. Admin role escalation: JWT claims admin but this IP
        #    previously authenticated as a non-admin user
        if role == "admin" and self._should_alert(ip, f"jwt_admin_claim:{sub}"):
            # Check if this IP had a recent JWKS lookup (recon signal)
            session = self.session_tracker.get_session(ip)
            had_jwks_access = any(".well-known" in r["path"] for r in session)
            if had_jwks_access:
                events.append(SecurityEvent(
                    event_type="jwt_forged_admin_after_recon",
                    severity=Severity.CRITICAL,
                    evidence={
                        "source_ip": ip,
                        "path": path,
                        "algorithm": alg,
                        "claimed_role": role,
                        "subject": sub,
                        "jwks_accessed": True,
                    },
                    context={
                        "detection": "jwt_inspection",
                        "note": "IP accessed JWKS endpoint then presented admin JWT — strong indicator of JWT forgery",
                    },
                ))

        return events

    def _load_custom_rules(self, rules_dir: Path) -> None:
        for rule_file in rules_dir.glob("*.yaml"):
            try:
                data = yaml.safe_load(rule_file.read_text())
                for rule in data.get("rules", []):
                    self._extra_patterns.append((
                        rule["name"],
                        re.compile(rule["pattern"], re.IGNORECASE),
                        Severity(rule.get("severity", "medium")),
                    ))
                logger.info("Loaded %d rules from %s",
                            len(data.get("rules", [])), rule_file.name)
            except Exception as e:
                logger.error("Failed to load rule file %s: %s", rule_file, e)
