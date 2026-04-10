"""Chain Completion Detector — identifies when an exploit chain succeeds.

Instead of triggering the Fixer on every suspicious event, we watch for
SEQUENCES of events that indicate a full exploit was completed. The Fixer
only acts when real damage was done (in the shadow environment).

Each chain pattern defines:
  - Required events (must all be present in the session)
  - A completion signal (the final event that confirms success)
  - Severity (determines Fixer priority)

Observable signals the Watcher/Analyzer can detect:
  - Cross-user resource access (token A accessed resource belonging to user B)
  - Password change followed by login from a new session
  - Negative balance after order manipulation
  - 500 error from injection payload
  - Admin role in JWT after JWKS endpoint access
  - Internal service data in SSRF responses
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ChainPattern:
    """Defines a detectable exploit chain."""
    name: str
    description: str
    # Event types that must appear in the session (order doesn't matter)
    required_events: list[str]
    # Minimum number of required events that must match
    min_matches: int = 0  # 0 = all required
    # How to detect the chain completed (not just attempted)
    completion_signals: list[str]
    severity: str = "high"
    # What the Fixer should fix
    fix_hint: str = ""


# ── Known exploit chain patterns ──────────────────────────────────

CHAIN_PATTERNS = [
    ChainPattern(
        name="bola_data_access",
        description="Attacker accessed another user's data via BOLA",
        required_events=[
            "multi_resource_enumeration",  # accessed multiple different resource IDs
        ],
        completion_signals=[
            "multi_resource_enumeration",  # accessing 3+ resources IS the exploit
        ],
        severity="high",
        fix_hint="Add authorization check: verify the requesting user owns the resource",
    ),
    ChainPattern(
        name="idor_account_takeover",
        description="Attacker enumerated users, found admin, reset password, logged in",
        required_events=[
            "idor_sequential_enumeration",  # scanned user IDs
            "not_found_probing",            # hit non-existent IDs too
        ],
        completion_signals=[
            "idor_sequential_enumeration",  # the enumeration itself is the breach
        ],
        severity="critical",
        fix_hint="Add authorization to user profile endpoint; don't expose reset tokens",
    ),
    ChainPattern(
        name="otp_bruteforce_takeover",
        description="Attacker brute-forced OTP to reset another user's password",
        required_events=[
            "global_rate_limit_exceeded",   # many rapid requests
        ],
        # Completion: the OTP endpoint was hit many times from one session
        # We detect this via rate exceeded on auth/check-otp paths
        completion_signals=[
            "global_rate_limit_exceeded",
        ],
        min_matches=1,
        severity="critical",
        fix_hint="Add rate limiting to OTP verification endpoint; lock after N failed attempts",
    ),
    ChainPattern(
        name="jwt_forgery",
        description="Attacker accessed JWKS, forged JWT with wrong algorithm, got admin access",
        required_events=[
            "recon_endpoint_scan",           # accessed .well-known/jwks.json
            "jwt_forged_admin_after_recon",   # presented admin JWT after JWKS access
        ],
        completion_signals=[
            "jwt_forged_admin_after_recon",
        ],
        severity="critical",
        fix_hint="Remove HS256 from accepted algorithms; only accept RS256 with proper key verification",
    ),
    ChainPattern(
        name="ssrf_internal_access",
        description="Attacker used SSRF to access internal services",
        required_events=[
            "ssrf_port_scanning",           # probed multiple internal hosts
        ],
        completion_signals=[
            "ssrf_port_scanning",
        ],
        severity="critical",
        fix_hint="Add URL allowlist to the fetch endpoint; block internal/private IP ranges",
    ),
    ChainPattern(
        name="refund_manipulation",
        description="Attacker manipulated order quantity to negative value",
        required_events=[
            "suspicious_write_operations",   # PUT on order endpoints
            "negative_value_manipulation",   # negative quantity in body
        ],
        completion_signals=[
            "negative_value_manipulation",
        ],
        severity="high",
        fix_hint="Validate quantity is positive in the order update endpoint",
    ),
    ChainPattern(
        name="sql_injection",
        description="Attacker injected SQL via coupon or other input",
        required_events=[
            "sql_injection_in_body",
        ],
        completion_signals=[
            "sql_injection_in_body",        # injection in body that caused 500 = success
        ],
        severity="critical",
        fix_hint="Use parameterized queries for coupon validation; never interpolate user input into SQL",
    ),
    ChainPattern(
        name="nosql_injection",
        description="Attacker injected NoSQL operators",
        required_events=[
            "nosql_injection_in_body",
        ],
        completion_signals=[
            "nosql_injection_in_body",
        ],
        severity="high",
        fix_hint="Validate coupon_code is a string, not an object; reject MongoDB operators",
    ),
    ChainPattern(
        name="honeypot_credential_usage",
        description="Attacker found and used honeypot credentials/tokens",
        required_events=[
            "honeypot_token_usage",
        ],
        completion_signals=[
            "honeypot_token_usage",
        ],
        severity="high",
        fix_hint="N/A — honeypot worked as intended; attacker is being tracked",
    ),
    ChainPattern(
        name="api_key_exfiltration",
        description="Attacker found debug endpoint and brute-forced the API key",
        required_events=[
            "debug_endpoint_access",
        ],
        completion_signals=[
            "debug_endpoint_access",
        ],
        severity="critical",
        fix_hint="Remove debug endpoints from production; add authentication to config endpoints",
    ),
    ChainPattern(
        name="chatbot_data_leak",
        description="Chatbot was social-engineered into revealing user data or taking actions",
        required_events=[
            "chatbot_prompt_injection",
        ],
        completion_signals=[
            "chatbot_prompt_injection",
        ],
        severity="high",
        fix_hint="Add output filtering to chatbot; restrict which API actions it can perform",
    ),
]


@dataclass
class SessionEventLog:
    """Tracks events per session for chain detection."""
    events: list[dict] = field(default_factory=list)
    detected_chains: set[str] = field(default_factory=set)
    last_event_time: float = 0


class ChainDetector:
    """Detects when exploit chains are completed in a session."""

    def __init__(self):
        # session_id → SessionEventLog
        self._sessions: dict[str, SessionEventLog] = {}
        self._ttl = 3600  # session events expire after 1 hour

    def add_event(self, session_id: str, event_type: str, severity: str,
                  evidence: dict) -> list[ChainPattern]:
        """Record an event and check if any chains are now complete.
        Returns list of newly completed chains."""
        now = time.time()

        if session_id not in self._sessions:
            self._sessions[session_id] = SessionEventLog()

        session = self._sessions[session_id]
        session.events.append({
            "type": event_type,
            "severity": severity,
            "time": now,
            "evidence": evidence,
        })
        session.last_event_time = now

        # Prune old sessions
        self._prune()

        # Check chain patterns
        completed = []
        session_event_types = {e["type"] for e in session.events}

        for pattern in CHAIN_PATTERNS:
            if pattern.name in session.detected_chains:
                continue  # already detected this chain for this session

            # Check required events
            min_matches = pattern.min_matches or len(pattern.required_events)
            matches = sum(1 for req in pattern.required_events if req in session_event_types)
            if matches < min_matches:
                continue

            # Check completion signal
            if any(sig in session_event_types for sig in pattern.completion_signals):
                session.detected_chains.add(pattern.name)
                completed.append(pattern)
                logger.warning(
                    "CHAIN COMPLETE: %s for session %s — %s",
                    pattern.name, session_id[:20], pattern.description,
                )

        return completed

    def get_session_status(self, session_id: str) -> dict:
        session = self._sessions.get(session_id)
        if not session:
            return {"events": 0, "chains_detected": []}
        return {
            "events": len(session.events),
            "event_types": list({e["type"] for e in session.events}),
            "chains_detected": list(session.detected_chains),
        }

    def _prune(self):
        """Remove expired sessions."""
        now = time.time()
        expired = [
            sid for sid, s in self._sessions.items()
            if now - s.last_event_time > self._ttl
        ]
        for sid in expired:
            del self._sessions[sid]
