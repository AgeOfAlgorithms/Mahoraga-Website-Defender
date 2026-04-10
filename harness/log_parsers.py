"""Log parsers for different sources.

Each parser takes a raw log line and returns a structured dict
that the Watcher can analyze, or None if the line isn't relevant.
"""

from __future__ import annotations

import re
from typing import Any


# ── crAPI Identity (Spring Boot / Java) ───────────────────────────
# Format: timestamp level [thread] logger - message
# Example: 2026-04-09 04:14:04.123 INFO [http-nio-8080-exec-1] c.c.handler - POST /identity/api/auth/login 200

SPRING_LOG_PATTERN = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[\.,]\d+)\s+"
    r"(?P<level>\w+)\s+"
    r"(?:\[(?P<thread>[^\]]+)\])?\s*"
    r"(?P<logger>\S+)\s*[-:]\s*"
    r"(?P<message>.*)"
)

# crAPI identity logs HTTP requests like: "POST /identity/api/auth/login 200"
HTTP_IN_MESSAGE = re.compile(
    r"(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+"
    r"(?P<path>/\S+)\s+"
    r"(?P<status>\d{3})"
)


def parse_crapi_identity(line: str) -> dict[str, Any] | None:
    m = SPRING_LOG_PATTERN.match(line)
    if not m:
        return None

    result = {
        "source": "crapi-identity",
        "timestamp": m.group("timestamp"),
        "level": m.group("level"),
        "message": m.group("message"),
    }

    # Extract HTTP request details if present
    http_match = HTTP_IN_MESSAGE.search(m.group("message"))
    if http_match:
        result["method"] = http_match.group("method")
        result["path"] = http_match.group("path")
        result["status"] = int(http_match.group("status"))

    return result


# ── crAPI Community (Go) ──────────────────────────────────────────
# Go services typically log JSON or structured text
# Example: {"level":"info","ts":"2026-04-09T04:14:04.123Z","msg":"request","method":"GET","path":"/community/api/v2/community/posts/recent","status":200}

import json

def parse_crapi_community(line: str) -> dict[str, Any] | None:
    line = line.strip()
    if not line:
        return None

    # Try JSON format first (Go structured logging)
    if line.startswith("{"):
        try:
            data = json.loads(line)
            return {
                "source": "crapi-community",
                "timestamp": data.get("ts", data.get("time", "")),
                "level": data.get("level", "info"),
                "message": data.get("msg", ""),
                "method": data.get("method", ""),
                "path": data.get("path", data.get("uri", "")),
                "status": data.get("status", data.get("status_code", 0)),
                "ip": data.get("ip", data.get("remote_addr", "")),
            }
        except json.JSONDecodeError:
            pass

    # Fallback: plain text with HTTP info
    http_match = HTTP_IN_MESSAGE.search(line)
    if http_match:
        return {
            "source": "crapi-community",
            "message": line,
            "method": http_match.group("method"),
            "path": http_match.group("path"),
            "status": int(http_match.group("status")),
        }

    return None


# ── crAPI Workshop (Django / Python) ──────────────────────────────
# Django logs via gunicorn: "POST /workshop/api/shop/orders 200 OK"

DJANGO_LOG_PATTERN = re.compile(
    r"(?P<ip>\d+\.\d+\.\d+\.\d+)?\s*-?\s*"
    r"\[?(?P<timestamp>[^\]]*)\]?\s*"
    r'"?(?P<method>GET|POST|PUT|DELETE|PATCH)\s+(?P<path>/\S+)\s+HTTP/\S+"?\s+'
    r"(?P<status>\d{3})"
)


def parse_crapi_workshop(line: str) -> dict[str, Any] | None:
    line = line.strip()
    if not line:
        return None

    m = DJANGO_LOG_PATTERN.search(line)
    if m:
        return {
            "source": "crapi-workshop",
            "ip": m.group("ip") or "",
            "timestamp": m.group("timestamp"),
            "method": m.group("method"),
            "path": m.group("path"),
            "status": int(m.group("status")),
            "message": line,
        }

    # Django also logs plain messages
    if any(kw in line.lower() for kw in ["error", "warning", "exception", "traceback"]):
        return {
            "source": "crapi-workshop",
            "level": "error",
            "message": line,
        }

    return None


# ── crAPI Chatbot (Python / Quart) ────────────────────────────────
# The chatbot prints debug info like: "messages [...]", "Response {...}"

CHATBOT_ACTION_PATTERN = re.compile(
    r"(?:INFO|DEBUG|WARNING|ERROR)\s*[-:]\s*"
    r"(?P<message>.*)"
)


def parse_crapi_chatbot(line: str) -> dict[str, Any] | None:
    line = line.strip()
    if not line:
        return None

    # Detect MCP tool calls (chatbot calling crAPI's API)
    if "tool" in line.lower() or "function" in line.lower() or "mcp" in line.lower():
        return {
            "source": "crapi-chatbot",
            "level": "info",
            "event_type": "tool_call",
            "message": line[:500],
        }

    # Detect HTTP requests from the MCP server
    http_match = HTTP_IN_MESSAGE.search(line)
    if http_match:
        return {
            "source": "crapi-chatbot",
            "method": http_match.group("method"),
            "path": http_match.group("path"),
            "status": int(http_match.group("status")),
            "message": line[:500],
        }

    # Detect chat messages (the actual user queries)
    if line.startswith("messages") or line.startswith("Response") or line.startswith("Reply"):
        return {
            "source": "crapi-chatbot",
            "event_type": "chat_message",
            "message": line[:500],
        }

    return None


# ── PostgreSQL / pgaudit ──────────────────────────────────────────
# pgaudit format: timestamp [pid] user=X db=Y LOG: AUDIT: SESSION,...,READ,SELECT,...
# Standard Postgres: timestamp [pid] user=X db=Y LOG: statement: SELECT ...

PGAUDIT_PATTERN = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[\.\d]*\s*\w*)\s*"
    r"\[(?P<pid>\d+)\]\s*"
    r"user=(?P<user>\S+)\s+"
    r"db=(?P<db>\S+)\s+"
    r"(?:LOG|STATEMENT):\s*"
    r"(?P<message>.*)"
)

PG_STATEMENT_PATTERN = re.compile(
    r"(?:statement|AUDIT:.*?)\s*[:,]\s*(?P<sql>SELECT|INSERT|UPDATE|DELETE|ALTER|DROP|CREATE|GRANT|REVOKE)\b",
    re.IGNORECASE,
)

# Sensitive tables that shouldn't be queried by normal operations
SENSITIVE_TABLES = [
    "user_login", "user_details", "otp_", "vehicle_details",
    "credit_card", "api_key", "password", "token",
]


def parse_postgres(line: str) -> dict[str, Any] | None:
    line = line.strip()
    if not line:
        return None

    m = PGAUDIT_PATTERN.search(line)
    if not m:
        return None

    result = {
        "source": "postgres",
        "timestamp": m.group("timestamp"),
        "user": m.group("user"),
        "db": m.group("db"),
        "pid": m.group("pid"),
        "message": m.group("message")[:500],
    }

    # Classify the SQL operation
    sql_match = PG_STATEMENT_PATTERN.search(m.group("message"))
    if sql_match:
        result["sql_operation"] = sql_match.group("sql").upper()

    # Flag queries touching sensitive tables
    msg_lower = m.group("message").lower()
    for table in SENSITIVE_TABLES:
        if table in msg_lower:
            result["sensitive_table"] = table
            break

    # Detect suspicious patterns
    if any(pattern in msg_lower for pattern in [
        "information_schema", "pg_catalog", "pg_tables",
        "pg_user", "pg_shadow", "pg_roles",
    ]):
        result["suspicious"] = "schema_enumeration"

    return result


# ── Unified parser ────────────────────────────────────────────────

PARSERS = {
    "crapi-identity": parse_crapi_identity,
    "crapi-community": parse_crapi_community,
    "crapi-workshop": parse_crapi_workshop,
    "crapi-chatbot": parse_crapi_chatbot,
    "postgresdb": parse_postgres,
}


def parse_line(source: str, line: str) -> dict[str, Any] | None:
    """Parse a log line from any source."""
    parser = PARSERS.get(source)
    if parser:
        return parser(line)
    return None
