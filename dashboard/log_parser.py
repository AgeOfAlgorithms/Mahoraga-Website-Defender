"""Parse nginx access.log and shadow.log formats into structured dicts."""

from __future__ import annotations

import re
from datetime import datetime


# access.log format:
# $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
# "$http_referer" "$http_user_agent" rt=$request_time
# auth="$http_authorization" body="$request_body" env="$target_env"
ACCESS_RE = re.compile(
    r'(?P<ip>\S+) - (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<proto>[^"]*)" '
    r'(?P<status>\d+) (?P<bytes>\d+) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)" '
    r'rt=(?P<rt>\S+) '
    r'auth="(?P<auth>[^"]*)" '
    r'body="(?P<body>.*)" '
    r'env="(?P<env>[^"]*)"$'
)

# shadow.log format:
# $remote_addr [$time_local] "$request" $status
# auth="$http_authorization" req_body="$request_body" resp_body="$resp_body"
SHADOW_RE = re.compile(
    r'(?P<ip>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<proto>[^"]*)" '
    r'(?P<status>\d+) '
    r'auth="(?P<auth>[^"]*)" '
    r'req_body="(?P<req_body>.*)" '
    r'resp_body="(?P<resp_body>.*)"$'
)


def parse_access_line(line: str) -> dict | None:
    m = ACCESS_RE.match(line.strip())
    if not m:
        return None
    d = m.groupdict()
    return {
        "ip": d["ip"],
        "time": d["time"],
        "method": d["method"],
        "path": d["path"],
        "status": int(d["status"]),
        "bytes": int(d["bytes"]),
        "referer": d["referer"] if d["referer"] != "-" else None,
        "user_agent": d["ua"],
        "response_time": float(d["rt"]),
        "auth": d["auth"] if d["auth"] != "-" else None,
        "body": d["body"] if d["body"] != "-" else None,
        "env": d["env"],
    }


def parse_shadow_line(line: str) -> dict | None:
    m = SHADOW_RE.match(line.strip())
    if not m:
        return None
    d = m.groupdict()
    return {
        "ip": d["ip"],
        "time": d["time"],
        "method": d["method"],
        "path": d["path"],
        "status": int(d["status"]),
        "auth": d["auth"] if d["auth"] != "-" else None,
        "req_body": d["req_body"] if d["req_body"] != "-" else None,
        "resp_body": d["resp_body"] if d["resp_body"] != "-" else None,
    }
