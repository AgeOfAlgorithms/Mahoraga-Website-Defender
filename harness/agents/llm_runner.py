"""LLM agentic runner — sandboxed tool-calling loop.

Exposes a sandboxed Bash tool that allows:
  1. Reading/writing files ONLY within crapi-fork/
  2. docker exec into whitelisted containers (for reloads)
  3. docker compose rebuild for compiled services (Java/Go)

Also provides a simple text-only completion function for the
shadow analyzer (no tool use needed).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import subprocess
from pathlib import Path

from openai import AsyncOpenAI

logger = logging.getLogger(__name__)

# Absolute path to the crapi-fork directory (set at import time)
_PROJECT_DIR = Path(__file__).resolve().parent.parent.parent
CRAPI_FORK_DIR = _PROJECT_DIR / "crapi-fork"

# Containers we allow docker exec into (for reloads/verification)
ALLOWED_EXEC_CONTAINERS = {"crapi-workshop", "shadow-workshop", "nginx-proxy"}

# Containers we allow rebuilding (compiled services)
ALLOWED_REBUILD_SERVICES = {
    "crapi-identity", "shadow-identity",
    "crapi-community", "shadow-community",
    "crapi-workshop", "shadow-workshop",
    "nginx-proxy",
}

# Paths that must NEVER be accessed (even within crapi-fork)
BLOCKED_PATTERNS = [
    "plant_flags", "plant_shadow_flags",
    "harness/", "detection/", "config/", "dashboard/",
    "docker-compose", "start.sh", ".env",
    "scoreboard.json", "flag_verifier",
    "vuln_chains/",
]

BASH_TOOL = {
    "type": "function",
    "function": {
        "name": "bash",
        "description": (
            "Execute a bash command. Allowed commands:\n"
            "- cat, grep, find, head, tail, ls on files within crapi-fork/\n"
            "- sed, python3 -c to edit files within crapi-fork/\n"
            "- docker exec <container> for verification/reloads\n"
            "- docker compose up -d --build <service> to rebuild compiled services\n"
            "For pipes, just write them normally (e.g. grep -n pattern file | head)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The bash command to execute",
                }
            },
            "required": ["command"],
        },
    },
}


def _validate_command(command: str) -> str | None:
    """Validate that a command is safe. Returns error message or None if OK."""
    cmd = command.strip()

    # Check for blocked patterns in the entire command
    cmd_lower = cmd.lower()
    for blocked in BLOCKED_PATTERNS:
        if blocked in cmd_lower:
            return f"Access to '{blocked}' is not allowed"

    # Allow docker exec into whitelisted containers
    if cmd.startswith("docker exec"):
        parts = cmd.split()
        container = None
        i = 2
        while i < len(parts):
            if parts[i].startswith("-"):
                if parts[i] in ("-i", "-t", "-u", "-w", "-e"):
                    i += 2
                else:
                    i += 1
            else:
                container = parts[i]
                break
            i += 1
        if container not in ALLOWED_EXEC_CONTAINERS:
            return f"docker exec into '{container}' not allowed. Allowed: {ALLOWED_EXEC_CONTAINERS}"
        return None

    # Allow docker compose rebuild for specific services
    if cmd.startswith("docker compose") and "--build" in cmd:
        for service in ALLOWED_REBUILD_SERVICES:
            if service in cmd:
                return None
        return "docker compose rebuild only allowed for specific services"

    # Allow file operations ONLY within crapi-fork/
    crapi_str = str(CRAPI_FORK_DIR)

    read_cmds = ("cat ", "grep ", "find ", "head ", "tail ", "ls ", "wc ")
    write_cmds = ("sed ", "python3 ", "cp ", "mv ")
    allowed_prefixes = read_cmds + write_cmds

    if any(cmd.startswith(p) for p in allowed_prefixes):
        path_pattern = re.compile(r'(?:^|\s)(/\S+)')
        paths = path_pattern.findall(cmd)
        for path in paths:
            resolved = str(Path(path).resolve())
            if not resolved.startswith(crapi_str):
                return f"Path '{path}' is outside crapi-fork/. Only crapi-fork/ files are accessible."
        return None

    return (
        f"Command not allowed: '{cmd[:60]}...'. "
        "Only file operations within crapi-fork/ and docker exec/compose are permitted."
    )


def _execute_command(command: str, timeout: int = 60) -> str:
    """Execute a validated command and return output."""
    error = _validate_command(command)
    if error:
        return f"BLOCKED: {error}"

    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(_PROJECT_DIR),
        )
        output = result.stdout
        if result.stderr:
            output += f"\nSTDERR: {result.stderr}"
        if result.returncode != 0:
            output += f"\n(exit code {result.returncode})"
        if len(output) > 8000:
            output = output[:4000] + "\n... (truncated) ...\n" + output[-4000:]
        return output or "(no output)"
    except subprocess.TimeoutExpired:
        return f"Command timed out after {timeout}s"
    except Exception as e:
        return f"Error executing command: {e}"


# ── LLM config (loaded from config/llm.yaml) ────────────────────

def _load_llm_config() -> dict:
    """Load LLM config from config/llm.yaml."""
    import yaml
    config_path = _PROJECT_DIR / "config" / "llm.yaml"
    if config_path.exists():
        with open(config_path) as f:
            return yaml.safe_load(f) or {}
    return {}

_llm_config = _load_llm_config()

# Resolve model names and pricing from config
FIXER_MODEL = _llm_config.get("fixer", {}).get("model", "gemini-3-flash-preview")
REVIEWER_MODEL = _llm_config.get("reviewer", {}).get("model", "gemini-3-flash-preview")
ANALYZER_MODEL = _llm_config.get("shadow_analyzer", {}).get("model", "gemini-2.5-flash")

# Backward compat aliases
AGENT_MODEL = FIXER_MODEL
COMPLETION_MODEL = ANALYZER_MODEL

MODEL_PRICING = {}
for role in ("fixer", "reviewer", "shadow_analyzer"):
    cfg = _llm_config.get(role, {})
    p = cfg.get("pricing", {})
    if p:
        MODEL_PRICING[cfg.get("model", "")] = {
            "input": p.get("input_per_million", 0),
            "output": p.get("output_per_million", 0),
        }

# Per-agent heartbeat tracking: agent_name → {last_response_time, turn, event_id}
_agent_heartbeats: dict[str, dict] = {}

# Cache clients per role to avoid creating new connections each call
_llm_clients: dict[str, AsyncOpenAI] = {}


def _get_llm_client(role: str = "fixer") -> AsyncOpenAI:
    """Create or return cached LLM client for a given role (fixer/reviewer/shadow_analyzer)."""
    if role in _llm_clients:
        return _llm_clients[role]

    import httpx
    cfg = _llm_config.get(role, _llm_config.get("fixer", {}))
    api_key_env = cfg.get("api_key_env", "GEMINI_API_KEY")
    api_key = os.environ.get(api_key_env, "")
    if not api_key:
        raise ValueError(f"{api_key_env} not set in environment (needed for '{role}' LLM)")

    # Resolve base_url: explicit on role > provider lookup from config > error
    base_url = cfg.get("base_url")
    if not base_url:
        provider = cfg.get("provider", "").lower()
        providers = _llm_config.get("providers", {})
        base_url = providers.get(provider)
    if not base_url:
        raise ValueError(
            f"No base_url or provider set for '{role}' in config/llm.yaml."
        )

    client = AsyncOpenAI(
        api_key=api_key,
        base_url=base_url,
        timeout=httpx.Timeout(connect=15.0, read=120.0, write=30.0, pool=15.0),
        max_retries=3,
    )
    _llm_clients[role] = client
    return client


def _calc_cost(model: str, prompt_tokens: int, completion_tokens: int) -> float:
    """Calculate cost in USD from token counts."""
    pricing = MODEL_PRICING.get(model)
    if not pricing:
        return 0.0
    return (prompt_tokens * pricing["input"] + completion_tokens * pricing["output"]) / 1_000_000


async def run_agent(
    prompt: str,
    system_prompt: str,
    max_turns: int = 20,
    model: str = AGENT_MODEL,
    on_tool_call: callable = None,
    agent_name: str = "",
    role: str = "fixer",
) -> tuple[str, float]:
    """Run an LLM agent with sandboxed bash tool access.

    Returns (final_text_response, total_cost_usd).
    """
    client = _get_llm_client(role)

    total_prompt_tokens = 0
    total_completion_tokens = 0

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": prompt},
    ]

    for turn in range(max_turns):
        # Nudge the LLM to wrap up before it runs out of turns
        if turn == max_turns - 3:
            messages.append({
                "role": "user",
                "content": (
                    "You are almost out of turns. Stop making tool calls and "
                    "provide your final JSON response NOW."
                ),
            })

        try:
            response = await client.chat.completions.create(
                model=model,
                messages=messages,
                tools=[BASH_TOOL],
                temperature=0.1,
            )
        except Exception as e:
            logger.error("[%s] API call failed on turn %d: %s", model, turn + 1, e)
            raise

        # Accumulate token usage
        if response.usage:
            total_prompt_tokens += response.usage.prompt_tokens or 0
            total_completion_tokens += response.usage.completion_tokens or 0

        # Update heartbeat (in-memory + on-disk for dashboard)
        if agent_name:
            import time as _time
            hb = {
                "last_response": _time.time(),
                "turn": turn + 1,
                "max_turns": max_turns,
            }
            _agent_heartbeats[agent_name] = hb
            try:
                hb_file = _PROJECT_DIR / "config" / "agent_heartbeats.json"
                # Merge with existing heartbeats
                existing = {}
                if hb_file.exists():
                    existing = json.loads(hb_file.read_text())
                existing[agent_name] = hb
                hb_file.write_text(json.dumps(existing))
            except Exception:
                pass

        choice = response.choices[0]
        message = choice.message

        # Some APIs reject null values in message fields — strip them all
        msg_dict = {k: v for k, v in message.model_dump().items() if v is not None}
        if "content" not in msg_dict:
            msg_dict["content"] = ""
        messages.append(msg_dict)

        if choice.finish_reason != "tool_calls" or not message.tool_calls:
            # If model stopped with content, return it
            if message.content:
                cost = _calc_cost(model, total_prompt_tokens, total_completion_tokens)
                return message.content, cost
            # Model stopped without content after tool calls — nudge it
            messages.append({
                "role": "user",
                "content": "Now provide your final JSON response as specified in the response format.",
            })
            continue

        for tool_call in message.tool_calls:
            if tool_call.function.name == "bash":
                try:
                    args = json.loads(tool_call.function.arguments)
                    command = args.get("command", "")
                except json.JSONDecodeError:
                    command = tool_call.function.arguments

                logger.debug("[%s] bash: %s", model, command[:120])
                if on_tool_call:
                    on_tool_call(command[:120])
                output = _execute_command(command)

                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": output,
                })
            else:
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": f"Unknown tool: {tool_call.function.name}",
                })

    logger.warning("Agent reached max turns (%d)", max_turns)
    cost = _calc_cost(model, total_prompt_tokens, total_completion_tokens)
    for msg in reversed(messages):
        if msg.get("role") == "assistant" and msg.get("content"):
            return msg["content"], cost
    return "", cost


async def run_completion(
    prompt: str,
    system_prompt: str,
    model: str = COMPLETION_MODEL,
) -> tuple[str, float]:
    """Simple text completion — no tool use. For shadow analyzer.

    Returns (text_response, cost_usd).
    """
    client = _get_llm_client("shadow_analyzer")

    response = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
        temperature=0.1,
    )

    cost = 0.0
    if response.usage:
        cost = _calc_cost(model, response.usage.prompt_tokens or 0,
                          response.usage.completion_tokens or 0)

    return response.choices[0].message.content or "", cost
