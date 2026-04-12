"""LLM agentic runner — sandboxed tool-calling loop for Gemini.

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


def _get_gemini_client() -> AsyncOpenAI:
    """Create a Gemini client via OpenAI-compatible API."""
    import httpx
    api_key = os.environ.get("GEMINI_API_KEY", "")
    if not api_key:
        raise ValueError("GEMINI_API_KEY not set in environment")
    return AsyncOpenAI(
        api_key=api_key,
        base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
        timeout=httpx.Timeout(120.0, connect=15.0),
        max_retries=3,
    )


async def run_agent(
    prompt: str,
    system_prompt: str,
    max_turns: int = 20,
    model: str = "gemini-2.5-flash",
) -> str:
    """Run a Gemini agent with sandboxed bash tool access.

    Returns the final text response from the model.
    """
    client = _get_gemini_client()

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": prompt},
    ]

    for turn in range(max_turns):
        try:
            response = await client.chat.completions.create(
                model=model,
                messages=messages,
                tools=[BASH_TOOL],
                temperature=0.1,
            )
        except Exception as e:
            logger.error("Gemini API call failed on turn %d: %s", turn + 1, e)
            raise

        choice = response.choices[0]
        message = choice.message

        # Gemini rejects null values in message fields — strip them all
        msg_dict = {k: v for k, v in message.model_dump().items() if v is not None}
        if "content" not in msg_dict:
            msg_dict["content"] = ""
        messages.append(msg_dict)

        if choice.finish_reason != "tool_calls" or not message.tool_calls:
            return message.content or ""

        for tool_call in message.tool_calls:
            if tool_call.function.name == "bash":
                try:
                    args = json.loads(tool_call.function.arguments)
                    command = args.get("command", "")
                except json.JSONDecodeError:
                    command = tool_call.function.arguments

                logger.debug("Gemini bash: %s", command[:120])
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
    for msg in reversed(messages):
        if msg.get("role") == "assistant" and msg.get("content"):
            return msg["content"]
    return ""


async def run_completion(
    prompt: str,
    system_prompt: str,
    model: str = "gemini-2.5-flash",
) -> str:
    """Simple text completion — no tool use. For shadow analyzer."""
    client = _get_gemini_client()

    response = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
        temperature=0.1,
    )

    return response.choices[0].message.content or ""
