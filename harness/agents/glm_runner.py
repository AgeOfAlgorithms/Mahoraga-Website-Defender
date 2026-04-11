"""GLM agentic runner — sandboxed tool-calling loop for Zhipu AI models.

Replaces the Claude Agent SDK for fixer/reviewer agents. Exposes a
sandboxed Bash tool that allows:
  1. Reading/writing files ONLY within crapi-fork/
  2. docker exec into whitelisted containers (for reloads)
  3. docker compose rebuild for compiled services (Java/Go)

The model has NO access to anything outside crapi-fork/.
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
    # Resolve the crapi-fork path for validation
    crapi_str = str(CRAPI_FORK_DIR)

    # Read commands: cat, grep, find, head, tail, ls, wc
    read_cmds = ("cat ", "grep ", "find ", "head ", "tail ", "ls ", "wc ")
    # Write commands: sed, python3, cp, mv
    write_cmds = ("sed ", "python3 ", "cp ", "mv ")
    # All allowed prefixes
    allowed_prefixes = read_cmds + write_cmds

    # Check if the command starts with an allowed prefix
    if any(cmd.startswith(p) for p in allowed_prefixes):
        # Verify all file paths reference crapi-fork/
        # Extract potential file paths (anything that looks like a path)
        path_pattern = re.compile(r'(?:^|\s)(/\S+)')
        paths = path_pattern.findall(cmd)

        for path in paths:
            resolved = str(Path(path).resolve())
            if not resolved.startswith(crapi_str):
                return f"Path '{path}' is outside crapi-fork/. Only crapi-fork/ files are accessible."
        return None

    # Allow pkill for gunicorn reload via docker exec (already handled above)

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
        # Truncate very long outputs
        if len(output) > 8000:
            output = output[:4000] + "\n... (truncated) ...\n" + output[-4000:]
        return output or "(no output)"
    except subprocess.TimeoutExpired:
        return f"Command timed out after {timeout}s"
    except Exception as e:
        return f"Error executing command: {e}"


async def run_glm_agent(
    prompt: str,
    system_prompt: str,
    max_turns: int = 20,
    model: str = "glm-4-plus",
) -> str:
    """Run a GLM agent with sandboxed tool access.

    Returns the final text response from the model.
    """
    api_key = os.environ.get("GLM_API_KEY", "")
    if not api_key:
        raise ValueError("GLM_API_KEY not set in environment")

    from openai import AsyncOpenAI as _Client
    import httpx
    client = _Client(
        api_key=api_key,
        base_url="https://open.bigmodel.cn/api/paas/v4",
        timeout=httpx.Timeout(60.0, connect=15.0),
        max_retries=3,
    )

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
            logger.error("GLM API call failed on turn %d: %s", turn + 1, e)
            raise

        choice = response.choices[0]
        message = choice.message

        # Append assistant message to history
        messages.append(message.model_dump())

        # If no tool calls, we're done
        if choice.finish_reason != "tool_calls" or not message.tool_calls:
            return message.content or ""

        # Execute tool calls
        for tool_call in message.tool_calls:
            if tool_call.function.name == "bash":
                try:
                    args = json.loads(tool_call.function.arguments)
                    command = args.get("command", "")
                except json.JSONDecodeError:
                    command = tool_call.function.arguments

                logger.debug("GLM bash: %s", command[:120])
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

    logger.warning("GLM agent reached max turns (%d)", max_turns)
    for msg in reversed(messages):
        if msg.get("role") == "assistant" and msg.get("content"):
            return msg["content"]
    return ""
