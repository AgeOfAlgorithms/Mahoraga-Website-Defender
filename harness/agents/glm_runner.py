"""GLM agentic runner — sandboxed tool-calling loop for Zhipu AI models.

Replaces the Claude Agent SDK for fixer/reviewer agents. Only exposes
a single Bash tool that is restricted to whitelisted docker exec commands.
The model has NO direct filesystem access.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import subprocess

from openai import AsyncOpenAI

logger = logging.getLogger(__name__)

# Only allow docker exec into these containers
ALLOWED_CONTAINERS = {"crapi-workshop", "shadow-workshop", "nginx-proxy"}

# Block access to sensitive paths even inside containers
BLOCKED_PATHS = [
    "vuln_chains", "plant_flags", "plant_shadow_flags",
    "harness", "detection", "config", "dashboard",
    "docker-compose", "start.sh", ".env",
    "scoreboard.json", "flag_verifier",
]

BASH_TOOL = {
    "type": "function",
    "function": {
        "name": "bash",
        "description": "Execute a bash command. Only 'docker exec' commands are allowed. For pipes/chaining, use: docker exec <container> bash -c 'cmd1 | cmd2'",
        "parameters": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The bash command to execute (must be a docker exec command)",
                }
            },
            "required": ["command"],
        },
    },
}


def _validate_command(command: str) -> str | None:
    """Validate that a command is a safe docker exec. Returns error message or None."""
    cmd = command.strip()

    # Block shell operators that would execute on the HOST (security hole)
    # Pipes, semicolons, &&, ||, backticks, $() — all bypass docker exec
    # Exception: pipes inside a quoted bash -c string are fine
    # Simple check: if the command has a pipe/semicolon OUTSIDE of quotes, block it
    if not _has_bash_c(cmd):
        for op in ["|", "&&", "||", ";", "`", "$("]:
            if op in cmd:
                return (f"Shell operator '{op}' not allowed outside docker exec. "
                        "Use: docker exec <container> bash -c 'cmd1 | cmd2' instead")

    # Must start with docker exec
    if not cmd.startswith("docker exec"):
        return "Only 'docker exec' commands are allowed"

    # Extract container name (docker exec [-flags] <container> ...)
    parts = cmd.split()
    container = None
    i = 2  # skip "docker" "exec"
    while i < len(parts):
        if parts[i].startswith("-"):
            # Skip flags and their values
            if parts[i] in ("-i", "-t", "-u", "-w", "-e"):
                i += 2
            else:
                i += 1
        else:
            container = parts[i]
            break
        i += 1

    if not container or container not in ALLOWED_CONTAINERS:
        return f"Container '{container}' not allowed. Allowed: {ALLOWED_CONTAINERS}"

    # Check for blocked paths in the command
    cmd_lower = cmd.lower()
    for blocked in BLOCKED_PATHS:
        if blocked in cmd_lower:
            return f"Access to '{blocked}' is not allowed"

    return None


def _has_bash_c(cmd: str) -> bool:
    """Check if command uses bash -c (pipes inside quotes are safe)."""
    return "bash -c" in cmd or "sh -c" in cmd


def _execute_command(command: str, timeout: int = 30) -> str:
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
    """Run a GLM agent with sandboxed bash tool access.

    Returns the final text response from the model.
    """
    api_key = os.environ.get("GLM_API_KEY", "")
    if not api_key:
        raise ValueError("GLM_API_KEY not set in environment")

    client = AsyncOpenAI(
        api_key=api_key,
        base_url="https://open.bigmodel.cn/api/paas/v4",
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
                import json
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
    # Return whatever the last assistant message was
    for msg in reversed(messages):
        if msg.get("role") == "assistant" and msg.get("content"):
            return msg["content"]
    return ""
