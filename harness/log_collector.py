"""Log Collector — tails Docker container logs and writes them to local files.

Runs as a background process alongside the Watcher, collecting logs from:
  - crAPI services (identity, community, workshop, chatbot, web)
  - Postgres (pgaudit SQL query logs)

Each container's logs are written to a separate file in logs/<container-name>/
so the Watcher can tail them independently.
"""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

# Containers to collect logs from
MONITORED_CONTAINERS = [
    "crapi-identity",
    "crapi-community",
    "crapi-workshop",
    "crapi-chatbot",
    "crapi-web",
    "postgresdb",
]


async def tail_container(container: str, log_dir: Path) -> None:
    """Tail a single container's logs and write to a file."""
    output_dir = log_dir / container
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "container.log"

    logger.info("Tailing %s → %s", container, output_file)

    while True:
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "logs", "--follow", "--tail", "0",
                "--timestamps", container,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )

            with open(output_file, "a") as f:
                while True:
                    line = await proc.stdout.readline()
                    if not line:
                        break
                    decoded = line.decode("utf-8", errors="replace")
                    f.write(decoded)
                    f.flush()

            await proc.wait()
            logger.warning("Container %s log stream ended, restarting in 5s", container)
        except Exception as e:
            logger.error("Error tailing %s: %s", container, e)

        await asyncio.sleep(5)


async def run_collector(log_dir: Path) -> None:
    """Start tailing all monitored containers."""
    logger.info("Log collector starting for %d containers", len(MONITORED_CONTAINERS))

    tasks = [
        asyncio.create_task(tail_container(name, log_dir))
        for name in MONITORED_CONTAINERS
    ]

    await asyncio.gather(*tasks)


def start_collector(log_dir: Path) -> None:
    """Entry point — can be called from main.py."""
    asyncio.run(run_collector(log_dir))
