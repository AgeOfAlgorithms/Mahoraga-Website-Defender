"""Entrypoint for the Reactive Defender harness."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import threading
from pathlib import Path

from harness.log_collector import run_collector
from harness.orchestrator import Orchestrator


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)-8s] %(name)-25s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler("reactive_defender.log"),
        ],
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Reactive Defender — AI-powered website security agent",
    )
    parser.add_argument(
        "--project-dir",
        type=Path,
        default=Path("."),
        help="Project root directory (default: current directory)",
    )
    parser.add_argument(
        "--app-url",
        default="http://localhost:8888",
        help="URL of the application to defend (default: http://localhost:8888)",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=4.0,
        help="Seconds between log scans (default: 4.0)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()

    setup_logging(args.verbose)
    logging.getLogger(__name__).info(
        "Starting Reactive Defender (project=%s, app=%s, poll=%.1fs)",
        args.project_dir, args.app_url, args.poll_interval,
    )

    project_dir = args.project_dir.resolve()
    log_dir = project_dir / "logs"

    # Start log collector in a background thread
    def collector_thread():
        asyncio.run(run_collector(log_dir))

    collector = threading.Thread(target=collector_thread, daemon=True)
    collector.start()
    logging.getLogger(__name__).info("Log collector started in background")

    orchestrator = Orchestrator(
        project_dir=project_dir,
        app_url=args.app_url,
    )

    try:
        asyncio.run(orchestrator.run(poll_interval=args.poll_interval))
    except KeyboardInterrupt:
        logging.getLogger(__name__).info("Shutting down gracefully...")


if __name__ == "__main__":
    main()
