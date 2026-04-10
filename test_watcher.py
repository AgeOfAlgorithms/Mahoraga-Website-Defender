"""Standalone watcher test — runs scan_new_lines() in a loop and reports detections.

Usage: python test_watcher.py [--duration 60]
Runs alongside exploit scripts to measure detection accuracy.
"""

import json
import logging
import sys
import time
from collections import defaultdict
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent))

from harness.agents.watcher import Watcher
from harness.types import Severity

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("watcher-test")

PROJECT_DIR = Path(__file__).parent
LOG_PATH = PROJECT_DIR / "logs" / "nginx" / "access.log"
EVENTS_DIR = PROJECT_DIR / "events"
RULES_DIR = PROJECT_DIR / "detection" / "rules"
EXTRA_LOG_DIR = PROJECT_DIR / "logs"
RESULTS_FILE = PROJECT_DIR / "test_logs" / "watcher_detections.json"

EVENTS_DIR.mkdir(exist_ok=True)


def main():
    duration = int(sys.argv[1]) if len(sys.argv) > 1 else 120

    watcher = Watcher(
        log_path=LOG_PATH,
        events_dir=EVENTS_DIR,
        rules_dir=RULES_DIR,
        extra_log_dir=EXTRA_LOG_DIR,
    )

    logger.info("Watcher test started. Scanning for %ds...", duration)
    logger.info("  nginx log: %s", LOG_PATH)
    logger.info("  extra logs: %s", EXTRA_LOG_DIR)
    logger.info("  events dir: %s", EVENTS_DIR)

    all_events = []
    event_counts = defaultdict(int)
    start = time.time()

    while time.time() - start < duration:
        events = watcher.scan_new_lines()
        for event in events:
            all_events.append({
                "event_id": event.event_id,
                "timestamp": event.timestamp,
                "event_type": event.event_type,
                "severity": event.severity.value,
                "source_ip": event.evidence.get("source_ip", ""),
                "path": event.evidence.get("path", ""),
                "detection": event.context.get("detection", ""),
                "log_source": event.evidence.get("log_source", "nginx"),
                "message_preview": event.evidence.get("message", event.evidence.get("log_line", ""))[:150],
            })
            event_counts[event.event_type] += 1

            severity_icon = {
                "critical": "!!!",
                "high": "!! ",
                "medium": "!  ",
                "low": ".  ",
                "info": "   ",
            }.get(event.severity.value, "   ")

            logger.info(
                "%s [%s] %s | ip=%s path=%s",
                severity_icon,
                event.severity.value.upper(),
                event.event_type,
                event.evidence.get("source_ip", "-"),
                event.evidence.get("path", event.evidence.get("log_source", "-")),
            )

        time.sleep(1)

    # Summary
    logger.info("")
    logger.info("=" * 60)
    logger.info("DETECTION SUMMARY (%d events in %ds)", len(all_events), duration)
    logger.info("=" * 60)

    by_severity = defaultdict(list)
    for e in all_events:
        by_severity[e["severity"]].append(e)

    for sev in ["critical", "high", "medium", "low", "info"]:
        events_at_level = by_severity.get(sev, [])
        if events_at_level:
            logger.info("")
            logger.info("  %s (%d):", sev.upper(), len(events_at_level))
            types_at_level = defaultdict(int)
            for e in events_at_level:
                types_at_level[e["event_type"]] += 1
            for etype, count in sorted(types_at_level.items(), key=lambda x: -x[1]):
                logger.info("    %3d × %s", count, etype)

    logger.info("")
    logger.info("  Total unique event types: %d", len(event_counts))
    logger.info("  Total events: %d", len(all_events))

    # Save results
    results = {
        "duration_seconds": duration,
        "total_events": len(all_events),
        "unique_types": len(event_counts),
        "by_type": dict(event_counts),
        "by_severity": {k: len(v) for k, v in by_severity.items()},
        "events": all_events,
    }
    RESULTS_FILE.write_text(json.dumps(results, indent=2, default=str))
    logger.info("  Results saved to %s", RESULTS_FILE)


if __name__ == "__main__":
    main()
