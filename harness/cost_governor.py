"""Budget tracking and circuit breakers for API cost control."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class CostGovernor:
    daily_budget: float = 50.0
    per_incident_cap: float = 10.0
    hourly_api_calls_limit: int = 100
    anomaly_multiplier: float = 3.0  # pause if spend rate exceeds Nx baseline

    # Internal tracking
    _daily_spend: float = field(default=0.0, repr=False)
    _incident_spend: dict[str, float] = field(default_factory=dict, repr=False)
    _hourly_calls: list[float] = field(default_factory=list, repr=False)
    _day_start: float = field(default_factory=time.time, repr=False)
    _baseline_hourly_spend: float = field(default=10.0, repr=False)
    _paused: bool = field(default=False, repr=False)
    _ledger_path: Path | None = field(default=None, repr=False)

    def set_ledger_path(self, path: Path) -> None:
        self._ledger_path = path
        if path.exists():
            self._load_ledger()

    def can_spend(self, event_id: str, estimated_cost: float) -> bool:
        """Check if we're allowed to spend more."""
        if self._paused:
            logger.warning("Cost governor is PAUSED — human intervention required")
            return False

        self._reset_daily_if_needed()
        self._prune_hourly_calls()

        # Daily budget check
        if self._daily_spend + estimated_cost > self.daily_budget:
            logger.warning(
                "Daily budget would be exceeded: $%.2f + $%.2f > $%.2f",
                self._daily_spend, estimated_cost, self.daily_budget,
            )
            return False

        # Per-incident cap
        incident_total = self._incident_spend.get(event_id, 0.0)
        if incident_total + estimated_cost > self.per_incident_cap:
            logger.warning(
                "Incident %s cap would be exceeded: $%.2f + $%.2f > $%.2f",
                event_id, incident_total, estimated_cost, self.per_incident_cap,
            )
            return False

        # Hourly rate limit
        if len(self._hourly_calls) >= self.hourly_api_calls_limit:
            logger.warning("Hourly API call limit reached: %d", self.hourly_api_calls_limit)
            return False

        # Anomaly detection: if recent spend rate is way above baseline
        recent_spend = self._recent_hourly_spend()
        if recent_spend > self._baseline_hourly_spend * self.anomaly_multiplier:
            logger.critical(
                "CIRCUIT BREAKER: spend rate $%.2f/hr exceeds %.0fx baseline ($%.2f/hr). Pausing.",
                recent_spend, self.anomaly_multiplier, self._baseline_hourly_spend,
            )
            self._paused = True
            return False

        return True

    def record_spend(self, event_id: str, cost: float) -> None:
        """Record actual spend after an API call."""
        self._daily_spend += cost
        self._incident_spend[event_id] = self._incident_spend.get(event_id, 0.0) + cost
        self._hourly_calls.append(time.time())
        self._save_ledger()
        logger.info(
            "Spend recorded: $%.4f for %s (daily total: $%.2f)",
            cost, event_id, self._daily_spend,
        )

    def resume(self) -> None:
        """Human override to resume after circuit breaker."""
        self._paused = False
        logger.info("Cost governor resumed by human override")

    def get_status(self) -> dict:
        self._reset_daily_if_needed()
        return {
            "paused": self._paused,
            "daily_spend": round(self._daily_spend, 4),
            "daily_budget": self.daily_budget,
            "daily_remaining": round(self.daily_budget - self._daily_spend, 4),
            "hourly_calls": len(self._hourly_calls),
            "hourly_limit": self.hourly_api_calls_limit,
            "incidents_tracked": len(self._incident_spend),
        }

    def _reset_daily_if_needed(self) -> None:
        now = time.time()
        if now - self._day_start > 86400:
            # Update baseline from actual usage before resetting
            hours_elapsed = (now - self._day_start) / 3600
            if hours_elapsed > 0:
                self._baseline_hourly_spend = max(
                    2.0, self._daily_spend / hours_elapsed
                )
            self._daily_spend = 0.0
            self._incident_spend.clear()
            self._day_start = now

    def _prune_hourly_calls(self) -> None:
        cutoff = time.time() - 3600
        self._hourly_calls = [t for t in self._hourly_calls if t > cutoff]

    def _recent_hourly_spend(self) -> float:
        """Estimate spend rate over the last hour."""
        cutoff = time.time() - 3600
        return sum(
            v for k, v in self._incident_spend.items()
            # Rough: assume recent spend is proportional to call count
        ) * (len([t for t in self._hourly_calls if t > cutoff]) / max(len(self._hourly_calls), 1))

    def _save_ledger(self) -> None:
        if self._ledger_path:
            data = {
                "daily_spend": self._daily_spend,
                "day_start": self._day_start,
                "incident_spend": self._incident_spend,
                "baseline_hourly_spend": self._baseline_hourly_spend,
                "paused": self._paused,
            }
            self._ledger_path.write_text(json.dumps(data, indent=2))

    def _load_ledger(self) -> None:
        if self._ledger_path and self._ledger_path.exists():
            data = json.loads(self._ledger_path.read_text())
            self._daily_spend = data.get("daily_spend", 0.0)
            self._day_start = data.get("day_start", time.time())
            self._incident_spend = data.get("incident_spend", {})
            self._baseline_hourly_spend = data.get("baseline_hourly_spend", 2.0)
            self._paused = data.get("paused", False)
