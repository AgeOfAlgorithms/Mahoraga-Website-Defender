"""Shared types for structured handoffs between agents."""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EventStatus(str, Enum):
    NEW = "new"
    ANALYZING = "analyzing"
    FIX_PROPOSED = "fix_proposed"
    FIX_REVIEWING = "fix_reviewing"
    FIX_TESTING = "fix_testing"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"
    ESCALATED = "escalated"  # needs human


class ApprovalPolicy(str, Enum):
    AUTO_APPLY = "auto_apply"
    AUTO_APPLY_NOTIFY = "auto_apply_notify"
    HUMAN_REQUIRED = "human_required"


@dataclass
class SecurityEvent:
    """Produced by the Watcher, consumed by the Analyzer."""
    event_id: str = field(default_factory=lambda: f"evt_{uuid.uuid4().hex[:12]}")
    timestamp: float = field(default_factory=time.time)
    source: str = "watcher"
    event_type: str = ""
    severity: Severity = Severity.INFO
    status: EventStatus = EventStatus.NEW
    evidence: dict[str, Any] = field(default_factory=dict)
    context: dict[str, Any] = field(default_factory=dict)

    def save(self, events_dir: Path) -> Path:
        path = events_dir / f"{self.event_id}.json"
        path.write_text(json.dumps(asdict(self), indent=2, default=str))
        return path

    @classmethod
    def load(cls, path: Path) -> SecurityEvent:
        data = json.loads(path.read_text())
        data["severity"] = Severity(data["severity"])
        data["status"] = EventStatus(data["status"])
        return cls(**data)


@dataclass
class TriageResult:
    """Produced by the Analyzer."""
    event_id: str
    is_threat: bool
    classification: str  # e.g. "sql_injection", "brute_force", "false_positive"
    confidence: float  # 0.0-1.0
    severity: Severity
    recommended_action: str
    analysis: str
    approval_policy: ApprovalPolicy = ApprovalPolicy.HUMAN_REQUIRED


@dataclass
class PatchProposal:
    """Produced by the Fixer."""
    event_id: str
    patch_id: str = field(default_factory=lambda: f"patch_{uuid.uuid4().hex[:8]}")
    patch_type: str = ""  # "waf_rule", "code_fix", "config_change", "ip_block"
    description: str = ""
    diff: str = ""
    files_modified: list[str] = field(default_factory=list)
    rollback_steps: str = ""


@dataclass
class ReviewResult:
    """Produced by the Reviewer."""
    patch_id: str
    approved: bool
    issues: list[str] = field(default_factory=list)
    security_concerns: list[str] = field(default_factory=list)
    suggestion: str = ""


@dataclass
class TestResult:
    """Produced by the Tester."""
    patch_id: str
    passed: bool
    flows_tested: list[str] = field(default_factory=list)
    regressions: list[str] = field(default_factory=list)
    performance_impact: str = ""  # "none", "minor", "major"
    complaint: str = ""  # human-readable complaint if something broke
    is_minor: bool = False  # if True, other agents may ignore the complaint


class TicketStatus(str, Enum):
    DETECTED = "detected"          # watcher event (rolling window)
    QUEUED = "queued"              # analyzer confirmed, waiting for fixer
    FIXING = "fixing"              # fixer actively working
    PENDING_REVIEW = "pending_review"  # patch proposed, waiting for reviewer
    REVIEWING = "reviewing"        # reviewer actively working
    DEPLOYED = "deployed"          # patch deployed to prod


@dataclass
class PipelineTicket:
    """Authoritative state for a pipeline ticket. Updated in-place on disk."""
    id: str
    type: str = ""
    endpoint: str = ""
    severity: str = "high"
    status: str = field(default_factory=lambda: TicketStatus.DETECTED.value)
    evidence: str = ""
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    agent: str = ""
    patch_id: str = ""
    patch_description: str = ""
    patch_files: list[str] = field(default_factory=list)
    retry_count: int = 0
    dedup_key: str = ""

    def save(self, pipeline_dir: Path) -> Path:
        self.updated_at = time.time()
        path = pipeline_dir / f"{self.id}.json"
        path.write_text(json.dumps(asdict(self), indent=2, default=str))
        return path

    @classmethod
    def load(cls, path: Path) -> PipelineTicket:
        data = json.loads(path.read_text())
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class AuditEntry:
    """Immutable record for the audit log."""
    timestamp: float = field(default_factory=time.time)
    event_id: str = ""
    action: str = ""
    agent: str = ""
    detail: str = ""
    cost_usd: float = 0.0

    def save(self, audit_dir: Path) -> Path:
        filename = f"{int(self.timestamp)}_{self.agent}_{self.event_id}.json"
        path = audit_dir / filename
        path.write_text(json.dumps(asdict(self), indent=2, default=str))
        return path
