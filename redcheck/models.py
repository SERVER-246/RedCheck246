"""RedCheck246 data models — Pydantic v2.

Every data structure used across the framework is defined here with full
runtime validation, JSON-schema generation, and serialization support.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class RuntimeMode(str, enum.Enum):
    """Operating modes with distinct capability restrictions."""

    DEV = "dev"
    CI = "ci"
    STAGING = "staging"
    PRODUCTION = "production"
    RESEARCH = "research"


class PluginCapability(str, enum.Enum):
    """Risk classification for plugins (Spec 2)."""

    PASSIVE = "passive"
    ACTIVE = "active"
    DESTRUCTIVE = "destructive"


class FindingSeverity(str, enum.Enum):
    """CVSS-aligned severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AuditLevel(str, enum.Enum):
    """Audit log severity levels."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    SECURITY = "security"


class OperatorRole(str, enum.Enum):
    """Operator roles for RBAC enforcement."""

    VIEWER = "viewer"
    OPERATOR = "operator"
    SENIOR_OPERATOR = "senior_operator"
    ADMIN = "admin"
    AUDITOR = "auditor"


class AttackerClass(str, enum.Enum):
    """Attacker profiles scoping attack graph traversal.

    Each class defines entry-node rules, maximum hop depth,
    allowed edge types, and node-count ceilings for graph construction.
    """

    AC1 = "ac1"  # Opportunistic External Attacker
    AC2 = "ac2"  # Authenticated Insider
    AC3 = "ac3"  # Compromised Service Account
    AC4 = "ac4"  # Post-Exploitation Actor


# ---------------------------------------------------------------------------
# Core Models
# ---------------------------------------------------------------------------


class OffensiveControls(BaseModel):
    """Explicit boolean flags gating each offensive capability.

    Every flag defaults to False (safe-by-default posture).
    Each flag maps to a specific set of plugin ``required_controls``.
    """

    model_config = ConfigDict(frozen=True)

    allow_auth_testing: bool = False
    allow_exploit_validation: bool = False
    allow_data_sampling: bool = False
    allow_credential_spraying: bool = False
    allow_privesc_probing: bool = False
    chain_mode: bool = False

    def has_controls(self, required: list[str]) -> bool:
        """Check if all required control flags are True."""
        return all(getattr(self, ctrl, False) for ctrl in required)


class PluginMetadata(BaseModel):
    """Declarative metadata attached to each plugin class."""

    model_config = ConfigDict(frozen=True)

    name: str
    capability: PluginCapability
    required_controls: list[str] = Field(default_factory=list)
    timeout_seconds: int = Field(default=60, ge=1, le=600)
    rate_limit_rps: int = Field(default=10, ge=1, le=50)
    mitre_techniques: list[str] = Field(default_factory=list)
    requires_isolation: bool = False


class TargetSpec(BaseModel):
    """A single scan target with optional port / protocol constraints."""

    host: str
    ports: list[int] = Field(default_factory=list)
    protocols: list[str] = Field(default_factory=lambda: ["https"])
    excluded_paths: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    """Individual security finding produced by a plugin."""

    finding_type: str
    target: str
    severity: FindingSeverity
    detail: str
    evidence_ref: str | None = None
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cwe_id: str | None = None
    remediation: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    plugin: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    evidence_digest: str | None = None
    sampled_data_len: int | None = None
    mitre_technique: str | None = None


class Evidence(BaseModel):
    """Collected evidence artifact metadata."""

    evidence_type: str
    path: str
    sha256: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    encrypted: bool = False
    size_bytes: int | None = None
    provenance_tag: str | None = None


class PluginResult(BaseModel):
    """Standardised result returned by every plugin execution."""

    plugin_name: str
    success: bool
    findings: list[Finding] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    duration_ms: float | None = None
    mode: str = "live"

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == FindingSeverity.CRITICAL)


class EngagementContext(BaseModel):
    """Full engagement metadata derived from a signed RoE document.

    This model is validated at every policy gate entry (Spec 1, Step 2).
    """

    engagement_id: str
    authorizer: str
    targets: list[str] = Field(min_length=1)
    allowed_tests: list[str] = Field(min_length=1)
    start_time_utc: datetime
    end_time_utc: datetime
    sensitivity: str = "standard"
    roe_path: str | None = None
    roe_signed: bool = False
    activation_verified: bool = False
    session_code: str | None = None
    tenant_id: str | None = None
    offensive_controls: OffensiveControls = Field(default_factory=OffensiveControls)
    safe_mode: bool = True
    runtime_mode: RuntimeMode = RuntimeMode.DEV
    session_id: str | None = None
    attacker_class: AttackerClass | None = None

    @field_validator("authorizer")
    @classmethod
    def authorizer_non_empty(cls, v: str) -> str:
        if not v.strip():
            msg = "authorizer must be a non-empty string"
            raise ValueError(msg)
        return v.strip()

    @model_validator(mode="after")
    def validate_time_window(self) -> EngagementContext:
        if self.end_time_utc <= self.start_time_utc:
            msg = "end_time_utc must be after start_time_utc"
            raise ValueError(msg)
        return self

    def is_within_window(self) -> bool:
        """Check if the current time is within the engagement window."""
        now = datetime.now(timezone.utc)
        start = self.start_time_utc
        end = self.end_time_utc
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)
        return start <= now <= end

    def is_expired(self) -> bool:
        now = datetime.now(timezone.utc)
        end = self.end_time_utc
        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)
        return now > end

    @classmethod
    def from_roe_yaml(cls, path: str | Path) -> EngagementContext:
        """Load engagement context from a validated RoE YAML file."""
        path = Path(path)
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        # Normalise Z suffix for Python 3.10 compat
        for key in ("start_time_utc", "end_time_utc"):
            raw = str(data.get(key, ""))
            if raw.endswith("Z"):
                data[key] = raw[:-1] + "+00:00"

        return cls(
            engagement_id=data.get("engagement_id", path.stem),
            authorizer=data.get("authorizer", ""),
            targets=data.get("authorized_targets", data.get("targets", [])),
            allowed_tests=data.get("allowed_tests", []),
            start_time_utc=data.get("start_time_utc", datetime.now(timezone.utc)),
            end_time_utc=data.get("end_time_utc", datetime.now(timezone.utc)),
            sensitivity=data.get("sensitivity", "standard"),
            roe_path=str(path),
        )


class RoEDocument(BaseModel):
    """Parsed RoE (Rules of Engagement) YAML document with full validation."""

    engagement_id: str
    authorizer: str
    authorized_targets: list[str] = Field(min_length=1)
    allowed_tests: list[str] = Field(min_length=1)
    start_time_utc: datetime
    end_time_utc: datetime
    sensitivity: str = "standard"
    signature: str | None = None

    @field_validator("authorizer")
    @classmethod
    def authorizer_non_empty(cls, v: str) -> str:
        if not v.strip():
            msg = "authorizer must be a non-empty string"
            raise ValueError(msg)
        return v.strip()

    @model_validator(mode="after")
    def validate_time_window(self) -> RoEDocument:
        if self.end_time_utc <= self.start_time_utc:
            msg = "end_time_utc must be after start_time_utc"
            raise ValueError(msg)
        return self

    def is_expired(self) -> bool:
        now = datetime.now(timezone.utc)
        end = self.end_time_utc
        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)
        return now > end

    def is_active(self) -> bool:
        now = datetime.now(timezone.utc)
        start = self.start_time_utc
        end = self.end_time_utc
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)
        return start <= now <= end

    def time_remaining_seconds(self) -> float:
        now = datetime.now(timezone.utc)
        end = self.end_time_utc
        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)
        return max(0.0, (end - now).total_seconds())


class AuditEntry(BaseModel):
    """Single tamper-evident audit log entry."""

    timestamp: str
    level: AuditLevel = AuditLevel.INFO
    action: str
    details: str = ""
    operator: str = "system"
    plugin: str | None = None
    engagement_id: str | None = None
    previous_hash: str = ""
    hash: str = ""


class ScanReport(BaseModel):
    """Aggregated report from a scanning session."""

    engagement_id: str
    scanner: str
    start_time: datetime
    end_time: datetime
    findings: list[Finding] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def duration_seconds(self) -> float:
        return (self.end_time - self.start_time).total_seconds()

    @property
    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts
