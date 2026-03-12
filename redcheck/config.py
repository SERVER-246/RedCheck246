"""RedCheck246 Configuration — Pydantic BaseSettings.

Loads from environment variables (REDCHECK_ prefix), config YAML, or defaults.
No side effects on construction — call ``ensure_dirs()`` explicitly.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from redcheck.models import RuntimeMode


class RedCheckConfig(BaseSettings):
    """Central configuration for RedCheck246.

    Resolution order (highest priority first):
      1. Environment variables  (``REDCHECK_`` prefix)
      2. Explicit constructor kwargs
      3. YAML config file (via ``from_yaml()``)
      4. Defaults below
    """

    model_config = SettingsConfigDict(
        env_prefix="REDCHECK_",
        env_nested_delimiter="__",
        case_sensitive=False,
    )

    # Paths
    project_root: Path = Field(default_factory=lambda: Path.cwd())
    engagements_dir: Path | None = None
    logs_dir: Path | None = None
    activation_file: Path | None = None
    evidence_dir: Path | None = None

    # Runtime mode (Spec 4)
    runtime_mode: RuntimeMode = RuntimeMode.DEV

    # Security
    require_signed_roe: bool = True
    require_activation_code: bool = True
    encryption_algorithm: str = "AES-256-GCM"

    # Operational
    default_mode: str = "dry-run"
    max_concurrent_plugins: int = Field(default=1, ge=1, le=10)
    audit_log_enabled: bool = True
    log_level: str = "INFO"
    log_format: str = "text"  # "text" | "json"

    # Networking limits (Spec 3)
    max_requests_per_second: int = Field(default=10, ge=1, le=50)
    request_timeout_seconds: int = Field(default=10, ge=1, le=30)
    scan_timeout_seconds: int = Field(default=300, ge=1, le=600)

    # Extended rate limits (Phase 1)
    tcp_connections_per_second: int = Field(default=5, ge=1, le=20)
    max_concurrent_targets: int = Field(default=3, ge=1, le=10)
    per_target_timeout_seconds: int = Field(default=60, ge=1, le=120)
    payload_batch_size: int = Field(default=50, ge=1, le=200)
    osint_api_rate_rps: int = Field(default=5, ge=1, le=20)

    # Metrics
    metrics_db_path: Path | None = None
    metrics_rotation_days: int = Field(default=1, ge=1, le=30)

    # Multi-tenant
    multi_tenant_enabled: bool = False
    default_tenant_id: str = "default"

    # OTP / Test Mode (Phase 1)
    otp_smtp_host: str = "localhost"
    otp_smtp_port: int = Field(default=587, ge=1, le=65535)
    otp_smtp_use_tls: bool = True

    @field_validator("runtime_mode", mode="before")
    @classmethod
    def coerce_runtime_mode(cls, v: Any) -> Any:
        if isinstance(v, str):
            return v.lower()
        return v

    def ensure_dirs(self) -> None:
        """Create required directories. Call explicitly — not on __init__."""
        for d in self.resolved_engagements_dir, self.resolved_logs_dir, self.resolved_evidence_dir:
            d.mkdir(parents=True, exist_ok=True)
        self.resolved_activation_file.parent.mkdir(parents=True, exist_ok=True)

    # Resolved paths (with defaults relative to project_root)
    @property
    def resolved_engagements_dir(self) -> Path:
        return self.engagements_dir or self.project_root / "engagements"

    @property
    def resolved_logs_dir(self) -> Path:
        return self.logs_dir or self.project_root / "logs"

    @property
    def resolved_activation_file(self) -> Path:
        return self.activation_file or self.project_root / ".activation" / "activation.enc"

    @property
    def resolved_evidence_dir(self) -> Path:
        return self.evidence_dir or self.project_root / "evidence"

    @classmethod
    def from_yaml(cls, path: str | Path) -> RedCheckConfig:
        """Load config from YAML file, merged with env vars."""
        path = Path(path)
        if not path.exists():
            return cls()
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        # Filter to known fields
        known = cls.model_fields.keys()
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)

    def to_yaml(self, path: str | Path) -> None:
        """Serialize config to YAML file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = self.model_dump(mode="json")
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)


# ---------------------------------------------------------------------------
# Module-level singleton with explicit reset for testing
# ---------------------------------------------------------------------------

_config: RedCheckConfig | None = None


def get_config(config_path: str | Path | None = None) -> RedCheckConfig:
    """Get or create the global config instance."""
    global _config  # noqa: PLW0603
    if _config is None:
        if config_path and Path(config_path).exists():
            _config = RedCheckConfig.from_yaml(config_path)
        else:
            _config = RedCheckConfig()
    return _config


def reset_config() -> None:
    """Reset global config — for test isolation only."""
    global _config  # noqa: PLW0603
    _config = None
