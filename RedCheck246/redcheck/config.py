"""
RedCheck246 Configuration

Central configuration management. Loads from config.yaml or environment variables.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class RedCheckConfig:
    """Central configuration for RedCheck246."""

    # Paths
    project_root: Path = field(default_factory=lambda: Path(__file__).resolve().parents[2])
    engagements_dir: Path = field(default=None)
    logs_dir: Path = field(default=None)
    activation_file: Path = field(default=None)

    # Security
    require_signed_roe: bool = True
    require_activation_code: bool = True
    encryption_algorithm: str = "AES-256-GCM"

    # Operational
    default_mode: str = "dry-run"
    max_concurrent_plugins: int = 1
    audit_log_enabled: bool = True

    def __post_init__(self):
        if self.engagements_dir is None:
            self.engagements_dir = self.project_root / "engagements"
        if self.logs_dir is None:
            self.logs_dir = self.project_root / "logs"
        if self.activation_file is None:
            self.activation_file = self.project_root / ".activation" / "activation.enc"

        # Ensure directories exist
        self.engagements_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_yaml(cls, path: str | Path) -> "RedCheckConfig":
        """Load config from YAML file."""
        path = Path(path)
        if not path.exists():
            return cls()
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    @classmethod
    def from_env(cls) -> "RedCheckConfig":
        """Load config from environment variables (REDCHECK_ prefix)."""
        kwargs: dict[str, Any] = {}
        prefix = "REDCHECK_"
        for key, field_info in cls.__dataclass_fields__.items():
            env_key = prefix + key.upper()
            val = os.environ.get(env_key)
            if val is not None:
                if field_info.type == "bool":
                    kwargs[key] = val.lower() in ("true", "1", "yes")
                elif field_info.type == "int":
                    kwargs[key] = int(val)
                elif field_info.type in ("Path", "Path | None"):
                    kwargs[key] = Path(val)
                else:
                    kwargs[key] = val
        return cls(**kwargs)

    def to_yaml(self, path: str | Path) -> None:
        """Save config to YAML file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {}
        for key in self.__dataclass_fields__:
            val = getattr(self, key)
            if isinstance(val, Path):
                data[key] = str(val)
            else:
                data[key] = val
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)


_config: RedCheckConfig | None = None


def get_config(config_path: str | Path | None = None) -> RedCheckConfig:
    """Get or create the global config instance."""
    global _config
    if _config is None:
        if config_path and Path(config_path).exists():
            _config = RedCheckConfig.from_yaml(config_path)
        else:
            _config = RedCheckConfig()
    return _config
