"""Shared test fixtures for RedCheck246 test suite.

Provides engagement directories, singleton resets, valid/expired RoE files,
mock HTTP transports, and plugin registry cleanup.
"""

from __future__ import annotations

from collections.abc import Generator  # noqa: TC003
from datetime import datetime, timedelta, timezone
from pathlib import Path  # noqa: TC003
from typing import Any

import pytest
import yaml

from redcheck.config import reset_config
from redcheck.core.activation_engine import ActivationEngine
from redcheck.core.policy_engine import PolicyEngine
from redcheck.plugins.base_plugin import PluginRegistry

# ---------------------------------------------------------------------------
# Singleton resets — ensures test isolation
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_singletons() -> Generator[None, None, None]:
    """Reset global singletons before and after every test."""
    PolicyEngine.reset()
    reset_config()
    yield
    PolicyEngine.reset()
    reset_config()


@pytest.fixture(autouse=True)
def _clean_plugin_registry() -> Generator[None, None, None]:
    """Snapshot and restore the plugin registry around each test."""
    original = dict(PluginRegistry._plugins)
    yield
    PluginRegistry._plugins = original


# ---------------------------------------------------------------------------
# Engagement directories
# ---------------------------------------------------------------------------


@pytest.fixture
def engagement_dir(tmp_path: Path) -> Path:
    """Create a temporary engagement directory structure."""
    for sub in ("evidence", "reports", "logs", "scans"):
        (tmp_path / sub).mkdir()
    return tmp_path


# ---------------------------------------------------------------------------
# RoE YAML fixtures
# ---------------------------------------------------------------------------


def _make_roe(
    *,
    engagement_id: str = "TEST-001",
    authorizer: str = "Test Admin",
    hosts: list[str] | None = None,
    tests: list[str] | None = None,
    start_offset_hours: float = -1,
    end_offset_hours: float = 1,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a RoE dict with sensible defaults."""
    now = datetime.now(timezone.utc)
    roe: dict[str, Any] = {
        "engagement_id": engagement_id,
        "authorizer": authorizer,
        "authorized_targets": [
            {"host": h, "ports": [80, 443]} for h in (hosts or ["testhost.local"])
        ],
        "allowed_tests": tests or ["passive-recon", "sast-scanner"],
        "start_time_utc": (now + timedelta(hours=start_offset_hours)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "end_time_utc": (now + timedelta(hours=end_offset_hours)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sensitivity": "high",
        "signature": "test-signature",
    }
    if extra:
        roe.update(extra)
    return roe


@pytest.fixture
def valid_roe_file(tmp_path: Path) -> Path:
    """Create a valid RoE YAML file with a current time window."""
    roe = _make_roe()
    path = tmp_path / "roe.yaml"
    with open(path, "w") as f:
        yaml.dump(roe, f)
    return path


@pytest.fixture
def expired_roe_file(tmp_path: Path) -> Path:
    """Create an expired RoE YAML file."""
    roe = _make_roe(
        engagement_id="TEST-EXPIRED",
        start_offset_hours=-720,  # 30 days ago
        end_offset_hours=-24,  # 1 day ago
    )
    path = tmp_path / "expired_roe.yaml"
    with open(path, "w") as f:
        yaml.dump(roe, f)
    return path


@pytest.fixture
def valid_roe_data() -> dict[str, Any]:
    """Return a valid RoE data dict (not written to disk)."""
    return _make_roe()


# ---------------------------------------------------------------------------
# Activation engine
# ---------------------------------------------------------------------------


@pytest.fixture
def activation_engine(tmp_path: Path) -> ActivationEngine:
    """Fresh activation engine with isolated storage."""
    return ActivationEngine(base_dir=str(tmp_path))


# ---------------------------------------------------------------------------
# Config YAML
# ---------------------------------------------------------------------------


@pytest.fixture
def config_yaml(tmp_path: Path) -> Path:
    """Create a temporary config YAML file."""
    config = {
        "log_level": "DEBUG",
        "log_format": "json",
        "max_concurrent_plugins": 4,
        "require_signed_roe": False,
        "default_mode": "dry-run",
    }
    path = tmp_path / "redcheck.yaml"
    with open(path, "w") as f:
        yaml.dump(config, f)
    return path
