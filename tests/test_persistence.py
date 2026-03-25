"""Tests for the Persistence Validator plugin.

Covers:
- PERSISTENCE_TECHNIQUES catalog
- Marker generation (deterministic SHA-256)
- Offline mode execution (no alert endpoint)
- Coverage calculation and finding types
- Custom scope filtering
"""

from __future__ import annotations

import pytest

from redcheck.plugins.base_plugin import PluginRegistry, PluginResult
from redcheck.plugins.detection.persistence_validator import (
    PERSISTENCE_TECHNIQUES,
    PersistenceValidator,
    generate_persistence_marker,
)


@pytest.fixture(autouse=True)
def _clean_registry():
    PluginRegistry.clear()
    PluginRegistry.register(PersistenceValidator)
    yield
    PluginRegistry.clear()


@pytest.fixture
def plugin() -> PersistenceValidator:
    return PersistenceValidator()


# ---------------------------------------------------------------------------
# Registration & metadata
# ---------------------------------------------------------------------------


class TestPersistenceRegistration:
    def test_auto_registers(self) -> None:
        assert PluginRegistry.get("persistence-validator") is PersistenceValidator

    def test_name_and_version(self, plugin: PersistenceValidator) -> None:
        assert plugin.name == "persistence-validator"
        assert plugin.version == "0.1.0"

    def test_mitre_techniques(self, plugin: PersistenceValidator) -> None:
        expected = {"T1053.005", "T1547.001", "T1136.001", "T1505.003", "T1543.003"}
        assert set(plugin.mitre_techniques) == expected

    def test_required_controls(self, plugin: PersistenceValidator) -> None:
        assert plugin.required_controls == ["allow_auth_testing"]


# ---------------------------------------------------------------------------
# Technique catalog
# ---------------------------------------------------------------------------


class TestPersistenceTechniques:
    def test_catalog_has_five_entries(self) -> None:
        assert len(PERSISTENCE_TECHNIQUES) == 5

    @pytest.mark.parametrize(
        "tid",
        ["T1053.005", "T1547.001", "T1136.001", "T1505.003", "T1543.003"],
    )
    def test_each_technique_has_name_and_description(self, tid: str) -> None:
        tech = PERSISTENCE_TECHNIQUES[tid]
        assert "name" in tech
        assert "description" in tech
        assert len(tech["name"]) > 0


# ---------------------------------------------------------------------------
# Marker generation
# ---------------------------------------------------------------------------


class TestMarkerGeneration:
    def test_deterministic(self) -> None:
        m1 = generate_persistence_marker("T1053.005")
        m2 = generate_persistence_marker("T1053.005")
        assert m1 == m2

    def test_different_techniques_different_markers(self) -> None:
        m1 = generate_persistence_marker("T1053.005")
        m2 = generate_persistence_marker("T1547.001")
        assert m1 != m2

    def test_different_seeds_different_markers(self) -> None:
        m1 = generate_persistence_marker("T1053.005", seed="a")
        m2 = generate_persistence_marker("T1053.005", seed="b")
        assert m1 != m2

    def test_marker_starts_with_prefix(self) -> None:
        m = generate_persistence_marker("T1053.005")
        assert m.startswith("REDCHECK-PERSIST-")

    def test_marker_length(self) -> None:
        from redcheck.constants import DETECTION_MARKER_DIGEST_LEN

        m = generate_persistence_marker("T1053.005")
        prefix = "REDCHECK-PERSIST-"
        assert len(m) == len(prefix) + DETECTION_MARKER_DIGEST_LEN


# ---------------------------------------------------------------------------
# Offline mode execution (no alert endpoint)
# ---------------------------------------------------------------------------


class TestPersistenceOffline:
    def test_offline_no_endpoints_returns_partial(self, plugin: PersistenceValidator) -> None:
        """Without alert endpoint, plugin returns PARTIAL (no fabricated metrics)."""
        result = plugin.execute({"targets": ["10.0.0.1"]})
        assert isinstance(result, PluginResult)
        assert result.success is False
        assert result.metadata.get("contract_status") == "PARTIAL"
        assert result.metadata.get("mode") == "no-input"

    def test_offline_coverage_partial_no_findings(self, plugin: PersistenceValidator) -> None:
        result = plugin.execute({"targets": ["10.0.0.1"]})
        assert result.success is False
        assert result.findings == []

    def test_offline_returns_error_message(self, plugin: PersistenceValidator) -> None:
        result = plugin.execute({"targets": ["10.0.0.1"]})
        assert len(result.errors) > 0
        assert "alert_endpoint" in result.errors[0]

    def test_offline_no_target_leakage(self, plugin: PersistenceValidator) -> None:
        result = plugin.execute({"targets": ["192.168.1.100"]})
        # No findings produced in PARTIAL mode
        assert result.findings == []

    def test_offline_metadata_partial(self, plugin: PersistenceValidator) -> None:
        result = plugin.execute({"targets": ["10.0.0.1"]})
        assert result.metadata["mode"] == "no-input"
        assert result.metadata["contract_status"] == "PARTIAL"


# ---------------------------------------------------------------------------
# Custom scope
# ---------------------------------------------------------------------------


class TestPersistenceCustomScope:
    def test_custom_scope_no_endpoints_partial(self, plugin: PersistenceValidator) -> None:
        result = plugin.execute(
            {
                "targets": ["10.0.0.1"],
                "persistence_scope": ["T1053.005", "T1547.001"],
            }
        )
        # No endpoints → PARTIAL regardless of scope
        assert result.success is False
        assert result.metadata.get("contract_status") == "PARTIAL"

    def test_custom_scope_invalid_ids_partial(self, plugin: PersistenceValidator) -> None:
        result = plugin.execute(
            {
                "targets": ["10.0.0.1"],
                "persistence_scope": ["T9999.999"],
            }
        )
        # No endpoints → PARTIAL
        assert result.success is False
        assert result.metadata.get("contract_status") == "PARTIAL"


# ---------------------------------------------------------------------------
# Dry-run
# ---------------------------------------------------------------------------


class TestPersistenceDryRun:
    def test_dry_run_succeeds(self, plugin: PersistenceValidator) -> None:
        result = plugin.dry_run({})
        assert result.success
        assert result.metadata.get("mode") == "dry-run"
