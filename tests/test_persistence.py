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
    def test_offline_all_undetected(self, plugin: PersistenceValidator) -> None:
        """Without alert endpoint, detection phase is skipped → all undetected."""
        result = plugin.execute({"targets": ["10.0.0.1"]})
        assert isinstance(result, PluginResult)
        assert result.success

        undetected = [f for f in result.findings if f["finding_type"] == "persistence_undetected"]
        assert len(undetected) == len(PERSISTENCE_TECHNIQUES)

    def test_offline_coverage_zero(self, plugin: PersistenceValidator) -> None:
        result = plugin.execute({"targets": ["10.0.0.1"]})
        coverage = [f for f in result.findings if f["finding_type"] == "persistence_coverage"]
        assert len(coverage) == 1
        assert coverage[0]["metadata"]["coverage_percent"] == 0.0

    def test_offline_coverage_severity_high(self, plugin: PersistenceValidator) -> None:
        result = plugin.execute({"targets": ["10.0.0.1"]})
        coverage = [f for f in result.findings if f["finding_type"] == "persistence_coverage"]
        # 0% coverage → severity is high
        assert coverage[0]["severity"] == "high"

    def test_offline_target_from_context(self, plugin: PersistenceValidator) -> None:
        result = plugin.execute({"targets": ["192.168.1.100"]})
        for f in result.findings:
            assert f["target"] == "192.168.1.100"

    def test_offline_metadata_counts(self, plugin: PersistenceValidator) -> None:
        result = plugin.execute({"targets": ["10.0.0.1"]})
        assert result.metadata["techniques_in_scope"] == 5
        assert result.metadata["techniques_injected"] == 5
        assert result.metadata["techniques_detected"] == 0


# ---------------------------------------------------------------------------
# Custom scope
# ---------------------------------------------------------------------------


class TestPersistenceCustomScope:
    def test_custom_scope_limits_techniques(self, plugin: PersistenceValidator) -> None:
        result = plugin.execute(
            {
                "targets": ["10.0.0.1"],
                "persistence_scope": ["T1053.005", "T1547.001"],
            }
        )
        undetected = [f for f in result.findings if f["finding_type"] == "persistence_undetected"]
        # Only 2 techniques in scope, so only 2 undetected findings
        assert len(undetected) == 2

    def test_custom_scope_invalid_ids_ignored(self, plugin: PersistenceValidator) -> None:
        result = plugin.execute(
            {
                "targets": ["10.0.0.1"],
                "persistence_scope": ["T9999.999"],
            }
        )
        undetected = [f for f in result.findings if f["finding_type"] == "persistence_undetected"]
        assert len(undetected) == 0
        # Only coverage finding remains
        coverage = [f for f in result.findings if f["finding_type"] == "persistence_coverage"]
        assert len(coverage) == 1


# ---------------------------------------------------------------------------
# Dry-run
# ---------------------------------------------------------------------------


class TestPersistenceDryRun:
    def test_dry_run_succeeds(self, plugin: PersistenceValidator) -> None:
        result = plugin.dry_run({})
        assert result.success
        assert result.metadata.get("mode") == "dry-run"
