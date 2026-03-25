"""Tests for the Detection Response Recorder plugin.

Covers:
- Detection effectiveness matrix generation
- Blind spot identification
- Effective detection identification
- Empty upstream / missing detection-coverage data
"""

from __future__ import annotations

import pytest

from redcheck.plugins.base_plugin import PluginRegistry
from redcheck.plugins.detection.response_recorder import (
    DetectionResponseRecorder,
)


@pytest.fixture(autouse=True)
def _clean_registry():
    PluginRegistry.clear()
    PluginRegistry.register(DetectionResponseRecorder)
    yield
    PluginRegistry.clear()


@pytest.fixture
def plugin() -> DetectionResponseRecorder:
    return DetectionResponseRecorder()


# ---------------------------------------------------------------------------
# Registration & metadata
# ---------------------------------------------------------------------------


class TestResponseRecorderRegistration:
    def test_auto_registers(self) -> None:
        assert PluginRegistry.get("detection-response-recorder") is DetectionResponseRecorder

    def test_name_and_version(self, plugin: DetectionResponseRecorder) -> None:
        assert plugin.name == "detection-response-recorder"
        assert plugin.version == "0.1.0"

    def test_mitre_techniques(self, plugin: DetectionResponseRecorder) -> None:
        assert set(plugin.mitre_techniques) == {"T1562.001", "T1562.006"}

    def test_required_controls(self, plugin: DetectionResponseRecorder) -> None:
        assert plugin.required_controls == ["allow_auth_testing"]


# ---------------------------------------------------------------------------
# Empty inputs
# ---------------------------------------------------------------------------


class TestResponseRecorderEmpty:
    def test_no_upstream(self, plugin: DetectionResponseRecorder) -> None:
        result = plugin.execute({})
        assert result.success is False
        assert result.metadata.get("contract_status") == "PARTIAL"
        assert result.metadata.get("mode") == "no-input"

    def test_upstream_without_mitre(self, plugin: DetectionResponseRecorder) -> None:
        upstream = [
            {"finding_type": "open_port", "target": "10.0.0.1", "metadata": {"port": 80}},
        ]
        result = plugin.execute({"upstream_findings": upstream})
        matrix = [f for f in result.findings if f["finding_type"] == "detection_response_matrix"]
        assert matrix[0]["metadata"]["total_techniques_with_findings"] == 0


# ---------------------------------------------------------------------------
# Blind spots
# ---------------------------------------------------------------------------


class TestBlindSpots:
    def test_finding_without_coverage(self, plugin: DetectionResponseRecorder) -> None:
        upstream = [
            {
                "finding_type": "vuln",
                "target": "10.0.0.1",
                "mitre_technique": "T1190",
                "metadata": {},
            },
        ]
        result = plugin.execute({"upstream_findings": upstream})
        blind = [f for f in result.findings if f["finding_type"] == "detection_blind_spot"]
        assert len(blind) == 1
        assert blind[0]["metadata"]["technique_id"] == "T1190"
        assert blind[0]["severity"] == "high"

    def test_multiple_blind_spots(self, plugin: DetectionResponseRecorder) -> None:
        upstream = [
            {"finding_type": "vuln", "target": "h1", "mitre_technique": "T1190", "metadata": {}},
            {"finding_type": "vuln", "target": "h1", "mitre_technique": "T1059", "metadata": {}},
        ]
        result = plugin.execute({"upstream_findings": upstream})
        blind = [f for f in result.findings if f["finding_type"] == "detection_blind_spot"]
        assert len(blind) == 2


# ---------------------------------------------------------------------------
# Effective detections
# ---------------------------------------------------------------------------


class TestEffectiveDetection:
    def _make_context(self, techniques_with_findings, detected_techniques):
        upstream = [
            {"finding_type": "vuln", "target": "10.0.0.1", "mitre_technique": t, "metadata": {}}
            for t in techniques_with_findings
        ]
        upstream_plugins = {
            "detection-coverage": {
                "findings": [
                    {
                        "finding_type": "detection_coverage",
                        "metadata": {"detected_techniques": list(detected_techniques)},
                    }
                ]
            }
        }
        return {"upstream_findings": upstream, "upstream_plugins": upstream_plugins}

    def test_technique_detected_is_effective(self, plugin: DetectionResponseRecorder) -> None:
        ctx = self._make_context(["T1190"], ["T1190"])
        result = plugin.execute(ctx)
        effective = [f for f in result.findings if f["finding_type"] == "detection_effective"]
        assert len(effective) == 1
        assert effective[0]["metadata"]["technique_id"] == "T1190"

    def test_mixed_effective_and_blind(self, plugin: DetectionResponseRecorder) -> None:
        ctx = self._make_context(["T1190", "T1059"], ["T1190"])
        result = plugin.execute(ctx)
        effective = [f for f in result.findings if f["finding_type"] == "detection_effective"]
        blind = [f for f in result.findings if f["finding_type"] == "detection_blind_spot"]
        assert len(effective) == 1
        assert len(blind) == 1

    def test_matrix_counts(self, plugin: DetectionResponseRecorder) -> None:
        ctx = self._make_context(["T1190", "T1059", "T1078"], ["T1190", "T1078"])
        result = plugin.execute(ctx)
        matrix = [f for f in result.findings if f["finding_type"] == "detection_response_matrix"]
        assert len(matrix) == 1
        m = matrix[0]["metadata"]
        assert m["effective_count"] == 2
        assert m["blind_spot_count"] == 1
        assert m["total_techniques_with_findings"] == 3
        assert m["effectiveness_percent"] == pytest.approx(66.7, abs=0.1)


# ---------------------------------------------------------------------------
# Multiple findings per technique
# ---------------------------------------------------------------------------


class TestMultipleFindingsPerTechnique:
    def test_deduplication_by_technique(self, plugin: DetectionResponseRecorder) -> None:
        """Multiple findings with the same technique → one entry in matrix."""
        upstream = [
            {"finding_type": "vuln-a", "target": "h1", "mitre_technique": "T1190", "metadata": {}},
            {"finding_type": "vuln-b", "target": "h1", "mitre_technique": "T1190", "metadata": {}},
        ]
        result = plugin.execute({"upstream_findings": upstream})
        blind = [f for f in result.findings if f["finding_type"] == "detection_blind_spot"]
        assert len(blind) == 1
        assert blind[0]["metadata"]["finding_count"] == 2


# ---------------------------------------------------------------------------
# Dry-run
# ---------------------------------------------------------------------------


class TestResponseRecorderDryRun:
    def test_dry_run_succeeds(self, plugin: DetectionResponseRecorder) -> None:
        result = plugin.dry_run({})
        assert result.success
        assert result.metadata.get("mode") == "dry-run"
