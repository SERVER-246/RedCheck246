"""Tests for redcheck.plugins.detection.coverage_validator.

Covers:
- MITRE technique catalog completeness
- Traffic marker generation (deterministic, prefix, uniqueness)
- CoverageResult computation (full, partial, empty, zero-division)
- DetectionCoverageValidator plugin (offline mode, with pre-detected, dry-run)
- No evasion logic (static analysis check)
"""

from __future__ import annotations

from typing import Any

from redcheck.plugins.detection.coverage_validator import (
    MITRE_TECHNIQUE_CATALOG,
    DetectionCoverageValidator,
    compute_coverage,
    generate_all_markers,
    generate_traffic_marker,
    technique_ids,
)

# =====================================================================
# Technique Catalog
# =====================================================================


class TestMITRETechniqueCatalog:
    """Verify the MITRE technique catalog is complete and well-formed."""

    def test_catalog_has_at_least_18_techniques(self) -> None:
        assert len(MITRE_TECHNIQUE_CATALOG) >= 18

    def test_all_entries_have_required_keys(self) -> None:
        for tid, info in MITRE_TECHNIQUE_CATALOG.items():
            assert "name" in info, f"{tid} missing 'name'"
            assert "tactic" in info, f"{tid} missing 'tactic'"
            assert "plugin" in info, f"{tid} missing 'plugin'"

    def test_technique_ids_returns_frozenset(self) -> None:
        ids = technique_ids()
        assert isinstance(ids, frozenset)
        assert len(ids) == len(MITRE_TECHNIQUE_CATALOG)

    def test_expected_techniques_present(self) -> None:
        ids = technique_ids()
        expected = {
            "T1046",
            "T1595.001",
            "T1596",
            "T1593",
            "T1190",
            "T1595.002",
            "T1078",
            "T1078.003",
            "T1059",
            "T1110.002",
            "T1203",
            "T1562.001",
            "T1562.006",
            "T1596.003",
            "T1583.001",
            "T1499",
            "T1195.002",
        }
        assert expected.issubset(ids)

    def test_catalog_values_are_non_empty_strings(self) -> None:
        for tid, info in MITRE_TECHNIQUE_CATALOG.items():
            assert isinstance(tid, str)
            assert tid.startswith("T")
            assert isinstance(info["name"], str)
            assert len(info["name"]) > 0
            assert isinstance(info["tactic"], str)
            assert len(info["tactic"]) > 0


# =====================================================================
# Traffic Marker Generation
# =====================================================================


class TestTrafficMarkerGeneration:
    """Verify deterministic, benign traffic marker generation."""

    def test_marker_has_prefix(self) -> None:
        marker = generate_traffic_marker("T1046")
        assert marker.startswith("REDCHECK-DET-")

    def test_marker_deterministic(self) -> None:
        m1 = generate_traffic_marker("T1046", seed="test")
        m2 = generate_traffic_marker("T1046", seed="test")
        assert m1 == m2

    def test_different_techniques_produce_different_markers(self) -> None:
        m1 = generate_traffic_marker("T1046")
        m2 = generate_traffic_marker("T1190")
        assert m1 != m2

    def test_different_seeds_produce_different_markers(self) -> None:
        m1 = generate_traffic_marker("T1046", seed="alpha")
        m2 = generate_traffic_marker("T1046", seed="beta")
        assert m1 != m2

    def test_generate_all_markers_count(self) -> None:
        markers = generate_all_markers()
        assert len(markers) == len(MITRE_TECHNIQUE_CATALOG)

    def test_generate_all_markers_scoped(self) -> None:
        scope = frozenset({"T1046", "T1190"})
        markers = generate_all_markers(scope)
        assert len(markers) == 2
        assert "T1046" in markers
        assert "T1190" in markers

    def test_all_markers_deterministic(self) -> None:
        """Same scope + seed → same markers on 3 runs."""
        scope = frozenset({"T1046", "T1190", "T1078"})
        results = [generate_all_markers(scope, seed="fixed") for _ in range(3)]
        assert results[0] == results[1] == results[2]


# =====================================================================
# Coverage Computation
# =====================================================================


class TestCoverageComputation:
    """Verify coverage percentage and list accuracy."""

    def test_full_coverage(self) -> None:
        all_ids = technique_ids()
        result = compute_coverage(set(all_ids))
        assert result.coverage_percentage == 100.0
        assert len(result.undetected_techniques) == 0

    def test_zero_coverage(self) -> None:
        result = compute_coverage(set())
        assert result.coverage_percentage == 0.0
        assert len(result.detected_techniques) == 0
        assert result.total_techniques == len(MITRE_TECHNIQUE_CATALOG)

    def test_partial_coverage_75_percent(self) -> None:
        """15 of 20 detected → 75.0% (DoD criterion)."""
        scope = frozenset(sorted(technique_ids())[:20])
        detected = set(sorted(scope)[:15])
        result = compute_coverage(detected, scope=scope)
        assert result.coverage_percentage == 75.0
        assert len(result.detected_techniques) == 15
        assert len(result.undetected_techniques) == 5

    def test_uncovered_list_accuracy(self) -> None:
        """Uncovered list matches exactly the techniques NOT detected."""
        scope = frozenset({"T1046", "T1190", "T1078", "T1059"})
        detected = {"T1046", "T1078"}
        result = compute_coverage(detected, scope=scope)
        assert set(result.undetected_techniques) == {"T1190", "T1059"}
        assert set(result.detected_techniques) == {"T1046", "T1078"}

    def test_per_technique_map(self) -> None:
        scope = frozenset({"T1046", "T1190"})
        detected = {"T1046"}
        result = compute_coverage(detected, scope=scope)
        assert result.per_technique["T1046"] is True
        assert result.per_technique["T1190"] is False

    def test_empty_scope(self) -> None:
        result = compute_coverage(set(), scope=frozenset())
        assert result.coverage_percentage == 0.0
        assert result.total_techniques == 0

    def test_to_dict_structure(self) -> None:
        result = compute_coverage({"T1046"}, scope=frozenset({"T1046", "T1190"}))
        d = result.to_dict()
        assert d["total_techniques"] == 2
        assert d["detected_count"] == 1
        assert d["undetected_count"] == 1
        assert d["coverage_percentage"] == 50.0
        assert "per_technique" in d


# =====================================================================
# DetectionCoverageValidator Plugin
# =====================================================================


class TestDetectionCoverageValidatorPlugin:
    """Verify the plugin execution in offline mode."""

    def _make_context(self, **overrides: Any) -> dict[str, Any]:
        ctx: dict[str, Any] = {
            "engagement_id": "test-engagement",
            "targets": ["10.0.0.1"],
        }
        ctx.update(overrides)
        return ctx

    def test_plugin_metadata(self) -> None:
        p = DetectionCoverageValidator()
        assert p.name == "detection-coverage"
        assert p.version == "0.1.0"
        assert p.category == "detection"
        assert p.capability.value == "active"
        assert "allow_auth_testing" in p.required_controls
        assert p.timeout_seconds == 180
        assert p.mitre_techniques == ["T1562.001"]

    def test_offline_zero_detected(self) -> None:
        """No detected_techniques → 0% coverage."""
        p = DetectionCoverageValidator()
        ctx = self._make_context()
        result = p.execute(ctx)
        assert result.success is True
        assert result.metadata["coverage_percentage"] == 0.0
        assert result.metadata["undetected_count"] == result.metadata["total_techniques"]

    def test_offline_partial_detected(self) -> None:
        """Pre-populated detected_techniques in context."""
        p = DetectionCoverageValidator()
        ctx = self._make_context(detected_techniques=["T1046", "T1190", "T1078"])
        result = p.execute(ctx)
        assert result.success is True
        assert result.metadata["detected_count"] == 3
        assert result.metadata["coverage_percentage"] > 0.0

    def test_offline_full_coverage(self) -> None:
        """All techniques detected."""
        p = DetectionCoverageValidator()
        all_ids = list(technique_ids())
        ctx = self._make_context(detected_techniques=all_ids)
        result = p.execute(ctx)
        assert result.metadata["coverage_percentage"] == 100.0
        assert result.metadata["undetected_count"] == 0

    def test_custom_scope(self) -> None:
        """Custom detection_scope limits the technique catalog."""
        p = DetectionCoverageValidator()
        ctx = self._make_context(
            detection_scope=["T1046", "T1190"],
            detected_techniques=["T1046"],
        )
        result = p.execute(ctx)
        assert result.metadata["total_techniques"] == 2
        assert result.metadata["detected_count"] == 1
        assert result.metadata["coverage_percentage"] == 50.0

    def test_deterministic_output(self) -> None:
        """Same input → same output on 3 runs (DoD criterion)."""
        p = DetectionCoverageValidator()
        ctx = self._make_context(
            detection_scope=["T1046", "T1190", "T1078"],
            detected_techniques=["T1046"],
            detection_seed="fixed-seed",
        )
        results = [p.execute(ctx) for _ in range(3)]
        coverages = [r.metadata["coverage_percentage"] for r in results]
        assert coverages[0] == coverages[1] == coverages[2]

    def test_findings_include_gaps(self) -> None:
        """Uncovered techniques produce detection_gap findings."""
        p = DetectionCoverageValidator()
        ctx = self._make_context(
            detection_scope=["T1046", "T1190"],
            detected_techniques=["T1046"],
        )
        result = p.execute(ctx)
        gap_findings = [f for f in result.findings if f["finding_type"] == "detection_gap"]
        assert len(gap_findings) == 1
        assert gap_findings[0]["technique_id"] == "T1190"

    def test_severity_high_below_50_percent(self) -> None:
        """Coverage below 50% → high severity finding."""
        p = DetectionCoverageValidator()
        ctx = self._make_context(
            detection_scope=["T1046", "T1190", "T1078", "T1059"],
            detected_techniques=["T1046"],  # 25%
        )
        result = p.execute(ctx)
        cov_finding = next(f for f in result.findings if f["finding_type"] == "detection_coverage")
        assert cov_finding["severity"] == "high"

    def test_severity_info_above_50_percent(self) -> None:
        """Coverage above 50% → info severity finding."""
        p = DetectionCoverageValidator()
        ctx = self._make_context(
            detection_scope=["T1046", "T1190"],
            detected_techniques=["T1046", "T1190"],
        )
        result = p.execute(ctx)
        cov_finding = next(f for f in result.findings if f["finding_type"] == "detection_coverage")
        assert cov_finding["severity"] == "info"

    def test_dry_run(self) -> None:
        p = DetectionCoverageValidator()
        ctx = self._make_context()
        result = p.dry_run(ctx)
        assert result.success is True
        assert result.metadata.get("mode") == "dry-run"


# =====================================================================
# No Evasion Logic (Static Analysis)
# =====================================================================


class TestNoEvasionLogic:
    """Ensure no evasion techniques exist in the coverage validator."""

    def test_no_encoding_functions(self) -> None:
        """No base64, URL encoding morphing, or obfuscation in module."""
        import inspect

        import redcheck.plugins.detection.coverage_validator as mod

        source = inspect.getsource(mod)
        # These would indicate evasion techniques
        evasion_patterns = [
            "base64.b64encode",
            "base64.b64decode",
            "rot13",
            "xor_encrypt",
            "payload_morph",
            "encoding_bypass",
            "obfuscate",
        ]
        for pattern in evasion_patterns:
            assert pattern not in source, f"Evasion pattern found: {pattern}"
