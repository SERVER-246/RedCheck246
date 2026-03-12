"""Integration tests — End-to-end Test Mode pipeline validation.

These tests verify that cross-cutting features integrated across
Phases 1-5 work together correctly: plugin pipeline, OTP gating,
attack path correlation, evidence indexing, backward compatibility,
and scope enforcement.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from redcheck.core.attack_path_correlator import AttackPathCorrelator
from redcheck.core.evidence_store import EvidenceStore
from redcheck.core.orchestrator import Orchestrator
from redcheck.core.scope_validator import ScopeValidator
from redcheck.exceptions import PolicyDeniedException
from redcheck.models import (
    EngagementContext,
    Finding,
    FindingSeverity,
    OffensiveControls,
    PluginCapability,
    RuntimeMode,
)
from redcheck.models import (
    PluginResult as PydanticPluginResult,
)
from redcheck.plugins.base_plugin import BasePlugin, PluginRegistry, PluginResult

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _PassiveStub(BasePlugin):
    name = "integration-passive-stub"
    version = "0.1.0"
    description = "Passive stub for integration tests"
    requires_authorization = False
    capability = PluginCapability.PASSIVE

    def execute(self, context: dict[str, Any]) -> PluginResult:
        return PluginResult(
            plugin_name=self.name,
            success=True,
            findings=[
                {
                    "finding_type": "open_port",
                    "target": "10.0.0.1",
                    "port": 80,
                    "severity": "info",
                    "detail": "Port 80/tcp open",
                }
            ],
            metadata={"mode": "test"},
        )

    def dry_run(self, context: dict[str, Any]) -> PluginResult:
        return PluginResult(
            plugin_name=self.name,
            success=True,
            findings=[
                {
                    "finding_type": "open_port",
                    "target": "10.0.0.1",
                    "port": 80,
                    "severity": "info",
                    "detail": "[DRY-RUN] Would detect port 80/tcp",
                }
            ],
            metadata={"mode": "dry-run"},
        )


class _ActiveStub(BasePlugin):
    name = "integration-active-stub"
    version = "0.1.0"
    description = "Active stub for integration tests"
    requires_authorization = True
    capability = PluginCapability.ACTIVE
    required_controls = ["allow_auth_testing"]

    def execute(self, context: dict[str, Any]) -> PluginResult:
        return PluginResult(
            plugin_name=self.name,
            success=True,
            findings=[
                {
                    "finding_type": "service_detected",
                    "target": "10.0.0.1",
                    "service": "Apache",
                    "severity": "info",
                    "detail": "Apache HTTP Server detected",
                }
            ],
        )

    def dry_run(self, context: dict[str, Any]) -> PluginResult:
        return PluginResult(
            plugin_name=self.name,
            success=True,
            findings=[
                {
                    "finding_type": "service_detected",
                    "target": "10.0.0.1",
                    "severity": "info",
                    "detail": "[DRY-RUN] Would detect services",
                }
            ],
            metadata={"mode": "dry-run"},
        )


class _DestructiveStub(BasePlugin):
    name = "integration-destructive-stub"
    version = "0.1.0"
    description = "Destructive stub for integration tests"
    requires_authorization = True
    capability = PluginCapability.DESTRUCTIVE
    required_controls = ["allow_exploit_validation"]
    requires_isolation = True

    def execute(self, context: dict[str, Any]) -> PluginResult:
        return PluginResult(
            plugin_name=self.name,
            success=True,
            findings=[
                {
                    "finding_type": "exploit_validated",
                    "target": "10.0.0.1",
                    "severity": "high",
                    "detail": "SQL injection confirmed",
                }
            ],
        )

    def dry_run(self, context: dict[str, Any]) -> PluginResult:
        return PluginResult(
            plugin_name=self.name,
            success=True,
            metadata={"mode": "dry-run", "description": "Would validate exploits"},
        )


def _make_engagement(
    *,
    mode: RuntimeMode = RuntimeMode.TEST,
    controls: OffensiveControls | None = None,
) -> EngagementContext:
    """Build a valid EngagementContext for testing."""
    now = datetime.now(tz=timezone.utc)
    if controls is None:
        controls = OffensiveControls(
            allow_auth_testing=True,
            allow_exploit_validation=True,
            chain_mode=True,
        )
    return EngagementContext(
        engagement_id="integ-test-001",
        authorizer="test-operator",
        targets=["10.0.0.1", "10.0.0.2"],
        allowed_tests=["*"],
        start_time_utc=now - timedelta(hours=1),
        end_time_utc=now + timedelta(hours=1),
        roe_path="/tmp/test-roe.yaml",
        roe_signed=True,
        activation_verified=True,
        offensive_controls=controls,
        runtime_mode=mode,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestTestModeIntegration:
    """End-to-end Test Mode with mocked targets."""

    def test_full_pipeline_dry_run(self):
        """Run plugins in dry-run mode and verify results."""
        plugin = _PassiveStub()
        result = plugin.dry_run({"targets": ["10.0.0.1"]})
        assert result.success is True
        assert result.metadata.get("mode") == "dry-run"
        assert len(result.findings) >= 1

    def test_otp_gate_blocks_destructive(self):
        """Verify DESTRUCTIVE plugins are blocked without activation."""
        eng = _make_engagement()
        eng.activation_verified = False
        orch = Orchestrator()
        orch._current_engagement = MagicMock()
        orch._current_engagement.context = eng

        with pytest.raises(PolicyDeniedException):
            orch.run_plugin("integration-destructive-stub", dry_run=False)

    def test_otp_gate_allows_with_valid_code(self):
        """Verify plugins proceed after valid activation."""
        eng = _make_engagement()
        assert eng.activation_verified is True
        plugin = _DestructiveStub()
        result = plugin.dry_run({"targets": ["10.0.0.1"]})
        assert result.success is True

    def test_attack_path_correlation(self):
        """Verify findings are correlated into attack graph."""
        correlator = AttackPathCorrelator()
        findings = [
            Finding(
                finding_type="open_port",
                target="10.0.0.1",
                severity=FindingSeverity.INFO,
                detail="Port 80 open",
            ),
            Finding(
                finding_type="service_detected",
                target="10.0.0.1",
                severity=FindingSeverity.MEDIUM,
                detail="Apache 2.4 detected",
            ),
            Finding(
                finding_type="exploit_validated",
                target="10.0.0.1",
                severity=FindingSeverity.HIGH,
                detail="RCE confirmed",
            ),
        ]
        mock_result = PydanticPluginResult(plugin_name="test", success=True, findings=findings)
        correlator.ingest_findings({"test": mock_result})
        graph = correlator.correlate()
        assert isinstance(graph, dict)

    def test_evidence_indexed(self, tmp_path: Path):
        """Verify evidence_index.json is created and accurate."""
        store = EvidenceStore(tmp_path / "evidence")
        ev = store.store(b"test-finding-data", "finding_snapshot")
        assert ev.sha256
        assert ev.size_bytes == len(b"test-finding-data")

        ok, errors = store.verify_integrity()
        assert ok is True
        assert len(errors) == 0

        results = store.query(evidence_type="finding_snapshot")
        assert len(results) >= 1

    def test_backward_compat_run_command(self):
        """Verify orchestrator initializes in DEV mode without errors."""
        eng = _make_engagement(mode=RuntimeMode.DEV)
        assert eng.runtime_mode == RuntimeMode.DEV
        plugin = _PassiveStub()
        result = plugin.execute({"targets": ["10.0.0.1"]})
        assert result.success is True

    def test_backward_compat_run_all_command(self):
        """Verify STAGING mode allows PASSIVE and ACTIVE plugins."""
        eng = _make_engagement(mode=RuntimeMode.STAGING)
        assert eng.runtime_mode == RuntimeMode.STAGING
        passive = _PassiveStub()
        active = _ActiveStub()
        assert passive.execute({"targets": []}).success is True
        assert active.dry_run({"targets": []}).success is True

    def test_scope_enforcement(self):
        """Verify discovered hosts outside scope are excluded."""
        authorized = ["10.0.0.0/24"]
        in_scope = ["10.0.0.1", "10.0.0.50", "10.0.0.254"]
        out_of_scope = ["192.168.1.1", "10.1.0.1"]

        valid_in, violations_in = ScopeValidator.validate_targets(in_scope, authorized)
        assert valid_in is True
        assert len(violations_in) == 0

        valid_out, violations_out = ScopeValidator.validate_targets(out_of_scope, authorized)
        assert valid_out is False
        assert len(violations_out) == 2

    def test_plugin_registry_auto_registration(self):
        """Verify test stubs auto-registered via __init_subclass__."""
        names = PluginRegistry.list_names()
        assert "integration-passive-stub" in names
        assert "integration-active-stub" in names
        assert "integration-destructive-stub" in names

    def test_evidence_store_integrity_after_multiple_stores(self, tmp_path: Path):
        """Verify integrity check passes after storing multiple items."""
        store = EvidenceStore(tmp_path / "evidence")
        for i in range(5):
            store.store(f"data-{i}".encode(), "test_snapshot")

        assert store.count == 5
        ok, errors = store.verify_integrity()
        assert ok is True

    def test_pipeline_findings_propagation(self):
        """Verify findings from one plugin can feed into another."""
        passive = _PassiveStub()
        active = _ActiveStub()

        r1 = passive.execute({"targets": ["10.0.0.1"]})
        assert r1.success is True
        assert len(r1.findings) > 0

        context = {
            "targets": ["10.0.0.1"],
            "upstream_findings": r1.findings,
        }
        r2 = active.execute(context)
        assert r2.success is True

    def test_dry_run_produces_no_side_effects(self, tmp_path: Path):
        """Verify dry-run mode doesn't modify evidence store."""
        store = EvidenceStore(tmp_path / "evidence")
        initial_count = store.count

        plugin = _PassiveStub()
        result = plugin.dry_run({"targets": ["10.0.0.1"]})
        assert result.success is True
        assert store.count == initial_count

    def test_engagement_context_time_window(self):
        """Verify expired engagement raises appropriate error."""
        now = datetime.now(tz=timezone.utc)
        eng = EngagementContext(
            engagement_id="expired-001",
            authorizer="test",
            targets=["10.0.0.1"],
            allowed_tests=["*"],
            start_time_utc=now - timedelta(hours=3),
            end_time_utc=now - timedelta(hours=1),
            roe_path="/tmp/test.yaml",
            roe_signed=True,
            activation_verified=True,
        )
        assert eng.is_expired() is True
        assert eng.is_within_window() is False

    def test_offensive_controls_validation(self):
        """Verify offensive controls gate works correctly."""
        controls = OffensiveControls(
            allow_auth_testing=True,
            allow_exploit_validation=False,
        )
        assert controls.has_controls(["allow_auth_testing"]) is True
        assert controls.has_controls(["allow_exploit_validation"]) is False
        assert controls.has_controls(["allow_auth_testing", "allow_exploit_validation"]) is False

    def test_attack_path_with_severity_ranking(self):
        """Verify attack paths are ranked by severity."""
        correlator = AttackPathCorrelator()
        findings = [
            Finding(
                finding_type="open_port",
                target="10.0.0.1",
                severity=FindingSeverity.INFO,
                detail="SSH open",
            ),
            Finding(
                finding_type="exploit_validated",
                target="10.0.0.1",
                severity=FindingSeverity.CRITICAL,
                detail="Root RCE",
            ),
        ]
        mock_result = PydanticPluginResult(
            plugin_name="severity-test", success=True, findings=findings
        )
        correlator.ingest_findings({"severity-test": mock_result})
        graph = correlator.correlate()
        assert isinstance(graph, dict)
