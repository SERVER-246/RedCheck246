"""Tests for Pydantic v2 models — validation, serialization, edge cases."""

from datetime import datetime, timedelta, timezone

import pytest
import yaml

from redcheck.models import (
    EngagementContext,
    Finding,
    FindingSeverity,
    PluginCapability,
    PluginResult,
    RoEDocument,
    RuntimeMode,
    ScanReport,
    TargetSpec,
)


class TestEnums:
    """Enum value and membership tests."""

    def test_runtime_mode_values(self):
        assert RuntimeMode.DEV.value == "dev"
        assert RuntimeMode.PRODUCTION.value == "production"

    def test_plugin_capability_values(self):
        assert PluginCapability.PASSIVE.value == "passive"
        assert PluginCapability.ACTIVE.value == "active"
        assert PluginCapability.DESTRUCTIVE.value == "destructive"

    def test_finding_severity_values(self):
        assert FindingSeverity.CRITICAL.value == "critical"
        assert FindingSeverity.INFO.value == "info"


class TestTargetSpec:
    """TargetSpec model tests."""

    def test_minimal_target(self):
        t = TargetSpec(host="example.com")
        assert t.host == "example.com"
        assert t.ports == []
        assert t.protocols == ["https"]

    def test_full_target(self):
        t = TargetSpec(host="x.com", ports=[80, 443], protocols=["tcp", "udp"])
        assert len(t.ports) == 2


class TestFinding:
    """Finding model tests."""

    def test_minimal_finding(self):
        f = Finding(
            finding_type="xss",
            target="https://example.com",
            severity=FindingSeverity.HIGH,
            detail="Reflected XSS in search",
        )
        assert f.severity == FindingSeverity.HIGH

    def test_cvss_score_bounds(self):
        f = Finding(
            finding_type="test",
            target="t",
            severity=FindingSeverity.LOW,
            detail="d",
            cvss_score=9.8,
        )
        assert f.cvss_score == 9.8

    def test_invalid_cvss_score(self):
        with pytest.raises(Exception):  # noqa: B017, PT011
            Finding(
                finding_type="test",
                target="t",
                severity=FindingSeverity.LOW,
                detail="d",
                cvss_score=11.0,
            )


class TestPluginResult:
    """PluginResult model tests."""

    def test_empty_result(self):
        r = PluginResult(plugin_name="test", success=True)
        assert r.finding_count == 0
        assert r.critical_count == 0

    def test_finding_counts(self):
        findings = [
            Finding(finding_type="a", target="t", severity=FindingSeverity.CRITICAL, detail="x"),
            Finding(finding_type="b", target="t", severity=FindingSeverity.HIGH, detail="y"),
            Finding(finding_type="c", target="t", severity=FindingSeverity.CRITICAL, detail="z"),
        ]
        r = PluginResult(plugin_name="test", success=True, findings=findings)
        assert r.finding_count == 3
        assert r.critical_count == 2

    def test_serialization(self):
        r = PluginResult(plugin_name="ser", success=False, errors=["e1"])
        d = r.model_dump()
        assert d["plugin_name"] == "ser"
        assert d["success"] is False


class TestEngagementContext:
    """EngagementContext model tests."""

    def _make_ctx(self, **kwargs):
        now = datetime.now(timezone.utc)
        defaults = {
            "engagement_id": "CTX-001",
            "authorizer": "Admin",
            "targets": ["host1.com"],
            "allowed_tests": ["passive-recon"],
            "start_time_utc": now - timedelta(hours=1),
            "end_time_utc": now + timedelta(hours=1),
        }
        defaults.update(kwargs)
        return EngagementContext(**defaults)

    def test_valid_context(self):
        ctx = self._make_ctx()
        assert ctx.engagement_id == "CTX-001"
        assert ctx.is_within_window()

    def test_empty_targets_rejected(self):
        with pytest.raises(Exception):  # noqa: B017, PT011
            self._make_ctx(targets=[])

    def test_empty_allowed_tests_rejected(self):
        with pytest.raises(Exception):  # noqa: B017, PT011
            self._make_ctx(allowed_tests=[])

    def test_end_before_start_rejected(self):
        now = datetime.now(timezone.utc)
        with pytest.raises(Exception):  # noqa: B017, PT011
            self._make_ctx(
                start_time_utc=now + timedelta(hours=1),
                end_time_utc=now - timedelta(hours=1),
            )

    def test_empty_authorizer_rejected(self):
        with pytest.raises(Exception):  # noqa: B017, PT011
            self._make_ctx(authorizer="  ")

    def test_is_expired(self):
        now = datetime.now(timezone.utc)
        ctx = self._make_ctx(
            start_time_utc=now - timedelta(days=2),
            end_time_utc=now - timedelta(days=1),
        )
        assert ctx.is_expired()

    def test_from_roe_yaml(self, tmp_path):
        now = datetime.now(timezone.utc)
        roe = {
            "engagement_id": "YAML-001",
            "authorizer": "Tester",
            "authorized_targets": ["host.local"],
            "allowed_tests": ["sast-scanner"],
            "start_time_utc": (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "end_time_utc": (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        p = tmp_path / "roe.yaml"
        with open(p, "w") as f:
            yaml.dump(roe, f)
        ctx = EngagementContext.from_roe_yaml(p)
        assert ctx.engagement_id == "YAML-001"


class TestRoEDocument:
    """RoEDocument model tests."""

    def _make_roe(self, **kwargs):
        now = datetime.now(timezone.utc)
        defaults = {
            "engagement_id": "ROE-001",
            "authorizer": "Admin",
            "authorized_targets": ["host.com"],
            "allowed_tests": ["passive-recon"],
            "start_time_utc": now - timedelta(hours=1),
            "end_time_utc": now + timedelta(hours=1),
        }
        defaults.update(kwargs)
        return RoEDocument(**defaults)

    def test_valid_roe(self):
        roe = self._make_roe()
        assert roe.is_active()
        assert not roe.is_expired()

    def test_time_remaining(self):
        roe = self._make_roe()
        assert roe.time_remaining_seconds() > 0

    def test_expired_roe(self):
        now = datetime.now(timezone.utc)
        roe = self._make_roe(
            start_time_utc=now - timedelta(days=2),
            end_time_utc=now - timedelta(days=1),
        )
        assert roe.is_expired()
        assert not roe.is_active()


class TestScanReport:
    """ScanReport model tests."""

    def test_duration(self):
        now = datetime.now(timezone.utc)
        report = ScanReport(
            engagement_id="R-001",
            scanner="test",
            start_time=now,
            end_time=now + timedelta(seconds=42),
        )
        assert report.duration_seconds == pytest.approx(42.0)

    def test_severity_counts(self):
        findings = [
            Finding(finding_type="a", target="t", severity=FindingSeverity.HIGH, detail="x"),
            Finding(finding_type="b", target="t", severity=FindingSeverity.HIGH, detail="y"),
            Finding(finding_type="c", target="t", severity=FindingSeverity.LOW, detail="z"),
        ]
        now = datetime.now(timezone.utc)
        report = ScanReport(
            engagement_id="R-002",
            scanner="test",
            start_time=now,
            end_time=now + timedelta(seconds=1),
            findings=findings,
        )
        counts = report.severity_counts
        assert counts["high"] == 2
        assert counts["low"] == 1
