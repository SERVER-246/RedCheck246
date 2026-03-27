"""Coverage tests for redcheck/models.py — uncovered lines."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import yaml

from redcheck.models import (
    EngagementContext,
    Evidence,
    Finding,
    PluginResult,
    RoEDocument,
)


class TestFindingDictAccess:
    def test_getitem_model_field(self):
        f = Finding(
            finding_type="xss",
            target="t",
            severity="high",
            detail="d",
        )
        assert f["severity"] == "high"

    def test_getitem_enum_value(self):
        f = Finding(
            finding_type="xss",
            target="t",
            severity="critical",
            detail="d",
        )
        # severity is FindingSeverity enum; __getitem__ returns .value string
        assert f["severity"] == "critical"

    def test_getitem_metadata_fallback(self):
        f = Finding(
            finding_type="xss",
            target="t",
            severity="info",
            detail="d",
            metadata={"custom_key": 42},
        )
        assert f["custom_key"] == 42

    def test_getitem_missing_raises(self):
        f = Finding(finding_type="xss", target="t", severity="info", detail="d")
        with pytest.raises(KeyError):
            f["nonexistent"]

    def test_contains_model_field(self):
        f = Finding(finding_type="xss", target="t", severity="info", detail="d")
        assert "severity" in f
        assert "finding_type" in f

    def test_contains_metadata_key(self):
        f = Finding(
            finding_type="xss",
            target="t",
            severity="info",
            detail="d",
            metadata={"foo": 1},
        )
        assert "foo" in f

    def test_contains_missing(self):
        f = Finding(finding_type="xss", target="t", severity="info", detail="d")
        assert "nonexistent" not in f


class TestPluginResultDictCoercion:
    def test_findings_dict_coerced(self):
        pr = PluginResult(
            plugin_name="test",
            success=True,
            findings=[
                {
                    "finding_type": "sqli",
                    "target": "host",
                    "severity": "high",
                    "detail": "injection found",
                }
            ],
        )
        assert len(pr.findings) == 1
        assert isinstance(pr.findings[0], Finding)
        assert pr.findings[0].finding_type == "sqli"

    def test_findings_dict_defaults(self):
        # Empty dict should get sensible defaults
        pr = PluginResult(
            plugin_name="test",
            success=True,
            findings=[{}],
        )
        assert pr.findings[0].finding_type == "unknown"
        assert pr.findings[0].severity.value == "info"

    def test_findings_invalid_severity_coerced(self):
        pr = PluginResult(
            plugin_name="test",
            success=True,
            findings=[{"severity": "BOGUS"}],
        )
        assert pr.findings[0].severity.value == "info"

    def test_evidence_dict_coerced(self):
        pr = PluginResult(
            plugin_name="test",
            success=True,
            evidence=[{"evidence_type": "screenshot", "path": "/tmp/a.png", "sha256": "abc"}],
        )
        assert len(pr.evidence) == 1
        assert isinstance(pr.evidence[0], Evidence)
        assert pr.evidence[0].evidence_type == "screenshot"

    def test_evidence_dict_defaults(self):
        pr = PluginResult(plugin_name="test", success=True, evidence=[{}])
        assert pr.evidence[0].evidence_type == "unknown"


class TestEngagementContextTimeMethods:
    def _make_ctx(self, *, start_offset_hours=-1, end_offset_hours=1):
        now = datetime.now(timezone.utc)
        return EngagementContext(
            engagement_id="e1",
            authorizer="admin",
            targets=["t"],
            allowed_tests=["recon"],
            start_time_utc=now + timedelta(hours=start_offset_hours),
            end_time_utc=now + timedelta(hours=end_offset_hours),
        )

    def test_is_within_window_active(self):
        ctx = self._make_ctx(start_offset_hours=-1, end_offset_hours=1)
        assert ctx.is_within_window() is True

    def test_is_within_window_expired(self):
        ctx = self._make_ctx(start_offset_hours=-3, end_offset_hours=-1)
        assert ctx.is_within_window() is False

    def test_is_expired_true(self):
        ctx = self._make_ctx(start_offset_hours=-3, end_offset_hours=-1)
        assert ctx.is_expired() is True

    def test_is_expired_false(self):
        ctx = self._make_ctx(start_offset_hours=-1, end_offset_hours=1)
        assert ctx.is_expired() is False

    def test_validate_time_window_invalid(self):
        now = datetime.now(timezone.utc)
        with pytest.raises(ValueError, match="end_time_utc must be after"):
            EngagementContext(
                engagement_id="e",
                authorizer="admin",
                targets=["t"],
                allowed_tests=["a"],
                start_time_utc=now + timedelta(hours=1),
                end_time_utc=now - timedelta(hours=1),
            )


class TestEngagementContextFromRoeYaml:
    def test_roundtrip(self, tmp_path):
        roe_data = {
            "engagement_id": "test-eng",
            "authorizer": "admin@test",
            "authorized_targets": ["192.168.1.1"],
            "allowed_tests": ["recon"],
            "start_time_utc": "2025-01-01T00:00:00Z",
            "end_time_utc": "2030-12-31T23:59:59Z",
        }
        p = tmp_path / "roe.yaml"
        p.write_text(yaml.dump(roe_data), encoding="utf-8")
        ctx = EngagementContext.from_roe_yaml(str(p))
        assert ctx.engagement_id == "test-eng"
        assert ctx.authorizer == "admin@test"
        assert "192.168.1.1" in ctx.targets

    def test_z_suffix_normalization(self, tmp_path):
        roe_data = {
            "authorizer": "admin",
            "authorized_targets": ["host"],
            "allowed_tests": ["recon"],
            "start_time_utc": "2025-06-01T00:00:00Z",
            "end_time_utc": "2030-12-31T23:59:59Z",
        }
        p = tmp_path / "roe.yaml"
        p.write_text(yaml.dump(roe_data), encoding="utf-8")
        ctx = EngagementContext.from_roe_yaml(str(p))
        assert ctx.start_time_utc.tzinfo is not None


class TestRoEDocument:
    def _make_roe(self, **overrides):
        now = datetime.now(timezone.utc)
        defaults = {
            "engagement_id": "e1",
            "authorizer": "admin",
            "authorized_targets": ["t1"],
            "allowed_tests": ["recon"],
            "start_time_utc": now - timedelta(hours=1),
            "end_time_utc": now + timedelta(hours=1),
        }
        defaults.update(overrides)
        return RoEDocument(**defaults)

    def test_valid_roe(self):
        roe = self._make_roe()
        assert roe.engagement_id == "e1"

    def test_authorizer_empty_raises(self):
        with pytest.raises(ValueError, match="authorizer must be a non-empty"):
            self._make_roe(authorizer="  ")

    def test_time_window_invalid_raises(self):
        now = datetime.now(timezone.utc)
        with pytest.raises(ValueError, match="end_time_utc must be after"):
            self._make_roe(
                start_time_utc=now + timedelta(hours=1),
                end_time_utc=now - timedelta(hours=1),
            )

    def test_is_expired_true(self):
        now = datetime.now(timezone.utc)
        roe = self._make_roe(
            start_time_utc=now - timedelta(hours=3),
            end_time_utc=now - timedelta(hours=1),
        )
        assert roe.is_expired() is True

    def test_is_expired_false(self):
        roe = self._make_roe()
        assert roe.is_expired() is False

    def test_is_active(self):
        roe = self._make_roe()
        assert roe.is_active() is True

    def test_is_active_expired(self):
        now = datetime.now(timezone.utc)
        roe = self._make_roe(
            start_time_utc=now - timedelta(hours=3),
            end_time_utc=now - timedelta(hours=1),
        )
        assert roe.is_active() is False

    def test_time_remaining_seconds_positive(self):
        roe = self._make_roe()
        assert roe.time_remaining_seconds() > 0

    def test_time_remaining_seconds_expired(self):
        now = datetime.now(timezone.utc)
        roe = self._make_roe(
            start_time_utc=now - timedelta(hours=3),
            end_time_utc=now - timedelta(hours=1),
        )
        assert roe.time_remaining_seconds() == 0.0
