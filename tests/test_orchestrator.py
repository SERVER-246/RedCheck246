"""Tests for Orchestrator — engagement lifecycle and plugin dispatch."""

import pytest

from redcheck.core.orchestrator import Orchestrator
from redcheck.exceptions import PolicyDeniedException
from redcheck.plugins.base_plugin import BasePlugin, PluginResult

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _StubPlugin(BasePlugin):
    """A minimal plugin for orchestrator testing."""

    name = "stub-test"
    version = "1.0.0"
    requires_authorization = False

    def execute(self, context):
        return PluginResult(
            plugin_name=self.name,
            success=True,
            findings=[{"type": "info", "detail": "stub finding"}],
            metadata={"echo": context.get("engagement_id", "")},
        )


class _FailingPlugin(BasePlugin):
    """A plugin that raises on execute."""

    name = "fail-test"
    version = "1.0.0"
    requires_authorization = False

    def execute(self, context):
        raise RuntimeError("boom")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestOrchestrator:
    """Orchestrator lifecycle tests."""

    def test_load_valid_engagement(self, valid_roe_file):
        orch = Orchestrator()
        ctx = orch.load_engagement(valid_roe_file)
        assert ctx.engagement_id == "TEST-001"
        assert ctx.roe_validated is True
        assert orch.current_engagement is not None

    def test_load_invalid_roe_raises(self, tmp_path):
        orch = Orchestrator()
        fake = tmp_path / "bad.yaml"
        fake.write_text("engagement_id: BAD")
        with pytest.raises(PolicyDeniedException):
            orch.load_engagement(fake)

    def test_load_expired_roe_raises(self, expired_roe_file):
        orch = Orchestrator()
        with pytest.raises(PolicyDeniedException):
            orch.load_engagement(expired_roe_file)

    def test_load_missing_roe_raises(self):
        orch = Orchestrator()
        with pytest.raises(PolicyDeniedException):
            orch.load_engagement("/nonexistent/roe.yaml")

    def test_run_plugin_dry_run(self, valid_roe_file):
        orch = Orchestrator()
        orch.load_engagement(valid_roe_file)
        result = orch.run_plugin("stub-test", dry_run=True)
        assert result.success is True
        assert result.metadata.get("mode") == "dry-run"

    def test_run_nonexistent_plugin(self, valid_roe_file):
        orch = Orchestrator()
        orch.load_engagement(valid_roe_file)
        result = orch.run_plugin("does-not-exist")
        assert result.success is False
        assert any("not found" in e for e in result.errors)

    def test_run_plugin_records_duration(self, valid_roe_file):
        orch = Orchestrator()
        orch.load_engagement(valid_roe_file)
        result = orch.run_plugin("stub-test")
        assert "duration_ms" in result.metadata
        assert result.metadata["duration_ms"] >= 0

    def test_run_plugin_exception_handled(self, valid_roe_file):
        orch = Orchestrator()
        orch.load_engagement(valid_roe_file)
        result = orch.run_plugin("fail-test")
        assert result.success is False
        assert any("boom" in e for e in result.errors)

    def test_shutdown_clears_engagement(self, valid_roe_file):
        orch = Orchestrator()
        orch.load_engagement(valid_roe_file)
        assert orch.current_engagement is not None
        orch.shutdown()
        assert orch.current_engagement is None

    def test_activate_without_engagement(self):
        orch = Orchestrator()
        assert orch.activate("any-code") is False

    def test_engagement_context_to_dict(self, valid_roe_file):
        orch = Orchestrator()
        ctx = orch.load_engagement(valid_roe_file)
        d = ctx.to_dict()
        assert d["engagement_id"] == "TEST-001"
        assert isinstance(d["authorized_targets"], list)

    def test_engagement_context_from_roe_data(self):
        from redcheck.core.orchestrator import EngagementContext

        data = {
            "engagement_id": "FROM-ROE",
            "authorizer": "Admin",
            "authorized_targets": [{"host": "x.com"}],
            "allowed_tests": ["passive-recon"],
            "start_time_utc": "2025-01-01T00:00:00Z",
            "end_time_utc": "2025-12-31T23:59:59Z",
        }
        ctx = EngagementContext.from_roe(data)
        assert ctx.engagement_id == "FROM-ROE"
