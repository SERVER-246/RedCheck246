"""Tests for Orchestrator — engagement lifecycle and plugin dispatch."""

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from redcheck.core.orchestrator import Orchestrator, _is_capability_allowed
from redcheck.exceptions import (
    ActivationError,
    IsolationError,
    OffensiveControlError,
    PluginNotFoundError,
    PolicyDeniedException,
    RoEValidationError,
    ScanTimeoutError,
)
from redcheck.models import (
    EngagementContext,
    OffensiveControls,
    PluginCapability,
    RuntimeMode,
)
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
        from redcheck.core.orchestrator import _build_engagement_from_roe

        data = {
            "engagement_id": "FROM-ROE",
            "authorizer": "Admin",
            "authorized_targets": [{"host": "x.com"}],
            "allowed_tests": ["passive-recon"],
            "start_time_utc": "2025-01-01T00:00:00Z",
            "end_time_utc": "2025-12-31T23:59:59Z",
        }
        ctx = _build_engagement_from_roe(data, "/tmp/roe.yaml")
        assert ctx.engagement_id == "FROM-ROE"


# ---------------------------------------------------------------------------
# Capability matrix tests
# ---------------------------------------------------------------------------


class TestCapabilityMatrix:
    """RuntimeMode × PluginCapability enforcement matrix."""

    def test_dev_allows_passive(self):
        assert _is_capability_allowed(RuntimeMode.DEV, PluginCapability.PASSIVE) is True

    def test_dev_blocks_active(self):
        assert _is_capability_allowed(RuntimeMode.DEV, PluginCapability.ACTIVE) is False

    def test_dev_blocks_destructive(self):
        assert _is_capability_allowed(RuntimeMode.DEV, PluginCapability.DESTRUCTIVE) is False

    def test_staging_allows_active(self):
        assert _is_capability_allowed(RuntimeMode.STAGING, PluginCapability.ACTIVE) is True

    def test_staging_blocks_destructive(self):
        assert _is_capability_allowed(RuntimeMode.STAGING, PluginCapability.DESTRUCTIVE) is False

    def test_production_allows_all(self):
        for cap in PluginCapability:
            assert _is_capability_allowed(RuntimeMode.PRODUCTION, cap) is True

    def test_research_allows_passive_and_active(self):
        assert _is_capability_allowed(RuntimeMode.RESEARCH, PluginCapability.PASSIVE) is True
        assert _is_capability_allowed(RuntimeMode.RESEARCH, PluginCapability.ACTIVE) is True
        assert _is_capability_allowed(RuntimeMode.RESEARCH, PluginCapability.DESTRUCTIVE) is False


# ---------------------------------------------------------------------------
# Async enforcement (arun_plugin) tests
# ---------------------------------------------------------------------------


def _make_engagement(**kwargs) -> EngagementContext:
    """Helper to build a valid EngagementContext for async tests."""
    now = datetime.now(timezone.utc)
    defaults = {
        "engagement_id": "ASYNC-001",
        "authorizer": "Admin",
        "targets": ["testhost.local"],
        "allowed_tests": [
            "passive-recon", "stub-test", "active-test",
            "destructive-test", "async-stub", "slow-test",
        ],
        "start_time_utc": now - timedelta(hours=1),
        "end_time_utc": now + timedelta(hours=1),
        "roe_signed": True,
        "activation_verified": True,
        "runtime_mode": RuntimeMode.PRODUCTION,
    }
    defaults.update(kwargs)
    return EngagementContext(**defaults)


class _AsyncStubPlugin(BasePlugin):
    """An async-capable stub plugin."""

    name = "async-stub"
    version = "1.0.0"
    requires_authorization = False
    capability = PluginCapability.PASSIVE
    timeout_seconds = 5
    required_controls: list[str] = []
    requires_isolation = False

    def execute(self, context):
        return PluginResult(
            plugin_name=self.name,
            success=True,
            metadata={"mode": "sync"},
        )

    async def aexecute(self, context):
        await asyncio.sleep(0.01)
        return PluginResult(
            plugin_name=self.name,
            success=True,
            metadata={"mode": "async"},
        )


class _ActivePlugin(BasePlugin):
    """An ACTIVE-capability plugin that requires auth testing."""

    name = "active-test"
    version = "1.0.0"
    requires_authorization = True
    capability = PluginCapability.ACTIVE
    required_controls = ["allow_auth_testing"]
    timeout_seconds = 10
    requires_isolation = False

    def execute(self, context):
        return PluginResult(plugin_name=self.name, success=True)

    async def aexecute(self, context):
        return PluginResult(plugin_name=self.name, success=True)


class _DestructivePlugin(BasePlugin):
    """A DESTRUCTIVE-capability plugin requiring isolation."""

    name = "destructive-test"
    version = "1.0.0"
    requires_authorization = True
    capability = PluginCapability.DESTRUCTIVE
    required_controls = ["allow_exploit_validation"]
    timeout_seconds = 10
    requires_isolation = True

    def execute(self, context):
        return PluginResult(plugin_name=self.name, success=True)

    async def aexecute(self, context):
        return PluginResult(plugin_name=self.name, success=True)


class _SlowPlugin(BasePlugin):
    """A plugin that takes too long."""

    name = "slow-test"
    version = "1.0.0"
    requires_authorization = False
    capability = PluginCapability.PASSIVE
    timeout_seconds = 1
    required_controls: list[str] = []
    requires_isolation = False

    def execute(self, context):
        import time

        time.sleep(5)
        return PluginResult(plugin_name=self.name, success=True)

    async def aexecute(self, context):
        await asyncio.sleep(5)
        return PluginResult(plugin_name=self.name, success=True)


class TestAsyncEnforcement:
    """Tests for arun_plugin() 11-step enforcement sequence."""

    @pytest.mark.asyncio
    async def test_step1_plugin_not_found(self):
        orch = Orchestrator()
        ctx = _make_engagement()
        with pytest.raises(PluginNotFoundError):
            await orch.arun_plugin("nonexistent-plugin", ctx)

    @pytest.mark.asyncio
    async def test_step3_expired_engagement(self):
        orch = Orchestrator()
        now = datetime.now(timezone.utc)
        ctx = _make_engagement(
            start_time_utc=now - timedelta(days=2),
            end_time_utc=now - timedelta(days=1),
        )
        with pytest.raises(PolicyDeniedException, match="expired"):
            await orch.arun_plugin("async-stub", ctx)

    @pytest.mark.asyncio
    async def test_step4_roe_not_validated(self):
        orch = Orchestrator()
        ctx = _make_engagement(roe_signed=False, roe_path=None)
        with pytest.raises(RoEValidationError):
            await orch.arun_plugin("async-stub", ctx)

    @pytest.mark.asyncio
    async def test_step5_activation_not_verified(self):
        orch = Orchestrator()
        ctx = _make_engagement(activation_verified=False)
        with pytest.raises(ActivationError):
            await orch.arun_plugin("async-stub", ctx)

    @pytest.mark.asyncio
    async def test_step6_capability_mode_blocked(self):
        orch = Orchestrator()
        ctx = _make_engagement(runtime_mode=RuntimeMode.DEV)
        with pytest.raises(PolicyDeniedException, match="[Cc]apability"):
            await orch.arun_plugin("active-test", ctx)

    @pytest.mark.asyncio
    async def test_step7_offensive_controls_missing(self):
        orch = Orchestrator()
        ctx = _make_engagement(offensive_controls=OffensiveControls())
        with pytest.raises(OffensiveControlError):
            await orch.arun_plugin("active-test", ctx)

    @pytest.mark.asyncio
    async def test_step7_offensive_controls_present(self):
        orch = Orchestrator()
        oc = OffensiveControls(allow_auth_testing=True)
        ctx = _make_engagement(offensive_controls=oc)
        result = await orch.arun_plugin("active-test", ctx)
        assert result.success is True

    @pytest.mark.asyncio
    async def test_step8_isolation_missing(self):
        orch = Orchestrator()
        oc = OffensiveControls(allow_exploit_validation=True)
        ctx = _make_engagement(offensive_controls=oc)
        with pytest.raises(IsolationError):
            await orch.arun_plugin("destructive-test", ctx, isolation_available=False)

    @pytest.mark.asyncio
    async def test_step8_isolation_available(self):
        orch = Orchestrator()
        oc = OffensiveControls(allow_exploit_validation=True)
        ctx = _make_engagement(offensive_controls=oc)
        result = await orch.arun_plugin("destructive-test", ctx, isolation_available=True)
        assert result.success is True

    @pytest.mark.asyncio
    async def test_step10_dry_run(self):
        orch = Orchestrator()
        ctx = _make_engagement()
        result = await orch.arun_plugin("async-stub", ctx, dry_run=True)
        assert result.success is True
        assert result.metadata.get("mode") == "dry-run"

    @pytest.mark.asyncio
    async def test_step11_async_execution(self):
        orch = Orchestrator()
        ctx = _make_engagement()
        result = await orch.arun_plugin("async-stub", ctx)
        assert result.success is True
        assert result.metadata.get("mode") == "async"
        assert "duration_ms" in result.metadata

    @pytest.mark.asyncio
    async def test_step11_timeout_fires(self):
        orch = Orchestrator()
        ctx = _make_engagement()
        with pytest.raises(ScanTimeoutError):
            await orch.arun_plugin("slow-test", ctx)

    @pytest.mark.asyncio
    async def test_engagement_model_round_trip(self):
        ctx = _make_engagement()
        d = ctx.model_dump()
        ctx2 = EngagementContext(**d)
        assert ctx2.engagement_id == ctx.engagement_id

    @pytest.mark.asyncio
    async def test_full_happy_path(self):
        orch = Orchestrator()
        oc = OffensiveControls(allow_auth_testing=True)
        ctx = _make_engagement(
            offensive_controls=oc,
            runtime_mode=RuntimeMode.PRODUCTION,
        )
        result = await orch.arun_plugin("active-test", ctx)
        assert result.success is True
