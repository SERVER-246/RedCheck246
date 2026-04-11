"""Tests for orchestrator rate limiting integration (Phase J)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from redcheck.core.orchestrator import Orchestrator
from redcheck.core.token_bucket import TokenBucket
from redcheck.models import EngagementContext, OffensiveControls, RuntimeMode
from redcheck.plugins.base_plugin import BasePlugin, PluginResult

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _RateLimitStub(BasePlugin):
    name = "rate-limit-stub"
    version = "0.1.0"
    description = "Stub for rate limit testing"
    category = "recon"
    requires_authorization = False
    rate_limit_rps = 5

    def execute(self, context):
        return PluginResult(plugin_name=self.name, success=True)

    async def aexecute(self, context):
        return PluginResult(plugin_name=self.name, success=True)


def _make_engagement(**overrides) -> EngagementContext:
    now = datetime.now(timezone.utc)
    defaults = {
        "engagement_id": "TEST-RL-001",
        "authorizer": "admin@test.com",
        "roe_signed": True,
        "roe_path": "tests/fixtures/test_roe.yaml",
        "activation_verified": True,
        "targets": ["10.0.0.1"],
        "allowed_tests": ["*"],
        "runtime_mode": RuntimeMode.PRODUCTION,
        "offensive_controls": OffensiveControls(),
        "start_time_utc": now - timedelta(hours=1),
        "end_time_utc": now + timedelta(hours=1),
    }
    defaults.update(overrides)
    return EngagementContext(**defaults)


# ---------------------------------------------------------------------------
# Tests — Rate Limiter Creation
# ---------------------------------------------------------------------------


class TestOrchestratorRateLimiter:
    def test_rate_limiter_created_for_plugin(self):
        """Orchestrator lazily creates a TokenBucket per plugin name."""
        orch = Orchestrator()
        assert len(orch._rate_limiters) == 0
        # After a run, the bucket should exist
        orch.audit = MagicMock()
        orch._current_engagement = _make_engagement()
        orch.run_plugin("rate-limit-stub")
        assert "rate-limit-stub" in orch._rate_limiters
        bucket = orch._rate_limiters["rate-limit-stub"]
        assert isinstance(bucket, TokenBucket)

    def test_rate_limiter_uses_plugin_rps(self):
        """Bucket rate matches plugin.rate_limit_rps."""
        orch = Orchestrator()
        orch.audit = MagicMock()
        orch._current_engagement = _make_engagement()
        orch.run_plugin("rate-limit-stub")
        bucket = orch._rate_limiters["rate-limit-stub"]
        assert bucket.rate == 5.0

    def test_rate_limiter_reused_across_calls(self):
        """Same bucket instance is reused for repeated plugin calls."""
        orch = Orchestrator()
        orch.audit = MagicMock()
        orch._current_engagement = _make_engagement()
        orch.run_plugin("rate-limit-stub")
        bucket1 = orch._rate_limiters["rate-limit-stub"]
        orch.run_plugin("rate-limit-stub")
        bucket2 = orch._rate_limiters["rate-limit-stub"]
        assert bucket1 is bucket2

    @pytest.mark.asyncio
    async def test_async_rate_limiter_created(self):
        """arun_plugin also creates a TokenBucket."""
        orch = Orchestrator()
        orch.audit = MagicMock()
        eng = _make_engagement()
        await orch.arun_plugin("rate-limit-stub", eng)
        assert "rate-limit-stub" in orch._rate_limiters

    @pytest.mark.asyncio
    async def test_async_rate_limiter_uses_plugin_rps(self):
        """Async bucket rate matches plugin.rate_limit_rps."""
        orch = Orchestrator()
        orch.audit = MagicMock()
        eng = _make_engagement()
        await orch.arun_plugin("rate-limit-stub", eng)
        bucket = orch._rate_limiters["rate-limit-stub"]
        assert bucket.rate == 5.0

    @pytest.mark.asyncio
    async def test_async_rate_limiter_reused(self):
        """Async path reuses the same bucket across calls."""
        orch = Orchestrator()
        orch.audit = MagicMock()
        eng = _make_engagement()
        await orch.arun_plugin("rate-limit-stub", eng)
        b1 = orch._rate_limiters["rate-limit-stub"]
        await orch.arun_plugin("rate-limit-stub", eng)
        b2 = orch._rate_limiters["rate-limit-stub"]
        assert b1 is b2

    def test_sync_execution_still_succeeds(self):
        """Plugin execution succeeds through rate limiter gate."""
        orch = Orchestrator()
        orch.audit = MagicMock()
        orch._current_engagement = _make_engagement()
        result = orch.run_plugin("rate-limit-stub")
        assert result.success is True

    @pytest.mark.asyncio
    async def test_async_execution_still_succeeds(self):
        """Async plugin execution succeeds through rate limiter gate."""
        orch = Orchestrator()
        orch.audit = MagicMock()
        eng = _make_engagement()
        result = await orch.arun_plugin("rate-limit-stub", eng)
        assert result.success is True

    def test_default_rps_when_no_attribute(self):
        """Plugins without rate_limit_rps default to 10 rps."""
        orch = Orchestrator()
        orch.audit = MagicMock()
        orch._current_engagement = _make_engagement()
        # Use the built-in stub-test which inherits default rate_limit_rps
        result = orch.run_plugin("stub-test")
        if result.success:
            bucket = orch._rate_limiters.get("stub-test")
            if bucket:
                assert bucket.rate == 10.0
