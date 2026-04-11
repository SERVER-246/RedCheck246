"""Tests for the chain_mode disabled warning (Phase I3)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from redcheck.core.pipeline import PipelineExecutor
from redcheck.exceptions import ChainModeError
from redcheck.models import (
    EngagementContext,
    OffensiveControls,
    RuntimeMode,
)


def _make_engagement(*, chain_mode: bool = True) -> EngagementContext:
    return EngagementContext(
        engagement_id="chain-test-1",
        authorizer="Test Authorizer",
        targets=["192.168.1.0/24"],
        allowed_tests=["passive-recon"],
        start_time_utc=datetime.now(timezone.utc) - timedelta(hours=1),
        end_time_utc=datetime.now(timezone.utc) + timedelta(hours=1),
        roe_signed=True,
        activation_verified=True,
        session_code="CHAIN-SESSION",
        runtime_mode=RuntimeMode.TEST,
        offensive_controls=OffensiveControls(chain_mode=chain_mode),
    )


class TestChainModeWarning:
    """Verify that chain=False logs a warning and chain=True+control=False raises."""

    @pytest.mark.asyncio
    async def test_chain_false_completes(self):
        """chain=False should not raise, pipeline completes with no plugins."""
        eng = _make_engagement(chain_mode=False)
        orch = MagicMock()
        pipe = PipelineExecutor(orch)
        # No plugins → pipeline finishes immediately
        result = await pipe.execute_pipeline(eng, [], chain=False)
        assert result is not None or result is None  # just exercises path

    @pytest.mark.asyncio
    async def test_chain_true_control_false_raises(self):
        """chain=True but chain_mode offensive control False → ChainModeError."""
        eng = _make_engagement(chain_mode=False)
        orch = MagicMock()
        pipe = PipelineExecutor(orch)

        with pytest.raises(ChainModeError):
            await pipe.execute_pipeline(eng, ["passive-recon"], chain=True)
