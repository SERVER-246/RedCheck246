"""Tests for redcheck.core.state_manager (Phase K)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from redcheck.core.state_manager import ExecutionStateManager
from redcheck.models import ExecutionState, PluginExecutionStatus


@pytest.fixture
def state_dir(tmp_path: Path) -> Path:
    d = tmp_path / "state"
    d.mkdir()
    return d


@pytest.fixture
def manager(state_dir: Path) -> ExecutionStateManager:
    return ExecutionStateManager(state_dir)


def _make_state(
    engagement_id: str = "eng-1",
    run_id: str | None = None,
    plugins: list[str] | None = None,
) -> ExecutionState:
    plugins = plugins or ["passive-recon", "network-scanner"]
    return ExecutionState(
        engagement_id=engagement_id,
        run_id=run_id or ExecutionStateManager.new_run_id(),
        started_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
        plugin_states=dict.fromkeys(plugins, PluginExecutionStatus.PENDING),
    )


class TestNewRunId:
    def test_returns_hex_string(self):
        rid = ExecutionStateManager.new_run_id()
        assert isinstance(rid, str)
        assert len(rid) == 32
        int(rid, 16)  # should not raise


class TestSaveLoadCheckpoint:
    def test_round_trip(self, manager: ExecutionStateManager):
        state = _make_state()
        manager.save_checkpoint(state)
        loaded = manager.load_checkpoint(state.run_id)
        assert loaded is not None
        assert loaded.run_id == state.run_id
        assert loaded.engagement_id == state.engagement_id

    def test_load_missing_returns_none(self, manager: ExecutionStateManager):
        assert manager.load_checkpoint("nonexistent") is None


class TestMarkPlugin:
    def test_mark_completed(self, manager: ExecutionStateManager):
        state = _make_state()
        manager.mark_plugin(state, "passive-recon", PluginExecutionStatus.COMPLETED)
        assert state.plugin_states["passive-recon"] == PluginExecutionStatus.COMPLETED
        assert "passive-recon" in state.completed_plugins

    def test_mark_failed(self, manager: ExecutionStateManager):
        state = _make_state()
        manager.mark_plugin(state, "passive-recon", PluginExecutionStatus.FAILED)
        assert "passive-recon" in state.failed_plugins

    def test_mark_skipped(self, manager: ExecutionStateManager):
        state = _make_state()
        manager.mark_plugin(state, "passive-recon", PluginExecutionStatus.SKIPPED)
        assert "passive-recon" in state.skipped_plugins


class TestResumeFrom:
    def test_returns_pending_and_failed(self, manager: ExecutionStateManager):
        state = _make_state(plugins=["a", "b", "c"])
        manager.mark_plugin(state, "a", PluginExecutionStatus.COMPLETED)
        manager.mark_plugin(state, "b", PluginExecutionStatus.FAILED)
        remaining = manager.resume_from(state)
        assert "a" not in remaining
        assert "b" in remaining
        assert "c" in remaining


class TestListRuns:
    def test_lists_saved_runs(self, manager: ExecutionStateManager):
        s1 = _make_state()
        s2 = _make_state()
        manager.save_checkpoint(s1)
        manager.save_checkpoint(s2)
        runs = manager.list_runs(s1.engagement_id)
        run_ids = [r.run_id for r in runs]
        assert s1.run_id in run_ids
        assert s2.run_id in run_ids


class TestCompareRuns:
    def test_detects_status_changes(self, manager: ExecutionStateManager):
        s1 = _make_state(plugins=["a", "b"])
        s2 = _make_state(plugins=["a", "b"])
        manager.mark_plugin(s1, "a", PluginExecutionStatus.COMPLETED)
        manager.mark_plugin(s2, "a", PluginExecutionStatus.FAILED)
        diff = ExecutionStateManager.compare_runs(s1, s2)
        assert "a" in diff["status_changes"]
