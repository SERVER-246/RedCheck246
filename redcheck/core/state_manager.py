"""RedCheck246 — Execution State Manager.

Persists pipeline execution state to disk after each plugin completes.
Supports checkpoint, resume, run listing, and run comparison.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from redcheck.models import ExecutionState, PluginExecutionStatus

log = structlog.get_logger(__name__)


class ExecutionStateManager:
    """Manage persistent execution state with atomic disk writes."""

    def __init__(self, state_dir: str | Path) -> None:
        self._state_dir = Path(state_dir)
        self._state_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def new_run_id() -> str:
        """Generate a new unique run ID."""
        return uuid.uuid4().hex

    def _state_path(self, run_id: str) -> Path:
        return self._state_dir / f"state_{run_id}.json"

    def save_checkpoint(self, state: ExecutionState) -> Path:
        """Persist state atomically (write to .tmp then rename)."""
        state.updated_at = datetime.now(timezone.utc)
        path = self._state_path(state.run_id)
        tmp_path = path.with_suffix(".tmp")
        data = state.model_dump(mode="json")
        tmp_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        # Atomic rename (on Windows this replaces if target exists on Python 3.12+;
        # for older Pythons we remove first).
        if path.exists():
            path.unlink()
        os.rename(str(tmp_path), str(path))
        log.debug(
            "checkpoint_saved",
            run_id=state.run_id,
            completed=len(state.completed_plugins),
        )
        return path

    def load_checkpoint(self, run_id: str) -> ExecutionState | None:
        """Load a checkpoint from disk. Returns None if not found."""
        path = self._state_path(run_id)
        if not path.exists():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return ExecutionState.model_validate(data)

    def resume_from(self, state: ExecutionState) -> list[str]:
        """Return plugin names that still need execution (PENDING or FAILED)."""
        resumable: list[str] = []
        for plugin_name, status in state.plugin_states.items():
            if status in (PluginExecutionStatus.PENDING, PluginExecutionStatus.FAILED):
                resumable.append(plugin_name)
        return resumable

    def mark_plugin(
        self,
        state: ExecutionState,
        plugin_name: str,
        status: PluginExecutionStatus,
        *,
        result_path: str | None = None,
    ) -> None:
        """Update a plugin's status within the execution state."""
        state.plugin_states[plugin_name] = status
        if status == PluginExecutionStatus.COMPLETED:
            if plugin_name not in state.completed_plugins:
                state.completed_plugins.append(plugin_name)
        elif status == PluginExecutionStatus.FAILED and plugin_name not in state.failed_plugins:
            state.failed_plugins.append(plugin_name)
        elif status == PluginExecutionStatus.SKIPPED and plugin_name not in state.skipped_plugins:
            state.skipped_plugins.append(plugin_name)
        if result_path:
            state.results_index[plugin_name] = result_path

    def list_runs(self, engagement_id: str | None = None) -> list[ExecutionState]:
        """List all saved runs, optionally filtered by engagement_id."""
        runs: list[ExecutionState] = []
        for path in sorted(self._state_dir.glob("state_*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                s = ExecutionState.model_validate(data)
                if engagement_id is None or s.engagement_id == engagement_id:
                    runs.append(s)
            except Exception:
                log.warning("state_load_failed", path=str(path), exc_info=True)
        return runs

    @staticmethod
    def compare_runs(run_a: ExecutionState, run_b: ExecutionState) -> dict[str, Any]:
        """Diff two runs — plugins added/removed, status changes."""
        a_plugins = set(run_a.plugin_states.keys())
        b_plugins = set(run_b.plugin_states.keys())

        status_changes: dict[str, dict[str, str]] = {}
        for plugin in a_plugins & b_plugins:
            sa = run_a.plugin_states[plugin].value
            sb = run_b.plugin_states[plugin].value
            if sa != sb:
                status_changes[plugin] = {"run_a": sa, "run_b": sb}

        return {
            "plugins_added": sorted(b_plugins - a_plugins),
            "plugins_removed": sorted(a_plugins - b_plugins),
            "status_changes": status_changes,
            "completed_delta": len(run_b.completed_plugins) - len(run_a.completed_plugins),
            "failed_delta": len(run_b.failed_plugins) - len(run_a.failed_plugins),
        }
