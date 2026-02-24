"""Mutation-killing tests for ``redcheck.core.orchestrator``.

Every test asserts **exact** return values, message strings, audit calls,
and side effects.  Targets every surviving mutmut mutant.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from redcheck.core.orchestrator import (
    Orchestrator,
    _build_engagement_from_roe,
    _is_capability_allowed,
    _LegacyEngagementAdapter,
)
from redcheck.exceptions import (
    ActivationError,
    IsolationError,
    OffensiveControlError,
    PolicyDeniedException,
    RoEValidationError,
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


def _make_engagement(**kwargs) -> EngagementContext:
    now = datetime.now(timezone.utc)
    defaults = {
        "engagement_id": "ENG-MUT",
        "authorizer": "admin@test.com",
        "targets": ["10.0.0.1"],
        "allowed_tests": ["recon", "stub-test", "async-stub", "active-test"],
        "start_time_utc": now - timedelta(hours=1),
        "end_time_utc": now + timedelta(hours=1),
        "roe_signed": True,
        "activation_verified": True,
        "runtime_mode": RuntimeMode.PRODUCTION,
    }
    defaults.update(kwargs)
    return EngagementContext(**defaults)


class _AsyncStubPlugin(BasePlugin):
    name = "async-stub"
    version = "1.0.0"
    requires_authorization = False
    capability = PluginCapability.PASSIVE
    timeout_seconds = 5
    required_controls: list[str] = []
    requires_isolation = False

    def execute(self, context):
        return PluginResult(plugin_name=self.name, success=True, metadata={"mode": "sync"})

    async def aexecute(self, context):
        await asyncio.sleep(0.01)
        return PluginResult(plugin_name=self.name, success=True, metadata={"mode": "async"})


class _ActivePlugin(BasePlugin):
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


class _StubPlugin(BasePlugin):
    """A minimal stub plugin for run_plugin tests."""

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


class _FailingAsyncPlugin(BasePlugin):
    """Plugin that raises during async execution."""

    name = "failing-async"
    version = "1.0.0"
    requires_authorization = False
    capability = PluginCapability.PASSIVE
    timeout_seconds = 5
    required_controls: list[str] = []
    requires_isolation = False

    def execute(self, context):
        raise RuntimeError("sync-boom")

    async def aexecute(self, context):
        raise RuntimeError("async-boom")


class _NoAexecutePlugin(BasePlugin):
    """Plugin without aexecute — forces run_in_executor path."""

    name = "no-aexecute"
    version = "1.0.0"
    requires_authorization = False
    capability = PluginCapability.PASSIVE
    timeout_seconds = 5
    required_controls: list[str] = []
    requires_isolation = False

    def execute(self, context):
        return PluginResult(plugin_name=self.name, success=True, metadata={"mode": "executor"})

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)


# Delete aexecute from the class dict so hasattr returns False
# (it's inherited from BasePlugin, so we need __getattr__ trick)
_original_aexecute = _NoAexecutePlugin.__dict__.get("aexecute")


class _NoAexecutePluginFixed(_NoAexecutePlugin):
    """Subclass that hides aexecute."""

    name = "no-aexecute-fixed"

    def __getattribute__(self, name):
        if name == "aexecute":
            raise AttributeError("no aexecute")
        return super().__getattribute__(name)


# ===================================================================
# Capability matrix — kills mutants 5-8, 18
# ===================================================================


class TestCapabilityMatrixMutations:
    """Kill every bool flip in _CAPABILITY_MODE_MATRIX and default."""

    def test_ci_passive_true(self):
        """Kills mutant 5 (CI PASSIVE True → False)."""
        assert _is_capability_allowed(RuntimeMode.CI, PluginCapability.PASSIVE) is True

    def test_ci_active_false(self):
        """Kills mutant 6 (CI ACTIVE False → True)."""
        assert _is_capability_allowed(RuntimeMode.CI, PluginCapability.ACTIVE) is False

    def test_ci_destructive_false(self):
        """Kills mutant 7 (CI DESTRUCTIVE False → True)."""
        assert _is_capability_allowed(RuntimeMode.CI, PluginCapability.DESTRUCTIVE) is False

    def test_staging_passive_true(self):
        """Kills mutant 8 (STAGING PASSIVE True → False)."""
        assert _is_capability_allowed(RuntimeMode.STAGING, PluginCapability.PASSIVE) is True

    def test_unknown_mode_defaults_false(self):
        """Kills mutant 18 (default False → True).

        A mode not in the matrix should return False (not True).
        """
        # Create a mode value not in the matrix
        fake_mode = MagicMock()
        assert _is_capability_allowed(fake_mode, PluginCapability.PASSIVE) is False


# ===================================================================
# load_engagement — kills mutants 26-29, 32-34
# ===================================================================


class TestLoadEngagementMutations:
    """Kill audit/log string mutations in load_engagement."""

    @patch("redcheck.core.orchestrator.log")
    def test_load_invalid_roe_logs_exact_event(self, mock_log, tmp_path):
        """Kills mutant 26 (log event name XX mutation)."""
        orch = Orchestrator()
        orch.audit = MagicMock()
        fake = tmp_path / "bad.yaml"
        fake.write_text("engagement_id: BAD", encoding="utf-8")
        with pytest.raises(PolicyDeniedException):
            orch.load_engagement(fake)
        mock_log.error.assert_called_once()
        assert mock_log.error.call_args[0][0] == "engagement_load_failed"

    def test_load_invalid_roe_audit_exact_action(self, tmp_path):
        """Kills mutants 27-28 (audit action/level XX mutation)."""
        orch = Orchestrator()
        orch.audit = MagicMock()
        fake = tmp_path / "bad.yaml"
        fake.write_text("engagement_id: BAD", encoding="utf-8")
        with pytest.raises(PolicyDeniedException):
            orch.load_engagement(fake)
        orch.audit.log.assert_called_once()
        kw = orch.audit.log.call_args.kwargs
        assert kw["action"] == "ENGAGEMENT_LOAD_FAILED"
        assert kw["level"] == "ERROR"

    def test_load_invalid_roe_raises_with_exact_name(self, tmp_path):
        """Kills mutant 29 (PolicyDeniedException('orchestrator') → 'XXorchestratorXX')."""
        orch = Orchestrator()
        orch.audit = MagicMock()
        fake = tmp_path / "bad.yaml"
        fake.write_text("engagement_id: BAD", encoding="utf-8")
        with pytest.raises(PolicyDeniedException) as exc_info:
            orch.load_engagement(fake)
        # The first arg should be 'orchestrator' not 'XXorchestratorXX'
        assert "XX" not in str(exc_info.value)

    @patch("redcheck.core.orchestrator.log")
    def test_load_valid_roe_logs_exact_event(self, mock_log, valid_roe_file):
        """Kills mutant 32 (log event name XX mutation on success)."""
        orch = Orchestrator()
        orch.audit = MagicMock()
        orch.load_engagement(valid_roe_file)
        # Find the 'engagement_loaded' call
        info_calls = [c for c in mock_log.info.call_args_list if c[0][0] == "engagement_loaded"]
        assert len(info_calls) == 1

    def test_load_valid_roe_audit_exact_action(self, valid_roe_file):
        """Kills mutants 33-34 (audit action/details XX mutation)."""
        orch = Orchestrator()
        orch.audit = MagicMock()
        orch.load_engagement(valid_roe_file)
        orch.audit.log_engagement_action.assert_called_once()
        kw = orch.audit.log_engagement_action.call_args.kwargs
        assert kw["action"] == "ENGAGEMENT_LOADED"
        assert kw["details"].startswith("RoE validated, authorizer:")
        assert "XX" not in kw["details"]


# ===================================================================
# activate — kills mutants 35-47
# ===================================================================


class TestActivateMutations:
    """Kill mutations in activate()."""

    def test_activate_no_engagement_returns_false(self):
        """Kills mutant 35 (not self._current_engagement → self._current_engagement)."""
        orch = Orchestrator()
        orch.audit = MagicMock()
        result = orch.activate("any-code")
        assert result is False

    @patch("redcheck.core.orchestrator.log")
    def test_activate_no_engagement_log_exact_event(self, mock_log):
        """Kills mutants 36-37 (log event name and reason XX mutation)."""
        orch = Orchestrator()
        orch.audit = MagicMock()
        orch.activate("any")
        mock_log.warning.assert_called_once_with(
            "activation_failed", reason="no_engagement"
        )

    def test_activate_no_engagement_audit_exact(self):
        """Kills mutants 38-40 (audit action/details/level XX mutation)."""
        orch = Orchestrator()
        orch.audit = MagicMock()
        orch.activate("any")
        orch.audit.log.assert_called_once()
        kw = orch.audit.log.call_args.kwargs
        assert kw["action"] == "ACTIVATION_FAILED"
        assert kw["details"] == "No engagement loaded"
        assert kw["level"] == "WARN"

    def test_activate_valid_code_sets_activation_verified(self, valid_roe_file):
        """Kills mutants 42-45 (validate_activation_code result, update)."""
        orch = Orchestrator()
        orch.audit = MagicMock()
        orch.load_engagement(valid_roe_file)
        with patch.object(orch.policy, "validate_activation_code", return_value=True):
            result = orch.activate("VALID-CODE")
        assert result is True
        assert orch.current_engagement is not None
        # The engagement should have activation_verified == True
        ctx = orch._current_engagement
        assert ctx.activation_verified is True

    @patch("redcheck.core.orchestrator.log")
    def test_activate_valid_code_logs_exact_event(self, mock_log, valid_roe_file):
        """Kills mutant 46 (log event name XX mutation)."""
        orch = Orchestrator()
        orch.audit = MagicMock()
        orch.load_engagement(valid_roe_file)
        with patch.object(orch.policy, "validate_activation_code", return_value=True):
            orch.activate("CODE")
        info_calls = [c for c in mock_log.info.call_args_list if c[0][0] == "engagement_activated"]
        assert len(info_calls) == 1

    def test_activate_valid_code_audit_exact_action(self, valid_roe_file):
        """Kills mutant 47 (audit action XX mutation)."""
        orch = Orchestrator()
        orch.audit = MagicMock()
        orch.load_engagement(valid_roe_file)
        with patch.object(orch.policy, "validate_activation_code", return_value=True):
            orch.activate("CODE")
        # Find the ENGAGEMENT_ACTIVATED call
        calls = orch.audit.log_engagement_action.call_args_list
        activated = [c for c in calls if c.kwargs.get("action") == "ENGAGEMENT_ACTIVATED"]
        assert len(activated) == 1


# ===================================================================
# run_plugin — kills mutants 52-70, 73-79, 83, 85-87, 91-96
# ===================================================================


class TestRunPluginMutations:
    """Kill mutations in run_plugin()."""

    def test_not_found_exact_error_message(self, valid_roe_file):
        """Kills mutant 52 (error message XX mutation)."""
        orch = Orchestrator()
        orch.load_engagement(valid_roe_file)
        result = orch.run_plugin("nonexistent")
        assert result.success is False
        assert result.errors[0] == "Plugin 'nonexistent' not found in registry"

    def test_context_keys_exact(self, valid_roe_file):
        """Kills mutants 53-64 (context dict key/value mutations)."""
        orch = Orchestrator()
        orch.audit = MagicMock()
        orch.load_engagement(valid_roe_file)
        # Intercept the plugin execute to check context
        captured_ctx = {}

        class _CtxCapturePlugin(BasePlugin):
            name = "ctx-capture"
            version = "1.0.0"
            requires_authorization = False

            def execute(self, context):
                captured_ctx.update(context)
                return PluginResult(plugin_name=self.name, success=True)

        _CtxCapturePlugin()  # Register
        result = orch.run_plugin("ctx-capture")
        assert result.success is True
        # Check exact keys set by setdefault — kills 56, 58, 61
        assert "authorized_targets" in captured_ctx
        assert "roe_validated" in captured_ctx
        assert "safety_mode" in captured_ctx
        # Check exact values — kills 57, 59, 60, 62, 63, 64
        # roe_validated should come from roe_signed
        assert isinstance(captured_ctx["roe_validated"], bool)
        assert captured_ctx["safety_mode"] in ("authorized-active", "dry-run")

    def test_context_authorized_targets_from_targets(self, valid_roe_file):
        """Kills mutant 57 (targets key → XXtargetsXX).

        The context must contain authorized_targets populated from the 'targets' field.
        """
        orch = Orchestrator()
        orch.audit = MagicMock()
        orch.load_engagement(valid_roe_file)
        captured_ctx = {}

        class _CtxCapture2(BasePlugin):
            name = "ctx-capture2"
            version = "1.0.0"
            requires_authorization = False

            def execute(self, context):
                captured_ctx.update(context)
                return PluginResult(plugin_name=self.name, success=True)

        _CtxCapture2()
        orch.run_plugin("ctx-capture2")
        # authorized_targets should be non-empty (from targets field in engagement)
        assert len(captured_ctx["authorized_targets"]) > 0

    def test_context_roe_validated_from_roe_signed(self, valid_roe_file):
        """Kills mutants 59-60 (roe_signed key → XXroe_signedXX, default False → True).

        roe_validated should come from roe_signed in the engagement.
        Since this is a valid loaded engagement, roe_signed=True.
        """
        orch = Orchestrator()
        orch.audit = MagicMock()
        orch.load_engagement(valid_roe_file)
        captured_ctx = {}

        class _CtxCapture3(BasePlugin):
            name = "ctx-capture3"
            version = "1.0.0"
            requires_authorization = False

            def execute(self, context):
                captured_ctx.update(context)
                return PluginResult(plugin_name=self.name, success=True)

        _CtxCapture3()
        orch.run_plugin("ctx-capture3")
        # roe_validated should be True (from roe_signed=True in loaded engagement)
        assert captured_ctx["roe_validated"] is True

    def test_context_safety_mode_exact_values(self, valid_roe_file):
        """Kills mutants 62-63 (authorized-active → XX, activation_verified key → XX)."""
        orch = Orchestrator()
        orch.audit = MagicMock()
        orch.load_engagement(valid_roe_file)
        # Activate the engagement to get safety_mode = 'authorized-active'
        with patch.object(orch.policy, "validate_activation_code", return_value=True):
            orch.activate("CODE")
        captured_ctx = {}

        class _CtxCapture4(BasePlugin):
            name = "ctx-capture4"
            version = "1.0.0"
            requires_authorization = False

            def execute(self, context):
                captured_ctx.update(context)
                return PluginResult(plugin_name=self.name, success=True)

        _CtxCapture4()
        orch.run_plugin("ctx-capture4")
        assert captured_ctx["safety_mode"] == "authorized-active"

    @patch("redcheck.core.orchestrator.log")
    def test_dry_run_logs_exact_event(self, mock_log, valid_roe_file):
        """Kills mutants 65-69 (dry run log/audit XX mutations)."""
        orch = Orchestrator()
        orch.audit = MagicMock()
        orch.load_engagement(valid_roe_file)
        result = orch.run_plugin("stub-test", dry_run=True)
        assert result.success is True

        # Check structlog event — kills 65
        dry_calls = [c for c in mock_log.info.call_args_list if c[0][0] == "plugin_dry_run"]
        assert len(dry_calls) == 1

        # Check audit — kills 66-69
        audit_calls = [c for c in orch.audit.log.call_args_list
                       if c.kwargs.get("action") == "PLUGIN_DRY_RUN"]
        assert len(audit_calls) == 1
        kw = audit_calls[0].kwargs
        assert kw["details"] == "Dry run: stub-test"
        assert kw["plugin"] == "stub-test"
        # engagement_id must be the actual engagement id, not "" or "XXXX"
        assert kw["engagement_id"] == "TEST-001"

    def test_requires_auth_passes_true(self, valid_roe_file):
        """Kills mutant 70 (requires_authorization=True → False)."""
        orch = Orchestrator()
        orch.audit = MagicMock()
        orch.load_engagement(valid_roe_file)

        # Mock policy.authorize to capture the call
        with patch.object(orch.policy, "authorize") as mock_auth:
            # Use a plugin that requires auth but will be mocked
            class _AuthPlugin(BasePlugin):
                name = "auth-check"
                version = "1.0.0"
                requires_authorization = True

                def execute(self, context):
                    return PluginResult(plugin_name=self.name, success=True)

            _AuthPlugin()  # Register
            orch.run_plugin("auth-check")
            mock_auth.assert_called_once()
            assert mock_auth.call_args.kwargs["requires_authorization"] is True

    def test_context_validation_failure(self, valid_roe_file):
        """Kills mutant 73 (success=False → True on validation failure)."""
        orch = Orchestrator()
        orch.audit = MagicMock()
        orch.load_engagement(valid_roe_file)

        class _BadCtxPlugin(BasePlugin):
            name = "bad-ctx"
            version = "1.0.0"
            requires_authorization = False

            def validate_context(self, context):
                return False, "Missing required key"

            def execute(self, context):
                return PluginResult(plugin_name=self.name, success=True)

        _BadCtxPlugin()
        result = orch.run_plugin("bad-ctx")
        assert result.success is False
        assert result.errors[0] == "Context validation failed: Missing required key"

    @patch("redcheck.core.orchestrator.log")
    def test_plugin_execute_logs_exact_events(self, mock_log, valid_roe_file):
        """Kills mutants 75-79, 91-96 (log/audit event names and details)."""
        orch = Orchestrator()
        orch.audit = MagicMock()
        orch.load_engagement(valid_roe_file)
        result = orch.run_plugin("stub-test")
        assert result.success is True

        # Check "plugin_execute" event — kills 75
        exec_calls = [c for c in mock_log.info.call_args_list if c[0][0] == "plugin_execute"]
        assert len(exec_calls) == 1

        # Check "plugin_complete" event — kills 91
        complete_calls = [c for c in mock_log.info.call_args_list if c[0][0] == "plugin_complete"]
        assert len(complete_calls) == 1

        # Check audit PLUGIN_EXECUTE — kills 76-79
        exec_audit = [c for c in orch.audit.log.call_args_list
                      if c.kwargs.get("action") == "PLUGIN_EXECUTE"]
        assert len(exec_audit) == 1
        kw = exec_audit[0].kwargs
        assert kw["details"] == "Executing: stub-test"
        assert kw["plugin"] == "stub-test"
        assert kw["engagement_id"] == "TEST-001"

        # Check audit PLUGIN_COMPLETE — kills 92-96
        comp_audit = [c for c in orch.audit.log.call_args_list
                      if c.kwargs.get("action") == "PLUGIN_COMPLETE"]
        assert len(comp_audit) == 1
        kw2 = comp_audit[0].kwargs
        details = kw2["details"]
        assert details.startswith("stub-test: success=True, ")
        assert "findings=" in details
        assert details.endswith("ms")
        assert "XX" not in details
        assert kw2["plugin"] == "stub-test"
        assert kw2["engagement_id"] == "TEST-001"

    def test_execution_error_exact_message(self, valid_roe_file):
        """Kills mutant 83 (error message XX mutation)."""
        orch = Orchestrator()
        orch.audit = MagicMock()
        orch.load_engagement(valid_roe_file)
        result = orch.run_plugin("fail-test")
        assert result.success is False
        assert result.errors[0] == "Plugin execution error: boom"

    def test_duration_ms_is_reasonable(self, valid_roe_file):
        """Kills mutants 85-87 (duration math mutations - +, /, *1001)."""
        orch = Orchestrator()
        orch.audit = MagicMock()
        orch.load_engagement(valid_roe_file)
        result = orch.run_plugin("stub-test")
        d = result.metadata["duration_ms"]
        assert isinstance(d, int)
        # Duration should be small (< 1000ms) not enormous (+ would make it huge)
        assert 0 <= d < 5000

    @patch("redcheck.core.orchestrator.time")
    def test_duration_ms_exact_formula(self, mock_time, valid_roe_file):
        """Kills mutants 86-87 (/ 1000 → * 1000, * 1001 → * 1000).

        We control time.monotonic() to return known values so we can
        verify the formula is ``int((end - start) * 1000)``.
        """
        mock_time.monotonic.side_effect = [100.0, 101.0]  # 1.0s apart
        orch = Orchestrator()
        orch.audit = MagicMock()
        orch.load_engagement(valid_roe_file)
        result = orch.run_plugin("stub-test")
        # (101.0 - 100.0) * 1000 = 1000
        assert result.metadata["duration_ms"] == 1000

    def test_run_plugin_no_engagement_context_empty(self, valid_roe_file):
        """Kills mutant 53 (context = {} → context = None).

        Without engagement loaded, context must be an empty dict, not None.
        A plugin should still receive a dict so .get()/.setdefault() work.
        """
        orch = Orchestrator()
        orch.audit = MagicMock()
        captured_ctx = {"_sentinel": True}  # sentinel to check update happened

        class _EmptyCtxCapture2(BasePlugin):
            name = "empty-ctx-capture2"
            version = "1.0.0"
            requires_authorization = False

            def validate_context(self, context):
                # Accept any context including empty dict
                return True, ""

            def execute(self, context):
                captured_ctx.clear()
                if context is not None:
                    captured_ctx.update(context)
                else:
                    captured_ctx["__was_none"] = True
                return PluginResult(plugin_name=self.name, success=True)

        _EmptyCtxCapture2()
        result = orch.run_plugin("empty-ctx-capture2")
        assert result.success is True
        # context should be an empty dict, never None
        assert "__was_none" not in captured_ctx
        assert isinstance(captured_ctx, dict)

    def test_model_dump_mode_json_produces_serializable(self, valid_roe_file):
        """Kills mutant 54 (model_dump mode='json' → mode='XXjsonXX').

        If mode is wrong, Pydantic may raise or return non-JSON-serializable types.
        """
        import json

        orch = Orchestrator()
        orch.audit = MagicMock()
        orch.load_engagement(valid_roe_file)
        captured_ctx = {}

        class _JsonCtxCapture(BasePlugin):
            name = "json-ctx-capture"
            version = "1.0.0"
            requires_authorization = False

            def execute(self, context):
                captured_ctx.update(context)
                return PluginResult(plugin_name=self.name, success=True)

        _JsonCtxCapture()
        orch.run_plugin("json-ctx-capture")
        # In JSON mode, datetimes are serialized as strings
        # If mode is invalid, this will either fail or have datetime objects
        json_str = json.dumps(captured_ctx)
        assert isinstance(json_str, str)
        assert isinstance(captured_ctx.get("start_time_utc"), str)


# ===================================================================
# arun_plugin — kills mutants 98-99, 102, 104, 108, 110, 112-113,
#   118-119, 122-123, 127-139, 143-159
# ===================================================================


class TestArunPluginMutations:
    """Kill mutations in the async 11-step enforcement."""

    @pytest.mark.asyncio
    async def test_step3_expired_exact_message(self):
        """Kills mutant 102 (message XX mutation)."""
        orch = Orchestrator()
        now = datetime.now(timezone.utc)
        ctx = _make_engagement(
            start_time_utc=now - timedelta(days=2),
            end_time_utc=now - timedelta(days=1),
        )
        with pytest.raises(PolicyDeniedException) as exc_info:
            await orch.arun_plugin("async-stub", ctx)
        msg = str(exc_info.value)
        assert "XX" not in msg

    @pytest.mark.asyncio
    async def test_step3_outside_window_exact_message(self):
        """Kills mutant 104 (message XX mutation)."""
        orch = Orchestrator()
        now = datetime.now(timezone.utc)
        ctx = _make_engagement(
            start_time_utc=now + timedelta(hours=1),
            end_time_utc=now + timedelta(hours=2),
        )
        with pytest.raises(PolicyDeniedException) as exc_info:
            await orch.arun_plugin("async-stub", ctx)
        msg = str(exc_info.value)
        assert "XX" not in msg

    @pytest.mark.asyncio
    async def test_step4_roe_not_validated_exact_message(self):
        """Kills mutant 108 (message XX mutation)."""
        orch = Orchestrator()
        ctx = _make_engagement(roe_signed=False, roe_path=None)
        with pytest.raises(RoEValidationError) as exc_info:
            await orch.arun_plugin("async-stub", ctx)
        assert "XX" not in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_step5_activation_exact_message(self):
        """Kills mutant 110 (message XX mutation)."""
        orch = Orchestrator()
        ctx = _make_engagement(activation_verified=False)
        with pytest.raises(ActivationError) as exc_info:
            await orch.arun_plugin("async-stub", ctx)
        assert "XX" not in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_step6_capability_exact_message(self):
        """Kills mutants 112-113 (message XX mutation)."""
        orch = Orchestrator()
        ctx = _make_engagement(runtime_mode=RuntimeMode.DEV)
        with pytest.raises(PolicyDeniedException) as exc_info:
            await orch.arun_plugin("active-test", ctx)
        msg = str(exc_info.value)
        assert "Capability" in msg
        assert "mode" in msg
        assert "XX" not in msg

    @pytest.mark.asyncio
    async def test_step7_offensive_controls_missing_list(self):
        """Kills mutants 118-119 (not → removed, default False → True)."""
        orch = Orchestrator()
        ctx = _make_engagement(offensive_controls=OffensiveControls())
        with pytest.raises(OffensiveControlError) as exc_info:
            await orch.arun_plugin("active-test", ctx)
        # The missing controls should include the actual missing one
        assert "allow_auth_testing" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_step8_isolation_default_false(self):
        """Kills mutant 98 (isolation_available default False → True)."""
        orch = Orchestrator()
        oc = OffensiveControls(allow_exploit_validation=True)
        ctx = _make_engagement(offensive_controls=oc)
        # Without passing isolation_available, default should be False → raises
        with pytest.raises(IsolationError):
            await orch.arun_plugin("destructive-test", ctx)

    @pytest.mark.asyncio
    async def test_step8_requires_isolation_attr(self):
        """Kills mutants 122-123 (getattr key mutation, default True → False)."""
        orch = Orchestrator()
        oc = OffensiveControls(allow_exploit_validation=True)
        ctx = _make_engagement(offensive_controls=oc)
        # Plugin has requires_isolation = True, isolation_available = False → raises
        with pytest.raises(IsolationError):
            await orch.arun_plugin("destructive-test", ctx, isolation_available=False)

    @pytest.mark.asyncio
    async def test_eid_used_in_exceptions(self):
        """Kills mutant 99 (eid = None instead of engagement.engagement_id)."""
        orch = Orchestrator()
        ctx = _make_engagement(activation_verified=False)
        with pytest.raises(ActivationError) as exc_info:
            await orch.arun_plugin("async-stub", ctx)
        assert exc_info.value.engagement_id == "ENG-MUT"

    @pytest.mark.asyncio
    @patch("redcheck.core.orchestrator.log")
    async def test_step10_dry_run_exact_log(self, mock_log):
        """Kills mutants 127-131 (dry run log/audit/context mutations)."""
        orch = Orchestrator()
        orch.audit = MagicMock()
        ctx = _make_engagement()
        result = await orch.arun_plugin("async-stub", ctx, dry_run=True)
        assert result.success is True

        # Check structlog event — kills 127
        dry_calls = [c for c in mock_log.info.call_args_list if c[0][0] == "async_plugin_dry_run"]
        assert len(dry_calls) == 1

        # Check audit — kills 128-129
        orch.audit.log.assert_called_once()
        kw = orch.audit.log.call_args.kwargs
        assert kw["action"] == "ASYNC_PLUGIN_DRY_RUN"
        assert kw["details"] == "Async dry run: async-stub"

    @pytest.mark.asyncio
    @patch("redcheck.core.orchestrator.log")
    async def test_step11_execute_exact_log(self, mock_log):
        """Kills mutants 135-139 (step 11 context/log/audit mutations)."""
        orch = Orchestrator()
        orch.audit = MagicMock()
        ctx = _make_engagement()
        result = await orch.arun_plugin("async-stub", ctx)
        assert result.success is True
        assert result.metadata["mode"] == "async"

        # Check structlog event — kills 137
        exec_calls = [c for c in mock_log.info.call_args_list if c[0][0] == "async_plugin_execute"]
        assert len(exec_calls) == 1

        # Check audit — kills 138-139
        exec_audit = [c for c in orch.audit.log.call_args_list
                      if c.kwargs.get("action") == "ASYNC_PLUGIN_EXECUTE"]
        assert len(exec_audit) == 1
        assert exec_audit[0].kwargs["details"] == "Async executing: async-stub"

    @pytest.mark.asyncio
    async def test_step11_async_exception_handled(self):
        """Kills mutants 145-147 (success=False→True, error msg, result=None)."""
        orch = Orchestrator()
        orch.audit = MagicMock()
        ctx = _make_engagement()
        result = await orch.arun_plugin("failing-async", ctx)
        assert result.success is False
        assert result.errors[0] == "Plugin execution error: async-boom"
        assert isinstance(result.metadata["duration_ms"], int)

    @pytest.mark.asyncio
    async def test_step11_duration_ms_reasonable(self):
        """Kills mutants 148-153 (duration math and None mutations)."""
        orch = Orchestrator()
        orch.audit = MagicMock()
        ctx = _make_engagement()
        result = await orch.arun_plugin("async-stub", ctx)
        d = result.metadata["duration_ms"]
        assert isinstance(d, int)
        assert 0 <= d < 5000

    @pytest.mark.asyncio
    @patch("redcheck.core.orchestrator.time")
    async def test_step11_duration_ms_exact_formula(self, mock_time):
        """Kills mutants 149-150 (/ 1000 → * 1000, * 1001).

        Control time.monotonic() to verify formula: int((end - start) * 1000).
        """
        mock_time.monotonic.side_effect = [200.0, 201.0]  # 1.0s apart
        orch = Orchestrator()
        orch.audit = MagicMock()
        ctx = _make_engagement()
        result = await orch.arun_plugin("async-stub", ctx)
        # (201.0 - 200.0) * 1000 = 1000
        assert result.metadata["duration_ms"] == 1000

    @pytest.mark.asyncio
    async def test_step8_isolation_requires_isolation_true_default(self):
        """Kills mutants 122-123 (requires_isolation attr key → XX, default True → False).

        A DESTRUCTIVE plugin without `requires_isolation` explicitly set should
        default to True (getattr(plugin, 'requires_isolation', True)),
        meaning it requires isolation and will fail if isolation_available=False.
        """
        orch = Orchestrator()
        oc = OffensiveControls(allow_exploit_validation=True)
        ctx = _make_engagement(offensive_controls=oc)

        class _DestructiveNoIsolAttr(BasePlugin):
            name = "destruct-no-isol-attr"
            version = "1.0.0"
            requires_authorization = False
            capability = PluginCapability.DESTRUCTIVE
            required_controls: list[str] = ["allow_exploit_validation"]
            timeout_seconds = 5

            def execute(self, context):
                return PluginResult(plugin_name=self.name, success=True)

            async def aexecute(self, context):
                return PluginResult(plugin_name=self.name, success=True)

            def __getattribute__(self, name):
                if name == "requires_isolation":
                    raise AttributeError("no requires_isolation")
                return super().__getattribute__(name)

        _DestructiveNoIsolAttr()
        # Default is True, isolation_available=False → should raise
        with pytest.raises(IsolationError):
            await orch.arun_plugin("destruct-no-isol-attr", ctx, isolation_available=False)

    @pytest.mark.asyncio
    async def test_step8_requires_isolation_false_allows_no_isolation(self):
        """Kills mutant 122 (requires_isolation key → XXrequires_isolationXX).

        A DESTRUCTIVE plugin with requires_isolation=False should NOT raise
        IsolationError even when isolation_available=False.
        If the attr key is mutated, getattr falls back to True → wrongly raises.
        """
        orch = Orchestrator()
        oc = OffensiveControls(allow_exploit_validation=True)
        ctx = _make_engagement(offensive_controls=oc)

        class _DestructiveNoIsolNeeded(BasePlugin):
            name = "destruct-no-isol-needed"
            version = "1.0.0"
            requires_authorization = False
            capability = PluginCapability.DESTRUCTIVE
            required_controls: list[str] = ["allow_exploit_validation"]
            timeout_seconds = 5
            requires_isolation = False  # Explicitly False

            def execute(self, context):
                return PluginResult(plugin_name=self.name, success=True)

            async def aexecute(self, context):
                return PluginResult(plugin_name=self.name, success=True)

        _DestructiveNoIsolNeeded()
        # requires_isolation=False, so should succeed even without isolation
        result = await orch.arun_plugin("destruct-no-isol-needed", ctx, isolation_available=False)
        assert result.success is True

    @pytest.mark.asyncio
    async def test_step7_controls_default_false(self):
        """Kills mutant 119 (getattr(offensive_controls, ctrl, False) → True).

        A plugin requiring 'allow_auth_testing' when OffensiveControls has
        no such attribute set should get default False and fail.
        """
        orch = Orchestrator()
        ctx = _make_engagement(offensive_controls=OffensiveControls())
        with pytest.raises(OffensiveControlError) as exc_info:
            await orch.arun_plugin("active-test", ctx)
        assert "allow_auth_testing" in str(exc_info.value)

    @pytest.mark.asyncio
    @patch("redcheck.core.orchestrator.log")
    async def test_step10_dry_run_context_is_dict(self, mock_log):
        """Kills mutant 131 (context = engagement.model_dump(...) → context = None)
        and 130 (mode='json' → mode='XXjsonXX').

        When dry_run is True, the context passed to plugin.dry_run()
        must be a dict (from model_dump), not None. And datetimes must be
        serialized as strings (json mode), not datetime objects.
        """
        orch = Orchestrator()
        orch.audit = MagicMock()
        ctx = _make_engagement()
        captured = {}

        class _DryRunCapture(BasePlugin):
            name = "dryrun-capture"
            version = "1.0.0"
            requires_authorization = False
            capability = PluginCapability.PASSIVE
            timeout_seconds = 5
            required_controls: list[str] = []
            requires_isolation = False

            def execute(self, context):
                return PluginResult(plugin_name=self.name, success=True)

            def dry_run(self, context):
                captured["ctx"] = context
                return PluginResult(plugin_name=self.name, success=True, metadata={"dry_run": True})

        _DryRunCapture()
        result = await orch.arun_plugin("dryrun-capture", ctx, dry_run=True)
        assert result.success is True
        # Context must be a dict, not None
        assert isinstance(captured["ctx"], dict)
        assert "engagement_id" in captured["ctx"]
        # Datetimes must be strings in json mode (kills mutant 130)
        assert isinstance(captured["ctx"]["start_time_utc"], str)

    @pytest.mark.asyncio
    @patch("redcheck.core.orchestrator.log")
    async def test_step11_execute_context_is_dict(self, mock_log):
        """Kills mutant 136 (context = engagement.model_dump(...) → context = None)
        and 135 (mode='json' → mode='XXjsonXX').

        When executing (not dry_run), the context passed to plugin must be a dict
        with datetimes serialized as strings.
        """
        orch = Orchestrator()
        orch.audit = MagicMock()
        ctx = _make_engagement()
        captured = {}

        class _ExecCapture(BasePlugin):
            name = "exec-capture"
            version = "1.0.0"
            requires_authorization = False
            capability = PluginCapability.PASSIVE
            timeout_seconds = 5
            required_controls: list[str] = []
            requires_isolation = False

            def execute(self, context):
                captured["ctx"] = context
                return PluginResult(plugin_name=self.name, success=True)

            async def aexecute(self, context):
                captured["ctx"] = context
                return PluginResult(plugin_name=self.name, success=True)

        _ExecCapture()
        result = await orch.arun_plugin("exec-capture", ctx)
        assert result.success is True
        assert isinstance(captured["ctx"], dict)
        assert "engagement_id" in captured["ctx"]
        # Datetimes must be strings in json mode (kills mutant 135)
        assert isinstance(captured["ctx"]["start_time_utc"], str)

    @pytest.mark.asyncio
    @patch("redcheck.core.orchestrator.log")
    async def test_step11_complete_audit_exact(self, mock_log):
        """Kills mutants 154-157 (complete log/audit event name and details)."""
        orch = Orchestrator()
        orch.audit = MagicMock()
        ctx = _make_engagement()
        await orch.arun_plugin("async-stub", ctx)

        # Check structlog — kills 154
        comp_calls = [c for c in mock_log.info.call_args_list if c[0][0] == "async_plugin_complete"]
        assert len(comp_calls) == 1

        # Check audit — kills 155-157
        comp_audit = [c for c in orch.audit.log.call_args_list
                      if c.kwargs.get("action") == "ASYNC_PLUGIN_COMPLETE"]
        assert len(comp_audit) == 1
        kw = comp_audit[0].kwargs
        assert "async-stub:" in kw["details"]
        assert "success=True" in kw["details"]
        assert "findings=" in kw["details"]
        assert "XX" not in kw["details"]

    @pytest.mark.asyncio
    async def test_step11_no_aexecute_uses_executor(self):
        """Kills mutants 143-144 (loop=None, result=None in else branch)."""
        orch = Orchestrator()
        orch.audit = MagicMock()
        ctx = _make_engagement()
        result = await orch.arun_plugin("no-aexecute-fixed", ctx)
        assert result.success is True
        assert result.metadata["mode"] == "executor"

    @pytest.mark.asyncio
    async def test_timeout_default_used(self):
        """Kills mutant 133 (default timeout 60 → 61).

        This mutant is equivalent (60 → 61 doesn't change behaviour).
        We just verify the normal timeout path works.
        """
        orch = Orchestrator()
        orch.audit = MagicMock()
        ctx = _make_engagement()
        # async-stub has timeout_seconds=5, which exercises getattr
        result = await orch.arun_plugin("async-stub", ctx)
        assert result.success is True


# ===================================================================
# shutdown — kills mutants 158-159
# ===================================================================


class TestShutdownMutations:
    @patch("redcheck.core.orchestrator.log")
    def test_shutdown_logs_exact_event(self, mock_log, valid_roe_file):
        """Kills mutant 158 (log event XX mutation)."""
        orch = Orchestrator()
        orch.audit = MagicMock()
        orch.load_engagement(valid_roe_file)
        orch.shutdown()
        shutdown_calls = [
            c for c in mock_log.info.call_args_list
            if c[0][0] == "engagement_shutdown"
        ]
        assert len(shutdown_calls) == 1

    def test_shutdown_audit_exact_action(self, valid_roe_file):
        """Kills mutant 159 (audit action XX mutation)."""
        orch = Orchestrator()
        orch.audit = MagicMock()
        orch.load_engagement(valid_roe_file)
        orch.shutdown()
        shutdown_audit = [c for c in orch.audit.log_engagement_action.call_args_list
                          if c.kwargs.get("action") == "ENGAGEMENT_SHUTDOWN"]
        assert len(shutdown_audit) == 1


# ===================================================================
# _LegacyEngagementAdapter — kills mutants 162-192
# ===================================================================


class TestLegacyAdapterMutations:
    """Kill mutations in _LegacyEngagementAdapter."""

    def _make_adapter(self, **overrides) -> _LegacyEngagementAdapter:
        ctx = _make_engagement(**overrides)
        return _LegacyEngagementAdapter(ctx)

    def test_authorized_targets_alias_returns_host_dicts(self):
        """Kills mutants 162-163, 172-173 (alias key/value mutations)."""
        adapter = self._make_adapter(targets=["10.0.0.1"])
        targets = adapter.authorized_targets
        assert isinstance(targets, list)
        assert len(targets) == 1
        assert targets[0] == {"host": "10.0.0.1"}

    def test_roe_validated_alias_returns_bool(self):
        """Kills alias mutations for roe_validated."""
        adapter = self._make_adapter(roe_signed=True)
        assert adapter.roe_validated is True

    def test_safety_mode_alias_activated(self):
        """Kills mutants 166-167, 176-179 (safety_mode alias mutations)."""
        adapter = self._make_adapter(activation_verified=True)
        assert adapter.safety_mode == "authorized-active"

    def test_safety_mode_alias_not_activated(self):
        """Kills mutant 179 (dry-run XX mutation)."""
        adapter = self._make_adapter(activation_verified=False)
        assert adapter.safety_mode == "dry-run"

    def test_unknown_attr_raises_exact_message(self):
        """Kills mutant 180 (error message XX mutation)."""
        adapter = self._make_adapter()
        with pytest.raises(AttributeError) as exc_info:
            _ = adapter.totally_bogus
        msg = str(exc_info.value)
        assert msg == "'_LegacyEngagementAdapter' has no attribute 'totally_bogus'"

    def test_to_dict_has_exact_keys(self):
        """Kills mutants 181, 184-192 (to_dict key/value mutations)."""
        adapter = self._make_adapter(
            targets=["10.0.0.1"],
            roe_signed=True,
            activation_verified=True,
        )
        d = adapter.to_dict()

        # kills 181 (model_dump mode='json' → 'XXjsonXX')
        # If mode is wrong, serialization will fail or produce wrong types
        assert isinstance(d, dict)
        assert "engagement_id" in d
        assert isinstance(d["engagement_id"], str)
        # Times must be serialized as strings in json mode
        assert isinstance(d.get("start_time_utc"), str)

        # kills 184 (host key mutation)
        assert d["authorized_targets"] == [{"host": "10.0.0.1"}]

        # kills 187-188 (roe_validated key/value mutation)
        assert "roe_validated" in d
        assert d["roe_validated"] is True

        # kills 189-192 (safety_mode key/value/None mutations)
        assert "safety_mode" in d
        assert d["safety_mode"] == "authorized-active"

    def test_to_dict_dry_run_mode(self):
        """Kills mutant 191 (dry-run XX mutation in to_dict)."""
        adapter = self._make_adapter(activation_verified=False)
        d = adapter.to_dict()
        assert d["safety_mode"] == "dry-run"

    def test_to_dict_targets_or_not_and(self):
        """Kills mutant 185 (targets or [] → targets and [])."""
        adapter = self._make_adapter(targets=["x.com"])
        d = adapter.to_dict()
        assert len(d["authorized_targets"]) == 1


# ===================================================================
# _build_engagement_from_roe — kills mutants 193-217
# ===================================================================


class TestBuildEngagementFromRoeMutations:
    """Kill mutations in the helper that builds EngagementContext from RoE."""

    def test_authorized_targets_key_used(self):
        """Kills mutant 193 (authorized_targets key XX mutation)."""
        data = {
            "engagement_id": "BUILD-1",
            "authorizer": "admin",
            "authorized_targets": ["10.0.0.1"],
            "allowed_tests": ["recon"],
            "start_time_utc": "2025-06-01T00:00:00Z",
            "end_time_utc": "2025-12-31T23:59:59Z",
        }
        ctx = _build_engagement_from_roe(data, "/tmp/roe.yaml")
        assert "10.0.0.1" in ctx.targets

    def test_targets_fallback_key_used(self):
        """Kills mutant 194 (targets fallback key XX mutation)."""
        data = {
            "engagement_id": "BUILD-2",
            "authorizer": "admin",
            "targets": ["fallback.com"],
            "allowed_tests": ["recon"],
            "start_time_utc": "2025-06-01T00:00:00Z",
            "end_time_utc": "2025-12-31T23:59:59Z",
        }
        ctx = _build_engagement_from_roe(data, "/tmp/roe.yaml")
        assert "fallback.com" in ctx.targets

    def test_dict_targets_use_host_key(self):
        """Kills mutant 197 (host key XX mutation in dict targets)."""
        data = {
            "engagement_id": "BUILD-3",
            "authorizer": "admin",
            "authorized_targets": [{"host": "dict-target.com"}],
            "allowed_tests": ["recon"],
            "start_time_utc": "2025-06-01T00:00:00Z",
            "end_time_utc": "2025-12-31T23:59:59Z",
        }
        ctx = _build_engagement_from_roe(data, "/tmp/roe.yaml")
        assert "dict-target.com" in ctx.targets

    def test_z_suffix_parsed(self):
        """Kills mutant 200 (Z suffix detection mutation)."""
        data = {
            "engagement_id": "BUILD-Z",
            "authorizer": "admin",
            "authorized_targets": ["x.com"],
            "allowed_tests": ["recon"],
            "start_time_utc": "2025-06-01T00:00:00Z",
            "end_time_utc": "2025-12-31T23:59:59Z",
        }
        ctx = _build_engagement_from_roe(data, "/tmp/roe.yaml")
        assert ctx.start_time_utc.tzinfo is not None
        assert ctx.end_time_utc.tzinfo is not None

    def test_naive_datetime_gets_utc(self):
        """Kills mutant 198 (is None → is not None for tzinfo)."""
        from datetime import datetime as dt

        now = dt.now()  # noqa: DTZ005 - intentionally naive for test
        data = {
            "engagement_id": "BUILD-NAIVE",
            "authorizer": "admin",
            "authorized_targets": ["x.com"],
            "allowed_tests": ["recon"],
            "start_time_utc": now,
            "end_time_utc": now + timedelta(hours=1),
        }
        ctx = _build_engagement_from_roe(data, "/tmp/roe.yaml")
        assert ctx.start_time_utc.tzinfo is not None
        assert ctx.end_time_utc.tzinfo is not None

    def test_engagement_id_exact(self):
        """Kills mutant 207 (default '' → 'XXXX')."""
        data = {
            "engagement_id": "ENG-EXACT",
            "authorizer": "admin",
            "authorized_targets": ["x.com"],
            "allowed_tests": ["recon"],
            "start_time_utc": "2025-06-01T00:00:00Z",
            "end_time_utc": "2025-12-31T23:59:59Z",
        }
        ctx = _build_engagement_from_roe(data, "/tmp/roe.yaml")
        assert ctx.engagement_id == "ENG-EXACT"

    def test_engagement_id_missing_defaults_empty(self):
        """Kills mutant 207 (default '' → 'XXX') — when key is absent.

        If engagement_id is missing from RoE data, the default must be '',
        not 'XXXX' or any other mutated string.
        """
        data = {
            "authorizer": "admin",
            "authorized_targets": ["x.com"],
            "allowed_tests": ["recon"],
            "start_time_utc": "2025-06-01T00:00:00Z",
            "end_time_utc": "2025-12-31T23:59:59Z",
        }
        ctx = _build_engagement_from_roe(data, "/tmp/roe.yaml")
        assert ctx.engagement_id == ""

    def test_authorizer_missing_raises_validation_error(self):
        """Mutant 209 is equivalent — Pydantic rejects empty authorizer.

        Verify that missing authorizer causes ValidationError.
        """
        from pydantic import ValidationError

        data = {
            "engagement_id": "A",
            "authorized_targets": ["x.com"],
            "allowed_tests": ["recon"],
            "start_time_utc": "2025-06-01T00:00:00Z",
            "end_time_utc": "2025-12-31T23:59:59Z",
        }
        with pytest.raises(ValidationError):
            _build_engagement_from_roe(data, "/tmp/roe.yaml")

    def test_authorizer_exact(self):
        """Kills mutant 209 (default '' → 'XXXX')."""
        data = {
            "engagement_id": "A",
            "authorizer": "exact-admin",
            "authorized_targets": ["x.com"],
            "allowed_tests": ["recon"],
            "start_time_utc": "2025-06-01T00:00:00Z",
            "end_time_utc": "2025-12-31T23:59:59Z",
        }
        ctx = _build_engagement_from_roe(data, "/tmp/roe.yaml")
        assert ctx.authorizer == "exact-admin"

    def test_empty_targets_uses_placeholder(self):
        """Kills mutants 210-211 (placeholder value and or→and)."""
        data = {
            "engagement_id": "NO-T",
            "authorizer": "admin",
            "authorized_targets": [],
            "allowed_tests": ["recon"],
            "start_time_utc": "2025-06-01T00:00:00Z",
            "end_time_utc": "2025-12-31T23:59:59Z",
        }
        ctx = _build_engagement_from_roe(data, "/tmp/roe.yaml")
        assert ctx.targets == ["placeholder.invalid"]

    def test_allowed_tests_exact_key(self):
        """Kills mutant 212 (allowed_tests key XX mutation)."""
        data = {
            "engagement_id": "AT",
            "authorizer": "admin",
            "authorized_targets": ["x.com"],
            "allowed_tests": ["sast", "dast"],
            "start_time_utc": "2025-06-01T00:00:00Z",
            "end_time_utc": "2025-12-31T23:59:59Z",
        }
        ctx = _build_engagement_from_roe(data, "/tmp/roe.yaml")
        assert ctx.allowed_tests == ["sast", "dast"]

    def test_allowed_tests_default(self):
        """Kills mutant 213 (default ['passive-recon'] → ['XXpassive-reconXX'])."""
        data = {
            "engagement_id": "DEF",
            "authorizer": "admin",
            "authorized_targets": ["x.com"],
            # No allowed_tests key
            "start_time_utc": "2025-06-01T00:00:00Z",
            "end_time_utc": "2025-12-31T23:59:59Z",
        }
        ctx = _build_engagement_from_roe(data, "/tmp/roe.yaml")
        assert ctx.allowed_tests == ["passive-recon"]

    def test_end_time_utc_key_exact(self):
        """Kills mutant 215 (end_time_utc key XX mutation)."""
        data = {
            "engagement_id": "END",
            "authorizer": "admin",
            "authorized_targets": ["x.com"],
            "allowed_tests": ["recon"],
            "start_time_utc": "2025-06-01T00:00:00Z",
            "end_time_utc": "2025-12-31T23:59:59Z",
        }
        ctx = _build_engagement_from_roe(data, "/tmp/roe.yaml")
        assert ctx.end_time_utc.year == 2025
        assert ctx.end_time_utc.month == 12

    def test_sensitivity_key_exact(self):
        """Kills mutant 216 (sensitivity key XX mutation)."""
        data = {
            "engagement_id": "S",
            "authorizer": "admin",
            "authorized_targets": ["x.com"],
            "allowed_tests": ["recon"],
            "start_time_utc": "2025-06-01T00:00:00Z",
            "end_time_utc": "2025-12-31T23:59:59Z",
            "sensitivity": "high",
        }
        ctx = _build_engagement_from_roe(data, "/tmp/roe.yaml")
        assert ctx.sensitivity == "high"

    def test_sensitivity_default(self):
        """Kills mutant 217 (default 'standard' → 'XXstandardXX')."""
        data = {
            "engagement_id": "SD",
            "authorizer": "admin",
            "authorized_targets": ["x.com"],
            "allowed_tests": ["recon"],
            "start_time_utc": "2025-06-01T00:00:00Z",
            "end_time_utc": "2025-12-31T23:59:59Z",
        }
        ctx = _build_engagement_from_roe(data, "/tmp/roe.yaml")
        assert ctx.sensitivity == "standard"

    def test_roe_path_stored(self):
        """Verify roe_path is stored correctly."""
        data = {
            "engagement_id": "RP",
            "authorizer": "admin",
            "authorized_targets": ["x.com"],
            "allowed_tests": ["recon"],
            "start_time_utc": "2025-06-01T00:00:00Z",
            "end_time_utc": "2025-12-31T23:59:59Z",
        }
        ctx = _build_engagement_from_roe(data, "/my/roe.yaml")
        assert ctx.roe_path == "/my/roe.yaml"
        assert ctx.roe_signed is True


# ===================================================================
# _current_engagement init value — kills mutants 21-22
# ===================================================================


class TestOrchestratorInitMutations:
    def test_initial_engagement_is_none(self):
        """Kills mutant 22 (_current_engagement = None → '')."""
        orch = Orchestrator()
        assert orch.current_engagement is None
        assert orch._current_engagement is None
