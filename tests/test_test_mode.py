"""Tests for the Test Mode Controller (redcheck.core.test_mode)."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from redcheck.core.orchestrator import Orchestrator
from redcheck.core.otp_engine import OTPChallenge, OTPEngine, reset_otp_engine
from redcheck.core.test_mode import TestModeController, TestModeReport
from redcheck.exceptions import (
    ChainModeError,
    ConfigurationError,
    OTPVerificationError,
)
from redcheck.models import (
    EngagementContext,
    OffensiveControls,
    PluginCapability,
    PluginResult,
    RuntimeMode,
)


@pytest.fixture(autouse=True)
def _reset_otp():
    reset_otp_engine()
    yield
    reset_otp_engine()


def _make_engagement(
    *,
    mode: RuntimeMode = RuntimeMode.TEST,
    otp_email: str | None = "op@example.com",
) -> EngagementContext:
    """Create a minimal valid EngagementContext for tests."""
    return EngagementContext(
        engagement_id="test-eng-1",
        authorizer="Test Authorizer",
        targets=["192.168.1.0/24"],
        allowed_tests=["passive_recon", "dast_scanner"],
        start_time_utc=datetime.now(timezone.utc) - timedelta(hours=1),
        end_time_utc=datetime.now(timezone.utc) + timedelta(hours=1),
        roe_signed=True,
        activation_verified=True,
        session_code="TEST-SESSION",
        runtime_mode=mode,
        otp_email=otp_email,
        offensive_controls=OffensiveControls(
            allow_auth_testing=True,
            allow_exploit_validation=True,
        ),
    )


def _make_result(plugin_name: str, *, success: bool = True) -> PluginResult:
    return PluginResult(plugin_name=plugin_name, success=success)


class TestTestModeReport:
    def test_report_fields(self):
        now = datetime.now(timezone.utc)
        r = TestModeReport(
            engagement_id="eng-1",
            plugins_executed=["a", "b"],
            plugins_skipped=["c"],
            total_findings=5,
            total_evidence=2,
            otp_challenges=1,
            otp_verified=1,
            otp_cancelled=0,
            start_time=now - timedelta(seconds=10),
            end_time=now,
        )
        assert r.duration_seconds == pytest.approx(10.0)
        assert r.runtime_mode == "test"

    def test_report_default_factory(self):
        r = TestModeReport(engagement_id="eng-1")
        assert r.plugins_executed == []
        assert r.total_findings == 0


class TestTestModeController:
    def test_reject_non_test_mode(self):
        eng = _make_engagement(mode=RuntimeMode.DEV)
        orch = MagicMock(spec=Orchestrator)
        otp = MagicMock(spec=OTPEngine)
        ctrl = TestModeController(orch, otp)

        with pytest.raises(ConfigurationError, match="RuntimeMode.TEST"):
            asyncio.run(ctrl.run_test_mode(eng, ["passive_recon"]))

    @patch("redcheck.core.test_mode.PluginRegistry")
    def test_skip_unknown_plugin(self, mock_registry):
        mock_registry.get_instance.return_value = None

        eng = _make_engagement()
        orch = MagicMock(spec=Orchestrator)
        otp = MagicMock(spec=OTPEngine)
        ctrl = TestModeController(orch, otp)

        report = asyncio.run(ctrl.run_test_mode(eng, ["nonexistent_plugin"]))
        assert "nonexistent_plugin" in report.plugins_skipped
        assert report.plugins_executed == []

    @patch("redcheck.core.test_mode.PluginRegistry")
    def test_passive_plugin_no_otp(self, mock_registry):
        """PASSIVE plugins should NOT trigger the OTP gate."""
        mock_plugin = MagicMock()
        mock_plugin.capability = PluginCapability.PASSIVE
        mock_registry.get_instance.return_value = mock_plugin

        orch = MagicMock(spec=Orchestrator)
        orch.arun_plugin = AsyncMock(return_value=_make_result("passive_recon"))

        otp = MagicMock(spec=OTPEngine)
        ctrl = TestModeController(orch, otp)
        eng = _make_engagement()

        report = asyncio.run(ctrl.run_test_mode(eng, ["passive_recon"]))
        assert "passive_recon" in report.plugins_executed
        otp.generate_otp.assert_not_called()

    @patch("redcheck.core.test_mode.PluginRegistry")
    def test_destructive_plugin_otp_verified(self, mock_registry):
        """DESTRUCTIVE plugin: user provides correct OTP → plugin executes."""
        mock_plugin = MagicMock()
        mock_plugin.capability = PluginCapability.DESTRUCTIVE
        mock_registry.get_instance.return_value = mock_plugin

        orch = MagicMock(spec=Orchestrator)
        orch.arun_plugin = AsyncMock(return_value=_make_result("exploit_plugin"))

        otp = OTPEngine(smtp_host="localhost", otp_length=6)
        # Generate a real challenge so verify works
        challenge, code = otp.generate_otp("test-eng-1", "exploit_plugin")

        # Mock generate_otp to return our pre-made challenge
        otp_mock = MagicMock(spec=OTPEngine)
        otp_mock.generate_otp.return_value = (challenge, code)
        otp_mock.send_otp.return_value = True
        otp_mock.verify_otp.return_value = True

        ctrl = TestModeController(orch, otp_mock, prompt_callback=lambda _: code)
        eng = _make_engagement()

        report = asyncio.run(ctrl.run_test_mode(eng, ["exploit_plugin"]))
        assert "exploit_plugin" in report.plugins_executed
        assert report.otp_challenges == 1
        assert report.otp_verified == 1

    @patch("redcheck.core.test_mode.PluginRegistry")
    def test_destructive_plugin_otp_cancelled(self, mock_registry):
        """DESTRUCTIVE plugin: user enters 'cancel' → plugin skipped."""
        mock_plugin = MagicMock()
        mock_plugin.capability = PluginCapability.DESTRUCTIVE
        mock_registry.get_instance.return_value = mock_plugin

        orch = MagicMock(spec=Orchestrator)
        otp = MagicMock(spec=OTPEngine)
        otp.generate_otp.return_value = (
            OTPChallenge(
                code_hash="abc",
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
                attempts_remaining=3,
                engagement_id="test-eng-1",
                plugin_name="exploit",
                challenge_id="chal-1",
            ),
            "123456",
        )
        otp.send_otp.return_value = True

        ctrl = TestModeController(orch, otp, prompt_callback=lambda _: "cancel")
        eng = _make_engagement()

        report = asyncio.run(ctrl.run_test_mode(eng, ["exploit"]))
        assert "exploit" in report.plugins_skipped
        assert report.otp_cancelled == 1
        orch.arun_plugin.assert_not_called()

    @patch("redcheck.core.test_mode.PluginRegistry")
    def test_destructive_plugin_otp_failed(self, mock_registry):
        """DESTRUCTIVE plugin: wrong OTP → plugin skipped."""
        mock_plugin = MagicMock()
        mock_plugin.capability = PluginCapability.DESTRUCTIVE
        mock_registry.get_instance.return_value = mock_plugin

        orch = MagicMock(spec=Orchestrator)
        otp = MagicMock(spec=OTPEngine)
        otp.generate_otp.return_value = (
            OTPChallenge(
                code_hash="abc",
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
                attempts_remaining=3,
                engagement_id="test-eng-1",
                plugin_name="exploit",
                challenge_id="chal-2",
            ),
            "123456",
        )
        otp.send_otp.return_value = True
        otp.verify_otp.side_effect = OTPVerificationError(
            attempts_remaining=2,
            challenge_id="chal-2",
            engagement_id="test-eng-1",
        )

        ctrl = TestModeController(orch, otp, prompt_callback=lambda _: "wrong")
        eng = _make_engagement()

        report = asyncio.run(ctrl.run_test_mode(eng, ["exploit"]))
        assert "exploit" in report.plugins_skipped
        assert report.plugins_executed == []

    @patch("redcheck.core.test_mode.PluginRegistry")
    def test_destructive_no_otp_email_skips(self, mock_registry):
        """DESTRUCTIVE plugin without otp_email → plugin skipped."""
        mock_plugin = MagicMock()
        mock_plugin.capability = PluginCapability.DESTRUCTIVE
        mock_registry.get_instance.return_value = mock_plugin

        orch = MagicMock(spec=Orchestrator)
        otp = MagicMock(spec=OTPEngine)
        ctrl = TestModeController(orch, otp)
        eng = _make_engagement(otp_email=None)

        report = asyncio.run(ctrl.run_test_mode(eng, ["exploit"]))
        assert "exploit" in report.plugins_skipped

    @patch("redcheck.core.test_mode.PluginRegistry")
    def test_chain_mode_flag(self, mock_registry):
        """Chain mode flag is reflected in report."""
        mock_plugin = MagicMock()
        mock_plugin.capability = PluginCapability.PASSIVE
        mock_registry.get_instance.return_value = mock_plugin

        orch = MagicMock(spec=Orchestrator)
        orch.arun_plugin = AsyncMock(return_value=_make_result("p1"))

        otp = MagicMock(spec=OTPEngine)
        ctrl = TestModeController(orch, otp)
        eng = _make_engagement()
        eng = eng.model_copy(
            update={
                "offensive_controls": OffensiveControls(
                    allow_auth_testing=True,
                    allow_exploit_validation=True,
                    chain_mode=True,
                )
            }
        )

        report = asyncio.run(ctrl.run_test_mode(eng, ["p1"], chain=True))
        assert report.chain_mode is True

    @patch("redcheck.core.test_mode.PluginRegistry")
    def test_chain_mode_rejected_without_offensive_control(self, mock_registry):
        """Chain mode with chain_mode=False in OffensiveControls raises ChainModeError."""
        mock_plugin = MagicMock()
        mock_plugin.capability = PluginCapability.PASSIVE
        mock_registry.get_instance.return_value = mock_plugin

        orch = MagicMock(spec=Orchestrator)
        otp = MagicMock(spec=OTPEngine)
        ctrl = TestModeController(orch, otp)
        eng = _make_engagement()
        # Explicitly disable chain_mode to test rejection
        eng = eng.model_copy(
            update={
                "offensive_controls": OffensiveControls(
                    chain_mode=False,
                    allow_auth_testing=True,
                    allow_exploit_validation=True,
                )
            }
        )

        with pytest.raises(ChainModeError):
            asyncio.run(ctrl.run_test_mode(eng, ["p1"], chain=True))

    @patch("redcheck.core.test_mode.PluginRegistry")
    def test_plugin_execution_failure_handled(self, mock_registry):
        """Plugin that raises → skipped, not crash."""
        mock_plugin = MagicMock()
        mock_plugin.capability = PluginCapability.PASSIVE
        mock_registry.get_instance.return_value = mock_plugin

        orch = MagicMock(spec=Orchestrator)
        orch.arun_plugin = AsyncMock(side_effect=RuntimeError("boom"))

        otp = MagicMock(spec=OTPEngine)
        ctrl = TestModeController(orch, otp)
        eng = _make_engagement()

        report = asyncio.run(ctrl.run_test_mode(eng, ["failing_plug"], chain=False))
        assert "failing_plug" in report.plugins_skipped

    @patch("redcheck.core.test_mode.PluginRegistry")
    def test_dry_run_forwarded(self, mock_registry):
        """dry_run flag is forwarded to orchestrator."""
        mock_plugin = MagicMock()
        mock_plugin.capability = PluginCapability.PASSIVE
        mock_registry.get_instance.return_value = mock_plugin

        orch = MagicMock(spec=Orchestrator)
        orch.arun_plugin = AsyncMock(return_value=_make_result("p1"))

        otp = MagicMock(spec=OTPEngine)
        ctrl = TestModeController(orch, otp)
        eng = _make_engagement()

        asyncio.run(ctrl.run_test_mode(eng, ["p1"], dry_run=True, chain=False))
        orch.arun_plugin.assert_called_once_with("p1", eng, dry_run=True)

    @patch("redcheck.core.test_mode.PluginRegistry")
    def test_multiple_plugins_mixed(self, mock_registry):
        """Mix of PASSIVE + DESTRUCTIVE plugins (cancelled) → correct counts."""
        passive = MagicMock()
        passive.capability = PluginCapability.PASSIVE
        destructive = MagicMock()
        destructive.capability = PluginCapability.DESTRUCTIVE

        def side_effect(name):
            return passive if name == "recon" else destructive

        mock_registry.get_instance.side_effect = side_effect

        orch = MagicMock(spec=Orchestrator)
        orch.arun_plugin = AsyncMock(return_value=_make_result("recon"))

        otp = MagicMock(spec=OTPEngine)
        otp.generate_otp.return_value = (
            OTPChallenge(
                code_hash="x",
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
                attempts_remaining=3,
                engagement_id="test-eng-1",
                plugin_name="exploit",
                challenge_id="c-1",
            ),
            "111111",
        )
        otp.send_otp.return_value = True

        ctrl = TestModeController(orch, otp, prompt_callback=lambda _: "cancel")
        eng = _make_engagement()

        report = asyncio.run(ctrl.run_test_mode(eng, ["recon", "exploit"]))
        assert "recon" in report.plugins_executed
        assert "exploit" in report.plugins_skipped
        assert report.otp_cancelled == 1
