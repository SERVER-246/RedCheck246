"""Mutation-killing tests for ``redcheck.core.policy_engine``.

Every test in this file asserts **exact** return values, message strings,
and side effects.  The goal is to kill every mutant that mutmut generates
— no test should pass if any string, boolean, comparison operator, or
return value is changed.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from redcheck.core.policy_engine import PolicyEngine, get_policy_engine
from redcheck.exceptions import PolicyDeniedException

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_roe(path: Path, data: dict) -> Path:
    roe_file = path / "roe.yml"
    roe_file.write_text(yaml.dump(data, default_flow_style=False), encoding="utf-8")
    return roe_file


def _valid_roe_data() -> dict:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return {
        "engagement_id": "ENG-1",
        "authorizer": "admin@test.com",
        "authorized_targets": ["10.0.0.1"],
        "allowed_tests": ["recon", "sast"],
        "start_time_utc": (now - timedelta(hours=1)).isoformat(),
        "end_time_utc": (now + timedelta(hours=1)).isoformat(),
        "signature": "abc123",
    }


def _valid_engagement() -> dict:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return {
        "roe_validated": True,
        "activation_verified": True,
        "allowed_tests": ["recon", "sast"],
        "start_time_utc": (now - timedelta(hours=1)).isoformat(),
        "end_time_utc": (now + timedelta(hours=1)).isoformat(),
    }


# ===================================================================
# validate_roe — exact return value assertions
# ===================================================================


class TestValidateRoeReturnValues:
    """Kill string-mutation and boolean-mutation survivors."""

    def test_valid_roe_returns_exact_tuple(self, tmp_path: Path) -> None:
        pe = PolicyEngine()
        roe_file = _write_roe(tmp_path, _valid_roe_data())
        valid, msg, data = pe.validate_roe(roe_file)
        assert valid is True
        assert msg == "RoE is valid"
        assert isinstance(data, dict)
        assert data["engagement_id"] == "ENG-1"
        assert data["authorizer"] == "admin@test.com"
        assert data["authorized_targets"] == ["10.0.0.1"]
        assert data["signature"] == "abc123"

    def test_file_not_found_returns_exact_message(self, tmp_path: Path) -> None:
        pe = PolicyEngine()
        missing = tmp_path / "nope.yml"
        valid, msg, data = pe.validate_roe(missing)
        assert valid is False
        assert msg == f"RoE file not found: {missing}"
        assert data == {}

    def test_invalid_yaml_returns_exact_prefix(self, tmp_path: Path) -> None:
        f = tmp_path / "roe.yml"
        f.write_text("{{{{", encoding="utf-8")
        pe = PolicyEngine()
        valid, msg, data = pe.validate_roe(f)
        assert valid is False
        assert msg.startswith("Invalid YAML in RoE:")
        assert data == {}

    def test_not_dict_returns_exact_message(self, tmp_path: Path) -> None:
        f = tmp_path / "roe.yml"
        f.write_text("- list_item\n", encoding="utf-8")
        pe = PolicyEngine()
        valid, msg, data = pe.validate_roe(f)
        assert valid is False
        assert msg == "RoE must be a YAML dictionary"
        assert data == {}

    def test_missing_fields_returns_exact_message(self, tmp_path: Path) -> None:
        roe_file = _write_roe(tmp_path, {"engagement_id": "E1"})
        pe = PolicyEngine()
        valid, msg, data = pe.validate_roe(roe_file)
        assert valid is False
        assert msg.startswith("Missing required RoE fields:")
        # Verify join uses ", " separator — kills mutant 24
        assert ", " in msg
        # Verify each missing field is listed
        for field in ["authorizer", "authorized_targets", "allowed_tests",
                       "start_time_utc", "end_time_utc"]:
            assert field in msg
        assert data == {}

    def test_missing_fields_exact_separator(self, tmp_path: Path) -> None:
        """Kills mutant 24 — join separator ', ' → 'XX, XX'.

        Use exactly two missing fields so we can check the exact separator.
        """
        d = _valid_roe_data()
        del d["authorizer"]
        del d["signature"]  # signature is not in required list, skip
        del d["allowed_tests"]
        roe_file = _write_roe(tmp_path, d)
        pe = PolicyEngine()
        valid, msg, data = pe.validate_roe(roe_file)
        assert valid is False
        # The joined part must be "authorizer, allowed_tests" exactly
        # If the mutant changes ', ' to 'XX, XX' we'd see 'authorizerXX, XXallowed_tests'
        assert "XX" not in msg
        assert "authorizer, allowed_tests" in msg or "allowed_tests, authorizer" in msg

    def test_empty_authorizer_returns_exact_message(self, tmp_path: Path) -> None:
        d = _valid_roe_data()
        d["authorizer"] = "  "
        roe_file = _write_roe(tmp_path, d)
        pe = PolicyEngine()
        valid, msg, data = pe.validate_roe(roe_file)
        assert valid is False
        assert msg == "Authorizer must be a non-empty string"
        assert data == {}

    def test_int_authorizer_returns_exact_message(self, tmp_path: Path) -> None:
        d = _valid_roe_data()
        d["authorizer"] = 123
        roe_file = _write_roe(tmp_path, d)
        pe = PolicyEngine()
        valid, msg, data = pe.validate_roe(roe_file)
        assert valid is False
        assert msg == "Authorizer must be a non-empty string"

    def test_targets_not_list_returns_exact_message(self, tmp_path: Path) -> None:
        d = _valid_roe_data()
        d["authorized_targets"] = "single"
        roe_file = _write_roe(tmp_path, d)
        pe = PolicyEngine()
        valid, msg, data = pe.validate_roe(roe_file)
        assert valid is False
        assert msg == "authorized_targets must be a non-empty list"
        assert data == {}

    def test_targets_empty_list_returns_exact_message(self, tmp_path: Path) -> None:
        d = _valid_roe_data()
        d["authorized_targets"] = []
        roe_file = _write_roe(tmp_path, d)
        pe = PolicyEngine()
        valid, msg, data = pe.validate_roe(roe_file)
        assert valid is False
        assert msg == "authorized_targets must be a non-empty list"

    def test_invalid_time_format_returns_exact_prefix(self, tmp_path: Path) -> None:
        d = _valid_roe_data()
        d["start_time_utc"] = "not-a-date"
        roe_file = _write_roe(tmp_path, d)
        pe = PolicyEngine()
        valid, msg, data = pe.validate_roe(roe_file)
        assert valid is False
        assert msg.startswith("Invalid time format in RoE:")
        assert data == {}

    def test_expired_roe_returns_exact_message(self, tmp_path: Path) -> None:
        d = _valid_roe_data()
        now = datetime.now(timezone.utc).replace(microsecond=0)
        d["start_time_utc"] = (now - timedelta(hours=2)).isoformat()
        d["end_time_utc"] = (now - timedelta(hours=1)).isoformat()
        roe_file = _write_roe(tmp_path, d)
        pe = PolicyEngine()
        valid, msg, data = pe.validate_roe(roe_file)
        assert valid is False
        assert msg.startswith("RoE has expired (end_time:")
        # data is the parsed roe dict, not empty
        assert isinstance(data, dict)
        assert data.get("engagement_id") == "ENG-1"

    def test_no_signature_field_returns_exact_message(self, tmp_path: Path) -> None:
        d = _valid_roe_data()
        del d["signature"]
        roe_file = _write_roe(tmp_path, d)
        pe = PolicyEngine()
        valid, msg, data = pe.validate_roe(roe_file)
        assert valid is False
        assert msg == "RoE must contain a 'signature' field"
        # Should return the parsed roe data even though invalid
        assert data.get("engagement_id") == "ENG-1"

    def test_z_suffix_start_time_parsed_correctly(self, tmp_path: Path) -> None:
        """Kills mutants 44, 126 (Z suffix detection)."""
        d = _valid_roe_data()
        now = datetime.now(timezone.utc).replace(microsecond=0)
        d["start_time_utc"] = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        d["end_time_utc"] = (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        roe_file = _write_roe(tmp_path, d)
        pe = PolicyEngine()
        valid, msg, data = pe.validate_roe(roe_file)
        assert valid is True
        assert msg == "RoE is valid"

    def test_z_suffix_end_time_only(self, tmp_path: Path) -> None:
        """Kills mutant 50 (end Z suffix)."""
        d = _valid_roe_data()
        now = datetime.now(timezone.utc).replace(microsecond=0)
        d["start_time_utc"] = (now - timedelta(hours=1)).isoformat()
        d["end_time_utc"] = (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        roe_file = _write_roe(tmp_path, d)
        pe = PolicyEngine()
        valid, msg, data = pe.validate_roe(roe_file)
        assert valid is True
        assert msg == "RoE is valid"

    def test_naive_datetime_gets_utc_tzinfo(self, tmp_path: Path) -> None:
        """Kills mutants 61-64 (naive datetime tzinfo assignment).

        Use a naive datetime string (no +00:00 suffix) so the code
        hits the ``start.tzinfo is None`` branch.
        """
        d = _valid_roe_data()
        now = datetime.now(timezone.utc).replace(microsecond=0)
        # Naive ISO string without timezone
        d["start_time_utc"] = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S")
        d["end_time_utc"] = (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S")
        roe_file = _write_roe(tmp_path, d)
        pe = PolicyEngine()
        valid, msg, data = pe.validate_roe(roe_file)
        assert valid is True
        assert msg == "RoE is valid"

    def test_exactly_at_end_time_is_not_expired(self, tmp_path: Path) -> None:
        """Kills mutant 65 (now > end → now >= end).

        The boundary: if now == end, the RoE should NOT be expired (> not >=).
        We mock datetime.now to return exactly end.
        """
        d = _valid_roe_data()
        now = datetime.now(timezone.utc).replace(microsecond=0)
        end_time = now
        d["start_time_utc"] = (now - timedelta(hours=2)).isoformat()
        d["end_time_utc"] = end_time.isoformat()
        roe_file = _write_roe(tmp_path, d)

        pe = PolicyEngine()
        with patch("redcheck.core.policy_engine.datetime") as mock_dt:
            mock_dt.now.return_value = end_time
            mock_dt.fromisoformat = datetime.fromisoformat
            mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)  # noqa: DTZ001
            valid, msg, data = pe.validate_roe(roe_file)

        # With `>`: now == end → not expired → valid
        # With `>=`: now == end → expired → invalid
        assert valid is True
        assert msg == "RoE is valid"


class TestValidateRoeAuditCalls:
    """Kill mutants on log.info and audit.log calls (72-78, 80)."""

    def test_valid_roe_logs_correct_action(self, tmp_path: Path) -> None:
        pe = PolicyEngine()
        pe.audit = MagicMock()
        roe_file = _write_roe(tmp_path, _valid_roe_data())
        valid, msg, data = pe.validate_roe(roe_file)
        assert valid is True

        # Verify audit.log was called with exact action + details
        pe.audit.log.assert_called_once()
        call_kwargs = pe.audit.log.call_args
        assert call_kwargs.kwargs["action"] == "ROE_VALIDATED"
        # Exact match kills mutant 76 (XX prefix/suffix on details)
        assert call_kwargs.kwargs["details"] == "RoE ENG-1 validated successfully"
        assert call_kwargs.kwargs["engagement_id"] == "ENG-1"

    @patch("redcheck.core.policy_engine.log")
    def test_valid_roe_structlog_event(self, mock_log, tmp_path: Path) -> None:
        """Kills mutants 72-73 (log event name and engagement_id key)."""
        pe = PolicyEngine()
        pe.audit = MagicMock()
        roe_file = _write_roe(tmp_path, _valid_roe_data())
        valid, _, _ = pe.validate_roe(roe_file)
        assert valid is True

        mock_log.info.assert_called_once_with(
            "roe_validated", engagement_id="ENG-1"
        )


# ===================================================================
# validate_activation_code
# ===================================================================


class TestValidateActivationCode:
    def test_returns_true_when_engine_verifies(self) -> None:
        pe = PolicyEngine()
        pe.audit = MagicMock()
        mock_engine = MagicMock()
        mock_engine.verify_code.return_value = True
        with patch(
            "redcheck.core.activation_engine.get_activation_engine",
            return_value=mock_engine,
        ):
            result = pe.validate_activation_code("CODE-123")
        assert result is True
        mock_engine.verify_code.assert_called_once_with("CODE-123")
        pe.audit.log_activation_attempt.assert_called_once_with(success=True)

    def test_returns_false_when_engine_rejects(self) -> None:
        pe = PolicyEngine()
        pe.audit = MagicMock()
        mock_engine = MagicMock()
        mock_engine.verify_code.return_value = False
        with patch(
            "redcheck.core.activation_engine.get_activation_engine",
            return_value=mock_engine,
        ):
            result = pe.validate_activation_code("BAD")
        assert result is False
        mock_engine.verify_code.assert_called_once_with("BAD")
        pe.audit.log_activation_attempt.assert_called_once_with(success=False)


# ===================================================================
# is_action_allowed — exact (bool, str) tuple assertions
# ===================================================================


class TestIsActionAllowed:
    """Each test asserts the exact (bool, str) return tuple."""

    def test_no_auth_required_returns_exact_tuple(self) -> None:
        """Kills mutants 90, 93."""
        pe = PolicyEngine()
        allowed, reason = pe.is_action_allowed("any", None, requires_authorization=False)
        assert allowed is True
        assert reason == "Plugin does not require authorization"

    def test_default_requires_authorization_is_true(self) -> None:
        """Kills mutant 90 (default bool=True → False)."""
        pe = PolicyEngine()
        # Call WITHOUT requires_authorization — default should be True
        # With no engagement, this should fail because auth is required
        allowed, reason = pe.is_action_allowed("plugin", None)
        assert allowed is False
        assert reason == "No engagement context provided"

    def test_no_engagement_returns_exact_tuple(self) -> None:
        """Kills mutant 96."""
        pe = PolicyEngine()
        allowed, reason = pe.is_action_allowed("plugin", None, requires_authorization=True)
        assert allowed is False
        assert reason == "No engagement context provided"

    def test_roe_not_validated_returns_exact_tuple(self) -> None:
        """Kills mutants 100, 102."""
        pe = PolicyEngine()
        allowed, reason = pe.is_action_allowed("plugin", {"roe_validated": False})
        assert allowed is False
        assert reason == "RoE has not been validated"

    def test_roe_missing_defaults_to_false(self) -> None:
        """Kills mutant 100 (default False → True)."""
        pe = PolicyEngine()
        # Engagement without roe_validated key
        allowed, reason = pe.is_action_allowed("plugin", {})
        assert allowed is False
        assert reason == "RoE has not been validated"

    def test_activation_not_verified_returns_exact_tuple(self) -> None:
        """Kills mutants 105, 107."""
        pe = PolicyEngine()
        allowed, reason = pe.is_action_allowed(
            "plugin", {"roe_validated": True, "activation_verified": False}
        )
        assert allowed is False
        assert reason == "Activation code has not been verified"

    def test_activation_missing_defaults_to_false(self) -> None:
        """Kills mutant 105 (default False → True)."""
        pe = PolicyEngine()
        allowed, reason = pe.is_action_allowed(
            "plugin", {"roe_validated": True}
        )
        assert allowed is False
        assert reason == "Activation code has not been verified"

    def test_plugin_not_in_allowed_tests_returns_exact_tuple(self) -> None:
        """Kills mutant 118."""
        pe = PolicyEngine()
        eng = _valid_engagement()
        eng["allowed_tests"] = ["recon"]
        allowed, reason = pe.is_action_allowed("exploit", eng)
        assert allowed is False
        assert reason.startswith("Plugin 'exploit' not in allowed tests:")
        assert "recon" in reason

    def test_dotted_plugin_name_uses_first_segment(self) -> None:
        """Kills mutants 110-113 (split('.')[0] logic)."""
        pe = PolicyEngine()
        eng = _valid_engagement()
        eng["allowed_tests"] = ["recon"]
        # Plugin name with dot — should use "recon" (before the dot)
        allowed, reason = pe.is_action_allowed("recon.deep", eng)
        assert allowed is True
        assert reason == "Action authorized"

    def test_dotted_plugin_name_rejected_when_category_not_allowed(self) -> None:
        """Kills mutant 111 (split('.')[0] → split('.')[1])."""
        pe = PolicyEngine()
        eng = _valid_engagement()
        eng["allowed_tests"] = ["recon"]
        # Category is "exploit" (before dot), which is NOT in allowed_tests
        allowed, reason = pe.is_action_allowed("exploit.deep", eng)
        assert allowed is False
        assert "exploit" in reason

    def test_authorized_success_returns_exact_tuple(self) -> None:
        """Kills mutant 153."""
        pe = PolicyEngine()
        eng = _valid_engagement()
        allowed, reason = pe.is_action_allowed("recon", eng)
        assert allowed is True
        assert reason == "Action authorized"

    def test_outside_time_window_before_start(self) -> None:
        """Kills mutant 145 (now < start → now <= start)."""
        now = datetime.now(timezone.utc).replace(microsecond=0)
        pe = PolicyEngine()
        eng = _valid_engagement()
        eng["start_time_utc"] = (now + timedelta(hours=1)).isoformat()
        eng["end_time_utc"] = (now + timedelta(hours=2)).isoformat()
        allowed, reason = pe.is_action_allowed("recon", eng)
        assert allowed is False
        assert "outside engagement window" in reason

    def test_outside_time_window_after_end(self) -> None:
        """Kills mutant 146 (now > end → now >= end)."""
        now = datetime.now(timezone.utc).replace(microsecond=0)
        pe = PolicyEngine()
        eng = _valid_engagement()
        eng["start_time_utc"] = (now - timedelta(hours=2)).isoformat()
        eng["end_time_utc"] = (now - timedelta(hours=1)).isoformat()
        allowed, reason = pe.is_action_allowed("recon", eng)
        assert allowed is False
        assert "outside engagement window" in reason
        assert reason.startswith("Current time outside engagement window (")

    def test_exactly_at_start_time_is_allowed(self) -> None:
        """Kills mutant 145 (now < start → now <= start).

        When now == start exactly: original `<` → False → allowed.
        Mutant `<=` → True → denied.  We assert allowed.
        """
        pe = PolicyEngine()
        fixed_now = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        eng = _valid_engagement()
        eng["start_time_utc"] = fixed_now.isoformat()
        eng["end_time_utc"] = (fixed_now + timedelta(hours=2)).isoformat()
        with patch("redcheck.core.policy_engine.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_now
            mock_dt.fromisoformat = datetime.fromisoformat
            mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)  # noqa: DTZ001
            allowed, reason = pe.is_action_allowed("recon", eng)
        assert allowed is True
        assert reason == "Action authorized"

    def test_exactly_at_end_time_is_allowed(self) -> None:
        """Kills mutant 146 (now > end → now >= end).

        When now == end exactly: original `>` → False → allowed.
        Mutant `>=` → True → denied.  We assert allowed.
        """
        pe = PolicyEngine()
        fixed_now = datetime(2025, 6, 15, 14, 0, 0, tzinfo=timezone.utc)
        eng = _valid_engagement()
        eng["start_time_utc"] = (fixed_now - timedelta(hours=2)).isoformat()
        eng["end_time_utc"] = fixed_now.isoformat()
        with patch("redcheck.core.policy_engine.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_now
            mock_dt.fromisoformat = datetime.fromisoformat
            mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)  # noqa: DTZ001
            allowed, reason = pe.is_action_allowed("recon", eng)
        assert allowed is True
        assert reason == "Action authorized"

    def test_invalid_time_in_engagement_returns_exact_tuple(self) -> None:
        """Kills mutant 151."""
        pe = PolicyEngine()
        eng = _valid_engagement()
        eng["start_time_utc"] = "bad"
        eng["end_time_utc"] = "bad"
        allowed, reason = pe.is_action_allowed("recon", eng)
        assert allowed is False
        assert reason == "Invalid time format in engagement context"

    def test_z_suffix_in_engagement_times(self) -> None:
        """Kills mutants 126-137 (Z suffix handling in is_action_allowed)."""
        now = datetime.now(timezone.utc).replace(microsecond=0)
        pe = PolicyEngine()
        eng = _valid_engagement()
        eng["start_time_utc"] = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        eng["end_time_utc"] = (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        allowed, reason = pe.is_action_allowed("recon", eng)
        assert allowed is True
        assert reason == "Action authorized"

    def test_naive_datetime_in_engagement(self) -> None:
        """Kills mutants 140-143 (naive tz branch in is_action_allowed)."""
        now = datetime.now(timezone.utc).replace(microsecond=0)
        pe = PolicyEngine()
        eng = _valid_engagement()
        eng["start_time_utc"] = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S")
        eng["end_time_utc"] = (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S")
        allowed, reason = pe.is_action_allowed("recon", eng)
        assert allowed is True
        assert reason == "Action authorized"

    def test_empty_allowed_tests_allows_all(self) -> None:
        """When allowed_tests is empty, any plugin should pass."""
        pe = PolicyEngine()
        eng = _valid_engagement()
        eng["allowed_tests"] = []
        allowed, reason = pe.is_action_allowed("anything", eng)
        assert allowed is True
        assert reason == "Action authorized"

    def test_no_time_fields_still_authorizes(self) -> None:
        """Kills mutant 123 (start_str and end_str → or)."""
        pe = PolicyEngine()
        eng = _valid_engagement()
        del eng["start_time_utc"]
        del eng["end_time_utc"]
        allowed, reason = pe.is_action_allowed("recon", eng)
        assert allowed is True
        assert reason == "Action authorized"

    def test_only_start_time_skips_window_check(self) -> None:
        """Kills mutant 123 (and → or). With only start_str, should skip."""
        pe = PolicyEngine()
        eng = _valid_engagement()
        del eng["end_time_utc"]
        allowed, reason = pe.is_action_allowed("recon", eng)
        assert allowed is True
        assert reason == "Action authorized"

    def test_only_end_time_skips_window_check(self) -> None:
        """With only end_str, should also skip (both needed for `and`)."""
        pe = PolicyEngine()
        eng = _valid_engagement()
        del eng["start_time_utc"]
        allowed, reason = pe.is_action_allowed("recon", eng)
        assert allowed is True
        assert reason == "Action authorized"


# ===================================================================
# authorize — PolicyDeniedException assertions
# ===================================================================


class TestAuthorize:
    """Verify authorize() raises PolicyDeniedException with correct reason."""

    def test_authorize_succeeds_without_raising(self) -> None:
        pe = PolicyEngine()
        eng = _valid_engagement()
        # Should not raise
        pe.authorize("recon", engagement=eng)

    def test_authorize_no_engagement_raises_with_reason(self) -> None:
        pe = PolicyEngine()
        pe.audit = MagicMock()
        with pytest.raises(PolicyDeniedException) as exc_info:
            pe.authorize("test-plugin", engagement=None)
        assert "No engagement context provided" in str(exc_info.value)

    def test_authorize_logs_policy_denied(self) -> None:
        """Kills mutants 86-89 (log + audit action/details/level)."""
        pe = PolicyEngine()
        pe.audit = MagicMock()
        with pytest.raises(PolicyDeniedException):
            pe.authorize("test-plugin", engagement=None)
        pe.audit.log.assert_called_once()
        call_kwargs = pe.audit.log.call_args.kwargs
        assert call_kwargs["action"] == "POLICY_DENIED"
        # Exact match kills mutant 88 (XX prefix/suffix on details)
        assert call_kwargs["details"] == "test-plugin: No engagement context provided"
        assert call_kwargs["level"] == "WARN"

    @patch("redcheck.core.policy_engine.log")
    def test_authorize_structlog_event(self, mock_log) -> None:
        """Kills mutant 86 (log.warning event name mutation)."""
        pe = PolicyEngine()
        pe.audit = MagicMock()
        with pytest.raises(PolicyDeniedException):
            pe.authorize("test-plugin", engagement=None)
        mock_log.warning.assert_called_once_with(
            "policy_denied",
            plugin="test-plugin",
            reason="No engagement context provided",
        )

    def test_authorize_roe_not_validated(self) -> None:
        pe = PolicyEngine()
        with pytest.raises(PolicyDeniedException) as exc_info:
            pe.authorize("p", engagement={"roe_validated": False})
        assert "RoE has not been validated" in str(exc_info.value)

    def test_authorize_activation_not_verified(self) -> None:
        pe = PolicyEngine()
        with pytest.raises(PolicyDeniedException) as exc_info:
            pe.authorize("p", engagement={"roe_validated": True, "activation_verified": False})
        assert "Activation code has not been verified" in str(exc_info.value)

    def test_authorize_plugin_not_allowed(self) -> None:
        pe = PolicyEngine()
        eng = _valid_engagement()
        eng["allowed_tests"] = ["recon"]
        with pytest.raises(PolicyDeniedException) as exc_info:
            pe.authorize("exploit", engagement=eng)
        assert "exploit" in str(exc_info.value)
        assert "not in allowed tests" in str(exc_info.value)

    def test_authorize_no_auth_required_never_raises(self) -> None:
        pe = PolicyEngine()
        # No engagement, but requires_authorization=False → OK
        pe.authorize("anything", engagement=None, requires_authorization=False)


# ===================================================================
# get_policy_engine singleton
# ===================================================================


class TestGetPolicyEngine:
    """Kills mutants 155-159 (singleton logic)."""

    def test_returns_policy_engine_instance(self) -> None:
        PolicyEngine.reset()
        eng = get_policy_engine()
        assert isinstance(eng, PolicyEngine)

    def test_returns_same_instance(self) -> None:
        PolicyEngine.reset()
        eng1 = get_policy_engine()
        eng2 = get_policy_engine()
        assert eng1 is eng2

    def test_reset_clears_singleton(self) -> None:
        """Kills mutant 155 (_policy_engine = None → '')."""
        PolicyEngine.reset()
        eng1 = get_policy_engine()
        PolicyEngine.reset()
        eng2 = get_policy_engine()
        # After reset, a NEW instance should be created
        assert eng1 is not eng2
        assert isinstance(eng2, PolicyEngine)

    def test_reset_makes_singleton_none(self) -> None:
        """Kills mutant 159 (_policy_engine = PolicyEngine() → None)."""
        PolicyEngine.reset()
        _ = get_policy_engine()
        PolicyEngine.reset()
        # After reset, calling get again should create a fresh instance
        eng = get_policy_engine()
        assert isinstance(eng, PolicyEngine)
        PolicyEngine.reset()  # cleanup

    def test_module_level_initial_value_is_none(self) -> None:
        """Kills mutant 157 (_policy_engine = None → '')."""
        import importlib  # noqa: I001

        import redcheck.core.policy_engine as pe_mod

        importlib.reload(pe_mod)
        assert pe_mod._policy_engine is None
        pe_mod.PolicyEngine.reset()  # cleanup
