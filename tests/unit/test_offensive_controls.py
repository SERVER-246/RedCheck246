"""Tests for OffensiveControls model — safe-by-default, frozen, has_controls()."""

from __future__ import annotations

import itertools

import pytest
from pydantic import ValidationError

from redcheck.models import (
    EngagementContext,
    OffensiveControls,
    OperatorRole,
    RuntimeMode,
)

# ---------------------------------------------------------------------------
# Defaults & Safe-by-default
# ---------------------------------------------------------------------------


class TestOffensiveControlsDefaults:
    """Every flag must default to False."""

    def test_all_flags_false_by_default(self):
        oc = OffensiveControls()
        assert oc.allow_auth_testing is False
        assert oc.allow_exploit_validation is False
        assert oc.allow_data_sampling is False
        assert oc.allow_credential_spraying is False
        assert oc.allow_privesc_probing is False
        assert oc.chain_mode is True

    def test_instantiate_with_no_args(self):
        oc = OffensiveControls()
        assert oc is not None

    def test_model_dump_all_false(self):
        oc = OffensiveControls()
        d = oc.model_dump()
        for key, value in d.items():
            if key == "chain_mode":
                assert value is True, "chain_mode should default to True"
            else:
                assert value is False, f"{key} should be False"


# ---------------------------------------------------------------------------
# Frozen model — rejects mutation
# ---------------------------------------------------------------------------


class TestOffensiveControlsFrozen:
    """Frozen model must reject all field assignment."""

    def test_mutation_rejected(self):
        oc = OffensiveControls()
        with pytest.raises(ValidationError):
            oc.allow_auth_testing = True  # type: ignore[misc]

    def test_mutation_chain_mode_rejected(self):
        oc = OffensiveControls(chain_mode=True)
        with pytest.raises(ValidationError):
            oc.chain_mode = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# has_controls() gate
# ---------------------------------------------------------------------------


class TestHasControls:
    """has_controls() must return True only when ALL required flags are True."""

    def test_empty_required_always_true(self):
        oc = OffensiveControls()
        assert oc.has_controls([]) is True

    def test_single_control_missing(self):
        oc = OffensiveControls()
        assert oc.has_controls(["allow_auth_testing"]) is False

    def test_single_control_present(self):
        oc = OffensiveControls(allow_auth_testing=True)
        assert oc.has_controls(["allow_auth_testing"]) is True

    def test_multiple_controls_all_present(self):
        oc = OffensiveControls(
            allow_auth_testing=True,
            allow_exploit_validation=True,
        )
        assert oc.has_controls(["allow_auth_testing", "allow_exploit_validation"]) is True

    def test_multiple_controls_one_missing(self):
        oc = OffensiveControls(allow_auth_testing=True)
        assert oc.has_controls(["allow_auth_testing", "allow_exploit_validation"]) is False

    def test_unknown_control_returns_false(self):
        oc = OffensiveControls(allow_auth_testing=True)
        assert oc.has_controls(["nonexistent_control"]) is False

    def test_all_controls_enabled(self):
        oc = OffensiveControls(
            allow_auth_testing=True,
            allow_exploit_validation=True,
            allow_data_sampling=True,
            allow_credential_spraying=True,
            allow_privesc_probing=True,
            chain_mode=True,
        )
        all_flags = [
            "allow_auth_testing",
            "allow_exploit_validation",
            "allow_data_sampling",
            "allow_credential_spraying",
            "allow_privesc_probing",
            "chain_mode",
        ]
        assert oc.has_controls(all_flags) is True

    @pytest.mark.parametrize(
        "enabled_flags",
        [
            combo
            for r in range(1, 4)
            for combo in itertools.combinations(
                [
                    "allow_auth_testing",
                    "allow_exploit_validation",
                    "allow_data_sampling",
                    "allow_credential_spraying",
                    "allow_privesc_probing",
                    "chain_mode",
                ],
                r,
            )
        ][:20],  # first 20 of 41 combinations
    )
    def test_has_controls_permutations(self, enabled_flags: tuple[str, ...]):
        """Parametrized: enabled flags pass, disabled ones fail."""
        all_flags = {
            "allow_auth_testing",
            "allow_exploit_validation",
            "allow_data_sampling",
            "allow_credential_spraying",
            "allow_privesc_probing",
            "chain_mode",
        }
        # Explicitly set all flags: enabled ones True, rest False
        kwargs = {f: (f in enabled_flags) for f in all_flags}
        oc = OffensiveControls(**kwargs)
        # All enabled flags should pass
        assert oc.has_controls(list(enabled_flags)) is True
        # Any flag NOT in enabled_flags should cause failure
        disabled = all_flags - set(enabled_flags)
        if disabled:
            # Asking for a disabled flag should return False
            assert oc.has_controls([next(iter(disabled))]) is False


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


class TestOffensiveControlsSerialization:
    """Model serialization round-trip."""

    def test_model_dump_round_trip(self):
        oc = OffensiveControls(allow_auth_testing=True, chain_mode=True)
        d = oc.model_dump()
        oc2 = OffensiveControls(**d)
        assert oc == oc2

    def test_json_round_trip(self):
        oc = OffensiveControls(allow_data_sampling=True)
        j = oc.model_dump_json()
        oc2 = OffensiveControls.model_validate_json(j)
        assert oc == oc2


# ---------------------------------------------------------------------------
# OperatorRole enum
# ---------------------------------------------------------------------------


class TestOperatorRole:
    """OperatorRole enum values."""

    def test_all_values(self):
        assert OperatorRole.VIEWER.value == "viewer"
        assert OperatorRole.OPERATOR.value == "operator"
        assert OperatorRole.SENIOR_OPERATOR.value == "senior_operator"
        assert OperatorRole.ADMIN.value == "admin"
        assert OperatorRole.AUDITOR.value == "auditor"

    def test_member_count(self):
        assert len(OperatorRole) == 5


# ---------------------------------------------------------------------------
# RuntimeMode.RESEARCH
# ---------------------------------------------------------------------------


class TestRuntimeModeResearch:
    """RuntimeMode.RESEARCH enum member."""

    def test_research_exists(self):
        assert RuntimeMode.RESEARCH.value == "research"

    def test_all_modes_count(self):
        assert len(RuntimeMode) == 6


# ---------------------------------------------------------------------------
# EngagementContext new fields
# ---------------------------------------------------------------------------


class TestEngagementContextExtensions:
    """Test new fields on EngagementContext."""

    def _make_ctx(self, **kwargs):
        from datetime import timedelta

        now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
        defaults = {
            "engagement_id": "EXT-001",
            "authorizer": "Admin",
            "targets": ["host1.com"],
            "allowed_tests": ["passive-recon"],
            "start_time_utc": now - timedelta(hours=1),
            "end_time_utc": now + timedelta(hours=1),
        }
        defaults.update(kwargs)
        return EngagementContext(**defaults)

    def test_default_offensive_controls(self):
        ctx = self._make_ctx()
        assert isinstance(ctx.offensive_controls, OffensiveControls)
        assert ctx.offensive_controls.allow_auth_testing is False

    def test_custom_offensive_controls(self):
        oc = OffensiveControls(allow_auth_testing=True)
        ctx = self._make_ctx(offensive_controls=oc)
        assert ctx.offensive_controls.allow_auth_testing is True

    def test_safe_mode_default_true(self):
        ctx = self._make_ctx()
        assert ctx.safe_mode is True

    def test_runtime_mode_default_dev(self):
        ctx = self._make_ctx()
        assert ctx.runtime_mode == RuntimeMode.DEV

    def test_tenant_id_default_none(self):
        ctx = self._make_ctx()
        assert ctx.tenant_id is None

    def test_session_id_default_none(self):
        ctx = self._make_ctx()
        assert ctx.session_id is None

    def test_set_tenant_id(self):
        ctx = self._make_ctx(tenant_id="tenant-42")
        assert ctx.tenant_id == "tenant-42"

    def test_set_session_id(self):
        ctx = self._make_ctx(session_id="sess-abc")
        assert ctx.session_id == "sess-abc"


# ---------------------------------------------------------------------------
# New exceptions
# ---------------------------------------------------------------------------


class TestNewExceptions:
    """All 5 new exceptions inherit from RedCheckError."""

    def test_offensive_control_error(self):
        from redcheck.exceptions import OffensiveControlError, RedCheckError

        e = OffensiveControlError("test-plugin", ["allow_auth_testing"])
        assert isinstance(e, RedCheckError)
        assert "allow_auth_testing" in str(e)
        assert e.missing_controls == ["allow_auth_testing"]

    def test_chain_mode_error(self):
        from redcheck.exceptions import ChainModeError, RedCheckError

        e = ChainModeError("test-plugin")
        assert isinstance(e, RedCheckError)
        assert "chain_mode" in str(e)

    def test_isolation_error(self):
        from redcheck.exceptions import IsolationError, RedCheckError

        e = IsolationError("test-plugin")
        assert isinstance(e, RedCheckError)
        assert "isolation" in str(e).lower()

    def test_rate_limit_exceeded(self):
        from redcheck.exceptions import RateLimitExceededError, RedCheckError

        e = RateLimitExceededError("test-plugin", 10.0)
        assert isinstance(e, RedCheckError)
        assert e.rate_limit_rps == 10.0

    def test_tenant_isolation_error(self):
        from redcheck.exceptions import RedCheckError, TenantIsolationError

        e = TenantIsolationError("tenant-a", "tenant-b")
        assert isinstance(e, RedCheckError)
        assert "tenant-a" in str(e)
        assert "tenant-b" in str(e)
