"""Tests for Module 5.2 — Role-Based Access Control.

Coverage targets:
  - All 30 role × action combos (parametrized)
  - Unauthorized access raises PolicyDeniedException
  - No implicit inheritance (each role checked explicitly)
  - DESTRUCTIVE confirmation gate
  - Capability mapping convenience
  - Matrix introspection
"""

from __future__ import annotations

import pytest

from redcheck.core.rbac import (
    _PERMISSION_MATRIX,
    RBACAction,
    RBACEnforcer,
    get_rbac_enforcer,
    reset_rbac_enforcer,
)
from redcheck.exceptions import PolicyDeniedException
from redcheck.models import OperatorRole, PluginCapability

# ═══════════════════════════════════════════════════════════════════
# Full 30-case Permission Matrix (5 roles × 6 actions)
# ═══════════════════════════════════════════════════════════════════

# fmt: off
_EXPECTED_MATRIX: list[tuple[OperatorRole, RBACAction, bool]] = [
    # VIEWER — read_reports only
    (OperatorRole.VIEWER, RBACAction.READ_REPORTS,    True),
    (OperatorRole.VIEWER, RBACAction.RUN_PASSIVE,     False),
    (OperatorRole.VIEWER, RBACAction.RUN_ACTIVE,      False),
    (OperatorRole.VIEWER, RBACAction.RUN_DESTRUCTIVE, False),
    (OperatorRole.VIEWER, RBACAction.MANAGE_TENANTS,  False),
    (OperatorRole.VIEWER, RBACAction.EXPORT_EVIDENCE, False),

    # OPERATOR — read_reports + run_passive
    (OperatorRole.OPERATOR, RBACAction.READ_REPORTS,    True),
    (OperatorRole.OPERATOR, RBACAction.RUN_PASSIVE,     True),
    (OperatorRole.OPERATOR, RBACAction.RUN_ACTIVE,      False),
    (OperatorRole.OPERATOR, RBACAction.RUN_DESTRUCTIVE, False),
    (OperatorRole.OPERATOR, RBACAction.MANAGE_TENANTS,  False),
    (OperatorRole.OPERATOR, RBACAction.EXPORT_EVIDENCE, False),

    # SENIOR_OPERATOR — read_reports + run_passive + run_active
    (OperatorRole.SENIOR_OPERATOR, RBACAction.READ_REPORTS,    True),
    (OperatorRole.SENIOR_OPERATOR, RBACAction.RUN_PASSIVE,     True),
    (OperatorRole.SENIOR_OPERATOR, RBACAction.RUN_ACTIVE,      True),
    (OperatorRole.SENIOR_OPERATOR, RBACAction.RUN_DESTRUCTIVE, False),
    (OperatorRole.SENIOR_OPERATOR, RBACAction.MANAGE_TENANTS,  False),
    (OperatorRole.SENIOR_OPERATOR, RBACAction.EXPORT_EVIDENCE, False),

    # ADMIN — all actions
    (OperatorRole.ADMIN, RBACAction.READ_REPORTS,    True),
    (OperatorRole.ADMIN, RBACAction.RUN_PASSIVE,     True),
    (OperatorRole.ADMIN, RBACAction.RUN_ACTIVE,      True),
    (OperatorRole.ADMIN, RBACAction.RUN_DESTRUCTIVE, True),
    (OperatorRole.ADMIN, RBACAction.MANAGE_TENANTS,  True),
    (OperatorRole.ADMIN, RBACAction.EXPORT_EVIDENCE, True),

    # AUDITOR — read_reports + export_evidence
    (OperatorRole.AUDITOR, RBACAction.READ_REPORTS,    True),
    (OperatorRole.AUDITOR, RBACAction.RUN_PASSIVE,     False),
    (OperatorRole.AUDITOR, RBACAction.RUN_ACTIVE,      False),
    (OperatorRole.AUDITOR, RBACAction.RUN_DESTRUCTIVE, False),
    (OperatorRole.AUDITOR, RBACAction.MANAGE_TENANTS,  False),
    (OperatorRole.AUDITOR, RBACAction.EXPORT_EVIDENCE, True),
]
# fmt: on


class TestPermissionMatrix:
    """All 30 role × action combinations."""

    @pytest.mark.parametrize(
        ("role", "action", "expected"),
        _EXPECTED_MATRIX,
        ids=[f"{r.value}_{a.value}" for r, a, _ in _EXPECTED_MATRIX],
    )
    def test_matrix_combo(
        self,
        role: OperatorRole,
        action: RBACAction,
        expected: bool,
    ) -> None:
        enforcer = RBACEnforcer(require_destructive_confirmation=False)
        assert enforcer.is_allowed(role, action) is expected


# ═══════════════════════════════════════════════════════════════════
# Enforcement (check raises on denial)
# ═══════════════════════════════════════════════════════════════════


class TestEnforcement:
    """Tests for RBACEnforcer.check() raising on denial."""

    def test_viewer_run_active_denied(self) -> None:
        enforcer = RBACEnforcer()
        with pytest.raises(PolicyDeniedException, match="not authorized"):
            enforcer.check(OperatorRole.VIEWER, RBACAction.RUN_ACTIVE)

    def test_operator_run_active_denied(self) -> None:
        enforcer = RBACEnforcer()
        with pytest.raises(PolicyDeniedException, match="not authorized"):
            enforcer.check(OperatorRole.OPERATOR, RBACAction.RUN_ACTIVE)

    def test_senior_operator_run_destructive_denied(self) -> None:
        enforcer = RBACEnforcer()
        with pytest.raises(PolicyDeniedException, match="not authorized"):
            enforcer.check(OperatorRole.SENIOR_OPERATOR, RBACAction.RUN_DESTRUCTIVE)

    def test_auditor_manage_tenants_denied(self) -> None:
        enforcer = RBACEnforcer()
        with pytest.raises(PolicyDeniedException, match="not authorized"):
            enforcer.check(OperatorRole.AUDITOR, RBACAction.MANAGE_TENANTS)

    def test_admin_all_allowed(self) -> None:
        enforcer = RBACEnforcer(require_destructive_confirmation=False)
        for action in RBACAction:
            enforcer.check(OperatorRole.ADMIN, action)  # Should not raise

    def test_viewer_read_reports_allowed(self) -> None:
        enforcer = RBACEnforcer()
        enforcer.check(OperatorRole.VIEWER, RBACAction.READ_REPORTS)  # Should not raise


# ═══════════════════════════════════════════════════════════════════
# DESTRUCTIVE Confirmation Gate
# ═══════════════════════════════════════════════════════════════════


class TestDestructiveConfirmation:
    """DESTRUCTIVE actions require explicit confirmation for ADMIN."""

    def test_admin_destructive_unconfirmed_denied(self) -> None:
        enforcer = RBACEnforcer(require_destructive_confirmation=True)
        with pytest.raises(PolicyDeniedException, match="confirmation"):
            enforcer.check(OperatorRole.ADMIN, RBACAction.RUN_DESTRUCTIVE)

    def test_admin_destructive_confirmed_allowed(self) -> None:
        enforcer = RBACEnforcer(require_destructive_confirmation=True)
        enforcer.check(OperatorRole.ADMIN, RBACAction.RUN_DESTRUCTIVE, confirmed=True)

    def test_admin_destructive_confirmation_disabled(self) -> None:
        enforcer = RBACEnforcer(require_destructive_confirmation=False)
        enforcer.check(OperatorRole.ADMIN, RBACAction.RUN_DESTRUCTIVE)

    def test_viewer_destructive_denied_before_confirm_check(self) -> None:
        """VIEWER is denied by the matrix, not by the confirmation gate."""
        enforcer = RBACEnforcer(require_destructive_confirmation=True)
        with pytest.raises(PolicyDeniedException, match="not authorized"):
            enforcer.check(OperatorRole.VIEWER, RBACAction.RUN_DESTRUCTIVE, confirmed=True)


# ═══════════════════════════════════════════════════════════════════
# Capability Mapping
# ═══════════════════════════════════════════════════════════════════


class TestCapabilityMapping:
    """check_plugin_capability() convenience method."""

    def test_passive_allowed_for_operator(self) -> None:
        enforcer = RBACEnforcer()
        enforcer.check_plugin_capability(OperatorRole.OPERATOR, PluginCapability.PASSIVE)

    def test_active_denied_for_operator(self) -> None:
        enforcer = RBACEnforcer()
        with pytest.raises(PolicyDeniedException):
            enforcer.check_plugin_capability(OperatorRole.OPERATOR, PluginCapability.ACTIVE)

    def test_destructive_for_admin_with_confirm(self) -> None:
        enforcer = RBACEnforcer(require_destructive_confirmation=True)
        enforcer.check_plugin_capability(
            OperatorRole.ADMIN,
            PluginCapability.DESTRUCTIVE,
            confirmed=True,
        )

    def test_active_for_senior_operator(self) -> None:
        enforcer = RBACEnforcer()
        enforcer.check_plugin_capability(
            OperatorRole.SENIOR_OPERATOR,
            PluginCapability.ACTIVE,
        )


# ═══════════════════════════════════════════════════════════════════
# Introspection
# ═══════════════════════════════════════════════════════════════════


class TestIntrospection:
    """Tests for describe_matrix() and get_allowed_roles_for_action()."""

    def test_describe_matrix_all_roles_present(self) -> None:
        enforcer = RBACEnforcer()
        matrix = enforcer.describe_matrix()
        for role in OperatorRole:
            assert role.value in matrix

    def test_describe_matrix_admin_has_all(self) -> None:
        enforcer = RBACEnforcer()
        matrix = enforcer.describe_matrix()
        admin_actions = set(matrix["admin"])
        all_actions = {a.value for a in RBACAction}
        assert admin_actions == all_actions

    def test_get_allowed_roles_for_read_reports(self) -> None:
        enforcer = RBACEnforcer()
        roles = enforcer.get_allowed_roles_for_action(RBACAction.READ_REPORTS)
        # All roles can read reports
        assert set(roles) == set(OperatorRole)

    def test_get_allowed_roles_for_manage_tenants(self) -> None:
        enforcer = RBACEnforcer()
        roles = enforcer.get_allowed_roles_for_action(RBACAction.MANAGE_TENANTS)
        assert roles == [OperatorRole.ADMIN]

    def test_get_allowed_actions_viewer(self) -> None:
        enforcer = RBACEnforcer()
        actions = enforcer.get_allowed_actions(OperatorRole.VIEWER)
        assert actions == frozenset({RBACAction.READ_REPORTS})

    def test_get_allowed_actions_auditor(self) -> None:
        enforcer = RBACEnforcer()
        actions = enforcer.get_allowed_actions(OperatorRole.AUDITOR)
        assert actions == frozenset({RBACAction.READ_REPORTS, RBACAction.EXPORT_EVIDENCE})


# ═══════════════════════════════════════════════════════════════════
# No Implicit Inheritance
# ═══════════════════════════════════════════════════════════════════


class TestNoImplicitInheritance:
    """Verify that roles do NOT implicitly inherit from one another."""

    def test_operator_does_not_inherit_active(self) -> None:
        """OPERATOR has PASSIVE but must NOT get ACTIVE (which SENIOR_OPERATOR has)."""
        enforcer = RBACEnforcer()
        assert enforcer.is_allowed(OperatorRole.OPERATOR, RBACAction.RUN_ACTIVE) is False

    def test_senior_operator_no_destructive(self) -> None:
        """SENIOR_OPERATOR has ACTIVE but must NOT get DESTRUCTIVE."""
        enforcer = RBACEnforcer()
        result = enforcer.is_allowed(
            OperatorRole.SENIOR_OPERATOR, RBACAction.RUN_DESTRUCTIVE
        )
        assert result is False

    def test_auditor_no_run_passive(self) -> None:
        """AUDITOR has export_evidence but must NOT get run_passive."""
        enforcer = RBACEnforcer()
        assert enforcer.is_allowed(OperatorRole.AUDITOR, RBACAction.RUN_PASSIVE) is False

    def test_matrix_complete_coverage(self) -> None:
        """Every role is explicitly present in the permission matrix."""
        for role in OperatorRole:
            assert role in _PERMISSION_MATRIX, f"Role {role} missing from permission matrix"


# ═══════════════════════════════════════════════════════════════════
# Singleton
# ═══════════════════════════════════════════════════════════════════


class TestSingleton:
    """Tests for get_rbac_enforcer() / reset_rbac_enforcer()."""

    def test_singleton_returns_same_instance(self) -> None:
        reset_rbac_enforcer()
        e1 = get_rbac_enforcer()
        e2 = get_rbac_enforcer()
        assert e1 is e2

    def test_reset_creates_new_instance(self) -> None:
        reset_rbac_enforcer()
        e1 = get_rbac_enforcer()
        reset_rbac_enforcer()
        e2 = get_rbac_enforcer()
        assert e1 is not e2

    def test_engagement_id_propagated(self) -> None:
        enforcer = RBACEnforcer()
        with pytest.raises(PolicyDeniedException) as exc_info:
            enforcer.check(
                OperatorRole.VIEWER,
                RBACAction.RUN_ACTIVE,
                engagement_id="eng-001",
            )
        assert exc_info.value.engagement_id == "eng-001"
