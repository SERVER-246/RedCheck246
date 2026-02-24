"""RedCheck246 — Role-Based Access Control (Module 5.2).

Implements a strict 5-role × 6-action permission matrix with no
implicit inheritance.  Each role is explicitly mapped to its exact
set of allowed actions.

Roles:
  VIEWER           — Read-only access to reports.
  OPERATOR         — Can run PASSIVE scans.
  SENIOR_OPERATOR  — Can run PASSIVE + ACTIVE scans.
  ADMIN            — Full access, including DESTRUCTIVE (with confirm) + tenant management.
  AUDITOR          — Read reports + export evidence for compliance.

Actions:
  read_reports     — View scan reports and findings.
  run_passive      — Execute PASSIVE-capability plugins.
  run_active       — Execute ACTIVE-capability plugins.
  run_destructive  — Execute DESTRUCTIVE-capability plugins (ADMIN only, requires confirmation).
  manage_tenants   — Create / modify / delete tenants.
  export_evidence  — Export evidence artifacts and audit trails.
"""

from __future__ import annotations

from enum import Enum

import structlog

from redcheck.exceptions import PolicyDeniedException
from redcheck.models import OperatorRole, PluginCapability

log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Action Enum
# ---------------------------------------------------------------------------


class RBACAction(str, Enum):
    """Fine-grained RBAC actions."""

    READ_REPORTS = "read_reports"
    RUN_PASSIVE = "run_passive"
    RUN_ACTIVE = "run_active"
    RUN_DESTRUCTIVE = "run_destructive"
    MANAGE_TENANTS = "manage_tenants"
    EXPORT_EVIDENCE = "export_evidence"


# ---------------------------------------------------------------------------
# Permission Matrix — explicit, no inheritance
# ---------------------------------------------------------------------------

# Each role maps to the set of actions it is allowed to perform.
# There is NO implicit role hierarchy — every grant is explicit.

_PERMISSION_MATRIX: dict[OperatorRole, frozenset[RBACAction]] = {
    OperatorRole.VIEWER: frozenset(
        {
            RBACAction.READ_REPORTS,
        }
    ),
    OperatorRole.OPERATOR: frozenset(
        {
            RBACAction.READ_REPORTS,
            RBACAction.RUN_PASSIVE,
        }
    ),
    OperatorRole.SENIOR_OPERATOR: frozenset(
        {
            RBACAction.READ_REPORTS,
            RBACAction.RUN_PASSIVE,
            RBACAction.RUN_ACTIVE,
        }
    ),
    OperatorRole.ADMIN: frozenset(
        {
            RBACAction.READ_REPORTS,
            RBACAction.RUN_PASSIVE,
            RBACAction.RUN_ACTIVE,
            RBACAction.RUN_DESTRUCTIVE,
            RBACAction.MANAGE_TENANTS,
            RBACAction.EXPORT_EVIDENCE,
        }
    ),
    OperatorRole.AUDITOR: frozenset(
        {
            RBACAction.READ_REPORTS,
            RBACAction.EXPORT_EVIDENCE,
        }
    ),
}


# ---------------------------------------------------------------------------
# Capability → Action mapping
# ---------------------------------------------------------------------------

_CAPABILITY_ACTION_MAP: dict[PluginCapability, RBACAction] = {
    PluginCapability.PASSIVE: RBACAction.RUN_PASSIVE,
    PluginCapability.ACTIVE: RBACAction.RUN_ACTIVE,
    PluginCapability.DESTRUCTIVE: RBACAction.RUN_DESTRUCTIVE,
}


# ---------------------------------------------------------------------------
# RBACEnforcer
# ---------------------------------------------------------------------------


class RBACEnforcer:
    """Stateless RBAC checker against the permission matrix.

    Usage::

        enforcer = RBACEnforcer()
        enforcer.check(OperatorRole.VIEWER, RBACAction.RUN_ACTIVE)  # raises
        enforcer.is_allowed(OperatorRole.ADMIN, RBACAction.RUN_DESTRUCTIVE)  # True
    """

    def __init__(
        self,
        *,
        require_destructive_confirmation: bool = True,
    ) -> None:
        self._require_destructive_confirmation = require_destructive_confirmation

    # ── Query ─────────────────────────────────────────────────────

    def is_allowed(self, role: OperatorRole, action: RBACAction) -> bool:
        """Check whether *role* is permitted to perform *action*.

        Returns True if allowed, False otherwise.
        This method never raises for permission denial.
        """
        allowed = _PERMISSION_MATRIX.get(role, frozenset())
        return action in allowed

    def get_allowed_actions(self, role: OperatorRole) -> frozenset[RBACAction]:
        """Return the set of actions explicitly granted to *role*."""
        return _PERMISSION_MATRIX.get(role, frozenset())

    def get_allowed_roles_for_action(self, action: RBACAction) -> list[OperatorRole]:
        """Return all roles that are allowed to perform *action*."""
        return [role for role, actions in _PERMISSION_MATRIX.items() if action in actions]

    # ── Enforcement ───────────────────────────────────────────────

    def check(
        self,
        role: OperatorRole,
        action: RBACAction,
        *,
        confirmed: bool = False,
        engagement_id: str | None = None,
    ) -> None:
        """Enforce the permission matrix.  Raises on denial.

        For DESTRUCTIVE actions, the caller must additionally set
        ``confirmed=True`` unless ``require_destructive_confirmation``
        is disabled.

        Raises:
            PolicyDeniedException: If the role does not have the action.
        """
        if not self.is_allowed(role, action):
            log.warning(
                "rbac_denied",
                role=role.value,
                action=action.value,
                engagement_id=engagement_id,
            )
            raise PolicyDeniedException(
                plugin_name="rbac",
                reason=(f"Role '{role.value}' is not authorized for action '{action.value}'"),
                engagement_id=engagement_id,
            )

        # DESTRUCTIVE confirmation gate
        if (
            action == RBACAction.RUN_DESTRUCTIVE
            and self._require_destructive_confirmation
            and not confirmed
        ):
            log.warning(
                "rbac_destructive_unconfirmed",
                role=role.value,
                engagement_id=engagement_id,
            )
            raise PolicyDeniedException(
                plugin_name="rbac",
                reason=("DESTRUCTIVE actions require explicit confirmation (pass confirmed=True)"),
                engagement_id=engagement_id,
            )

        log.debug(
            "rbac_allowed",
            role=role.value,
            action=action.value,
            engagement_id=engagement_id,
        )

    def check_plugin_capability(
        self,
        role: OperatorRole,
        capability: PluginCapability,
        *,
        confirmed: bool = False,
        engagement_id: str | None = None,
    ) -> None:
        """Convenience: check whether *role* may run a plugin with *capability*.

        Maps PluginCapability → RBACAction and delegates to ``check()``.
        """
        action = _CAPABILITY_ACTION_MAP.get(capability)
        if action is None:
            raise ValueError(f"Unknown plugin capability: {capability}")
        self.check(role, action, confirmed=confirmed, engagement_id=engagement_id)

    # ── Audit helpers ─────────────────────────────────────────────

    def describe_matrix(self) -> dict[str, list[str]]:
        """Return a serializable representation of the full permission matrix."""
        return {
            role.value: sorted(a.value for a in actions)
            for role, actions in _PERMISSION_MATRIX.items()
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_enforcer: RBACEnforcer | None = None


def get_rbac_enforcer(
    *,
    require_destructive_confirmation: bool = True,
) -> RBACEnforcer:
    """Get or create the global RBAC enforcer instance."""
    global _enforcer  # noqa: PLW0603
    if _enforcer is None:
        _enforcer = RBACEnforcer(
            require_destructive_confirmation=require_destructive_confirmation,
        )
    return _enforcer


def reset_rbac_enforcer() -> None:
    """Reset global enforcer — for test isolation only."""
    global _enforcer  # noqa: PLW0603
    _enforcer = None
