"""RedCheck246 — Multi-Tenant Isolation (Module 5.1).

Enforces strict filesystem isolation between tenants:
  - Each tenant gets a sandboxed directory tree.
  - Path traversal attacks (``../``) are blocked.
  - Tenant IDs are validated against a strict allowlist pattern.
  - Evidence/engagement directories are created with ``0o700`` perms.
  - Cross-tenant access raises ``TenantIsolationError``.
"""

from __future__ import annotations

import os
import re
from typing import TYPE_CHECKING

import structlog

from redcheck.constants import (
    TENANT_DIR_MODE,
    TENANT_ID_MAX_LENGTH,
    TENANT_ID_MIN_LENGTH,
    TENANT_ID_PATTERN,
)
from redcheck.exceptions import TenantIsolationError

if TYPE_CHECKING:
    from pathlib import Path

    from redcheck.config import RedCheckConfig

log = structlog.get_logger(__name__)

# Pre-compiled regex for tenant ID validation
_TENANT_ID_RE = re.compile(TENANT_ID_PATTERN)


# ---------------------------------------------------------------------------
# Tenant ID Validation
# ---------------------------------------------------------------------------


class TenantIDValidationError(ValueError):
    """Raised when a tenant ID fails format validation."""

    def __init__(self, tenant_id: str, reason: str) -> None:
        self.tenant_id = tenant_id
        self.reason = reason
        super().__init__(f"Invalid tenant ID '{tenant_id}': {reason}")


def validate_tenant_id(tenant_id: str | None) -> str:
    """Validate and normalise a tenant identifier.

    Rules:
      - Must not be None, empty, or whitespace-only.
      - Must not contain path separators, ``..``, or null bytes.
      - Must match ``^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}[a-zA-Z0-9]$`` (2–64 chars).
      - Must be lowercase-normalised for consistency.

    Returns:
        The normalised (lowercased) tenant ID.

    Raises:
        TenantIDValidationError: If the tenant ID fails any rule.
    """
    # Null / None / empty
    if tenant_id is None:
        raise TenantIDValidationError("None", "tenant ID must not be None")
    if not isinstance(tenant_id, str):
        raise TenantIDValidationError(str(tenant_id), "tenant ID must be a string")

    stripped = tenant_id.strip()
    if not stripped:
        raise TenantIDValidationError(repr(tenant_id), "tenant ID must not be empty or whitespace")

    # Null bytes
    if "\x00" in stripped:
        raise TenantIDValidationError(repr(stripped), "tenant ID must not contain null bytes")

    # Path traversal sequences
    if ".." in stripped:
        raise TenantIDValidationError(stripped, "tenant ID must not contain '..'")

    # Path separators
    if "/" in stripped or "\\" in stripped:
        raise TenantIDValidationError(stripped, "tenant ID must not contain path separators")

    # Length bounds
    if len(stripped) < TENANT_ID_MIN_LENGTH:
        raise TenantIDValidationError(
            stripped,
            f"tenant ID must be at least {TENANT_ID_MIN_LENGTH} characters",
        )
    if len(stripped) > TENANT_ID_MAX_LENGTH:
        raise TenantIDValidationError(
            stripped,
            f"tenant ID must be at most {TENANT_ID_MAX_LENGTH} characters",
        )

    # Regex pattern
    if not _TENANT_ID_RE.match(stripped):
        raise TenantIDValidationError(
            stripped,
            "tenant ID must match pattern: start/end with alphanumeric, "
            "middle may contain alphanumeric, dots, hyphens, underscores",
        )

    normalised = stripped.lower()
    log.debug("tenant_id_validated", tenant_id=normalised)
    return normalised


# ---------------------------------------------------------------------------
# Tenant Filesystem Manager
# ---------------------------------------------------------------------------


class TenantFilesystemManager:
    """Manages per-tenant directory structures with strict isolation.

    Directory layout::

        <base_dir>/
            tenants/
                <tenant_id>/
                    engagements/
                    evidence/
                    logs/
                    reports/
    """

    SUBDIRS = ("engagements", "evidence", "logs", "reports")

    def __init__(self, base_dir: Path, *, create_if_missing: bool = True) -> None:
        self._base_dir = base_dir.resolve()
        self._tenants_root = self._base_dir / "tenants"
        self._create_if_missing = create_if_missing

        if create_if_missing:
            self._tenants_root.mkdir(parents=True, exist_ok=True)
            self._set_dir_permissions(self._tenants_root)

    @property
    def base_dir(self) -> Path:
        return self._base_dir

    @property
    def tenants_root(self) -> Path:
        return self._tenants_root

    # ── Directory creation ────────────────────────────────────────

    def provision_tenant(self, tenant_id: str) -> Path:
        """Create the full directory tree for a tenant.

        Args:
            tenant_id: Raw tenant identifier (validated internally).

        Returns:
            Path to the tenant's root directory.

        Raises:
            TenantIDValidationError: If tenant_id is invalid.
        """
        safe_id = validate_tenant_id(tenant_id)
        tenant_dir = self._tenants_root / safe_id

        tenant_dir.mkdir(parents=True, exist_ok=True)
        self._set_dir_permissions(tenant_dir)

        for sub in self.SUBDIRS:
            subdir = tenant_dir / sub
            subdir.mkdir(parents=True, exist_ok=True)
            self._set_dir_permissions(subdir)

        log.info("tenant_provisioned", tenant_id=safe_id, path=str(tenant_dir))
        return tenant_dir

    def get_tenant_dir(self, tenant_id: str) -> Path:
        """Get the root directory for a tenant.

        Raises:
            TenantIDValidationError: If the tenant ID is invalid.
            FileNotFoundError: If the tenant directory doesn't exist.
        """
        safe_id = validate_tenant_id(tenant_id)
        tenant_dir = self._tenants_root / safe_id

        if not tenant_dir.exists():
            raise FileNotFoundError(f"Tenant directory not found: {safe_id}")

        return tenant_dir

    def get_tenant_subdir(self, tenant_id: str, subdir: str) -> Path:
        """Get a specific subdirectory for a tenant (e.g., 'evidence').

        Raises:
            TenantIDValidationError: If the tenant ID is invalid.
            ValueError: If the subdir name is not in the allowed list.
            FileNotFoundError: If the directory doesn't exist.
        """
        if subdir not in self.SUBDIRS:
            raise ValueError(f"Unknown tenant subdirectory: '{subdir}'. Allowed: {self.SUBDIRS}")

        safe_id = validate_tenant_id(tenant_id)
        target = self._tenants_root / safe_id / subdir

        if not target.exists():
            raise FileNotFoundError(f"Tenant subdirectory not found: {safe_id}/{subdir}")

        return target

    def list_tenants(self) -> list[str]:
        """List all provisioned tenant IDs."""
        if not self._tenants_root.exists():
            return []
        return sorted(
            d.name
            for d in self._tenants_root.iterdir()
            if d.is_dir() and not d.name.startswith(".")
        )

    def tenant_exists(self, tenant_id: str) -> bool:
        """Check if a tenant is provisioned."""
        safe_id = validate_tenant_id(tenant_id)
        return (self._tenants_root / safe_id).is_dir()

    # ── Path isolation ────────────────────────────────────────────

    def resolve_tenant_path(self, tenant_id: str, relative_path: str) -> Path:
        """Resolve a relative path within a tenant's directory, blocking traversal.

        Args:
            tenant_id: Validated tenant identifier.
            relative_path: Path relative to the tenant root (e.g., ``evidence/scan.json``).

        Returns:
            Absolute, resolved path within the tenant directory.

        Raises:
            TenantIsolationError: If the resolved path escapes the tenant directory.
            TenantIDValidationError: If the tenant ID is invalid.
        """
        safe_id = validate_tenant_id(tenant_id)
        tenant_dir = (self._tenants_root / safe_id).resolve()

        # Normalise and resolve the target path
        candidate = (tenant_dir / relative_path).resolve()

        # Strict containment check
        if not self._is_within(candidate, tenant_dir):
            raise TenantIsolationError(
                requested_tenant=str(candidate),
                current_tenant=safe_id,
            )

        return candidate

    def assert_tenant_access(
        self,
        requesting_tenant: str,
        target_path: Path,
    ) -> None:
        """Assert that a tenant is allowed to access a given path.

        Raises:
            TenantIsolationError: If the path is outside the tenant's directory.
        """
        safe_id = validate_tenant_id(requesting_tenant)
        tenant_dir = (self._tenants_root / safe_id).resolve()
        resolved_target = target_path.resolve()

        if not self._is_within(resolved_target, tenant_dir):
            raise TenantIsolationError(
                requested_tenant=str(resolved_target),
                current_tenant=safe_id,
            )

    def cross_tenant_check(
        self,
        source_tenant: str,
        target_tenant: str,
    ) -> None:
        """Raise if two tenant IDs don't match (cross-tenant access attempt).

        Raises:
            TenantIsolationError: If source ≠ target after normalisation.
        """
        safe_source = validate_tenant_id(source_tenant)
        safe_target = validate_tenant_id(target_tenant)

        if safe_source != safe_target:
            raise TenantIsolationError(
                requested_tenant=safe_target,
                current_tenant=safe_source,
            )

    # ── Internal helpers ──────────────────────────────────────────

    @staticmethod
    def _is_within(child: Path, parent: Path) -> bool:
        """Check that *child* is strictly within *parent* (resolved)."""
        try:
            child.resolve().relative_to(parent.resolve())
            return True
        except ValueError:
            return False

    @staticmethod
    def _set_dir_permissions(path: Path) -> None:
        """Set directory permissions to owner-only (0o700).

        On Windows, this is a best-effort operation since POSIX
        permissions don't fully apply; we still call ``os.chmod``
        for portability and CI validation.
        """
        try:
            os.chmod(path, TENANT_DIR_MODE)
        except OSError:
            log.warning(
                "tenant_dir_chmod_failed",
                path=str(path),
                target_mode=oct(TENANT_DIR_MODE),
            )


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------


def get_tenant_manager(config: RedCheckConfig) -> TenantFilesystemManager:
    """Create a ``TenantFilesystemManager`` from the current RedCheckConfig."""
    base_dir = config.project_root
    return TenantFilesystemManager(base_dir, create_if_missing=config.multi_tenant_enabled)


def enforce_tenant_isolation(
    config: RedCheckConfig,
    engagement_tenant_id: str | None,
    *,
    target_path: Path | None = None,
) -> str:
    """One-shot enforcement suitable for the orchestrator's policy gate.

    1. If multi-tenant is disabled, returns ``config.default_tenant_id``.
    2. Validates the engagement's ``tenant_id``.
    3. If *target_path* is given, asserts it's within the tenant's sandbox.

    Returns:
        The normalised tenant ID.

    Raises:
        TenantIsolationError: On cross-tenant access.
        TenantIDValidationError: On invalid tenant ID.
    """
    if not config.multi_tenant_enabled:
        return config.default_tenant_id

    if not engagement_tenant_id:
        raise TenantIsolationError(
            requested_tenant="(none)",
            current_tenant=config.default_tenant_id,
        )

    safe_id = validate_tenant_id(engagement_tenant_id)
    mgr = get_tenant_manager(config)

    if target_path is not None:
        mgr.assert_tenant_access(safe_id, target_path)

    return safe_id
