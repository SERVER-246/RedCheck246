"""Tests for Module 5.1 — Multi-Tenant Isolation.

Coverage targets:
  - Tenant ID validation (valid, invalid, edge-cases)
  - Path isolation & traversal prevention
  - Directory creation with 0o700 permissions
  - Cross-tenant access detection
  - Enforcement convenience function
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from redcheck.config import RedCheckConfig
from redcheck.constants import TENANT_DIR_MODE
from redcheck.core.multi_tenant import (
    TenantFilesystemManager,
    TenantIDValidationError,
    enforce_tenant_isolation,
    get_tenant_manager,
    validate_tenant_id,
)
from redcheck.exceptions import TenantIsolationError

# ═══════════════════════════════════════════════════════════════════
# Tenant ID Validation
# ═══════════════════════════════════════════════════════════════════


class TestValidateTenantID:
    """Tests for validate_tenant_id()."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("Acme", "acme"),
            ("tenant-1", "tenant-1"),
            ("my_org.prod", "my_org.prod"),
            ("AB", "ab"),  # minimum 2 chars
            ("a" * 64, "a" * 64),  # max 64 chars
            ("T1", "t1"),
            ("org.unit-01", "org.unit-01"),
            ("x0", "x0"),
        ],
    )
    def test_valid_ids(self, raw: str, expected: str) -> None:
        assert validate_tenant_id(raw) == expected

    @pytest.mark.parametrize(
        ("bad_id", "reason_fragment"),
        [
            (None, "must not be None"),
            ("", "must not be empty"),
            ("   ", "must not be empty"),
            ("a", "at least 2"),  # too short
            ("a" * 65, "at most 64"),  # too long
            ("../etc", "must not contain '..'"),
            ("tenant/evil", "must not contain path separator"),
            ("tenant\\evil", "must not contain path separator"),
            (".hidden", "must match pattern"),  # starts with dot
            ("-dash", "must match pattern"),  # starts with dash
            ("bad!", "must match pattern"),  # special char
            ("tenant\x00id", "must not contain null"),
        ],
    )
    def test_invalid_ids(self, bad_id: str | None, reason_fragment: str) -> None:
        with pytest.raises(TenantIDValidationError, match=reason_fragment):
            validate_tenant_id(bad_id)

    def test_non_string_rejected(self) -> None:
        with pytest.raises(TenantIDValidationError, match="must be a string"):
            validate_tenant_id(12345)  # type: ignore[arg-type]

    def test_normalisation_is_lowercase(self) -> None:
        assert validate_tenant_id("MyTenant") == "mytenant"


# ═══════════════════════════════════════════════════════════════════
# TenantFilesystemManager — provisioning
# ═══════════════════════════════════════════════════════════════════


class TestTenantProvisioning:
    """Tests for TenantFilesystemManager.provision_tenant()."""

    def test_provision_creates_subdirs(self, tmp_path: Path) -> None:
        mgr = TenantFilesystemManager(tmp_path)
        tenant_dir = mgr.provision_tenant("alpha")

        for sub in TenantFilesystemManager.SUBDIRS:
            assert (tenant_dir / sub).is_dir(), f"Missing subdir: {sub}"

    def test_provision_directory_permissions(self, tmp_path: Path) -> None:
        mgr = TenantFilesystemManager(tmp_path)
        tenant_dir = mgr.provision_tenant("bravo")

        # Check root tenant dir
        mode = tenant_dir.stat().st_mode
        expected = stat.S_IFDIR | TENANT_DIR_MODE
        if os.name != "nt":
            # On POSIX, full permission check
            assert mode == expected, f"Expected {oct(expected)}, got {oct(mode)}"
        else:
            # On Windows, just verify the dir exists (chmod is best-effort)
            assert tenant_dir.is_dir()

    def test_provision_subdirectory_permissions(self, tmp_path: Path) -> None:
        mgr = TenantFilesystemManager(tmp_path)
        tenant_dir = mgr.provision_tenant("charlie")

        for sub in TenantFilesystemManager.SUBDIRS:
            subdir = tenant_dir / sub
            mode = subdir.stat().st_mode
            if os.name != "nt":
                expected = stat.S_IFDIR | TENANT_DIR_MODE
                assert mode == expected, f"{sub}: expected {oct(expected)}, got {oct(mode)}"
            else:
                assert subdir.is_dir()

    def test_provision_idempotent(self, tmp_path: Path) -> None:
        mgr = TenantFilesystemManager(tmp_path)
        path1 = mgr.provision_tenant("delta")
        path2 = mgr.provision_tenant("delta")
        assert path1 == path2

    def test_provision_invalid_id_rejected(self, tmp_path: Path) -> None:
        mgr = TenantFilesystemManager(tmp_path)
        with pytest.raises(TenantIDValidationError):
            mgr.provision_tenant("../escape")


# ═══════════════════════════════════════════════════════════════════
# TenantFilesystemManager — tenant listing and existence
# ═══════════════════════════════════════════════════════════════════


class TestTenantListing:
    """Tests for list_tenants() and tenant_exists()."""

    def test_list_empty(self, tmp_path: Path) -> None:
        mgr = TenantFilesystemManager(tmp_path)
        assert mgr.list_tenants() == []

    def test_list_after_provision(self, tmp_path: Path) -> None:
        mgr = TenantFilesystemManager(tmp_path)
        mgr.provision_tenant("zeta")
        mgr.provision_tenant("alpha")
        # Should be sorted alphabetically
        assert mgr.list_tenants() == ["alpha", "zeta"]

    def test_tenant_exists_true(self, tmp_path: Path) -> None:
        mgr = TenantFilesystemManager(tmp_path)
        mgr.provision_tenant("echo")
        assert mgr.tenant_exists("echo") is True

    def test_tenant_exists_false(self, tmp_path: Path) -> None:
        mgr = TenantFilesystemManager(tmp_path)
        assert mgr.tenant_exists("nope") is False


# ═══════════════════════════════════════════════════════════════════
# TenantFilesystemManager — path isolation
# ═══════════════════════════════════════════════════════════════════


class TestPathIsolation:
    """Tests for path resolution and traversal blocking."""

    def test_valid_relative_path(self, tmp_path: Path) -> None:
        mgr = TenantFilesystemManager(tmp_path)
        mgr.provision_tenant("foxtrot")

        result = mgr.resolve_tenant_path("foxtrot", "evidence/scan.json")
        assert str(result).endswith("foxtrot/evidence/scan.json") or str(result).endswith(
            "foxtrot\\evidence\\scan.json"
        )

    def test_traversal_blocked(self, tmp_path: Path) -> None:
        mgr = TenantFilesystemManager(tmp_path)
        mgr.provision_tenant("golf")

        with pytest.raises(TenantIsolationError):
            mgr.resolve_tenant_path("golf", "../../etc/passwd")

    def test_traversal_with_encoded_dots(self, tmp_path: Path) -> None:
        mgr = TenantFilesystemManager(tmp_path)
        mgr.provision_tenant("hotel")

        with pytest.raises(TenantIsolationError):
            mgr.resolve_tenant_path("hotel", "evidence/../../../etc/shadow")

    def test_assert_tenant_access_valid(self, tmp_path: Path) -> None:
        mgr = TenantFilesystemManager(tmp_path)
        tenant_dir = mgr.provision_tenant("india")
        valid_path = tenant_dir / "evidence" / "report.json"

        # Should not raise
        mgr.assert_tenant_access("india", valid_path)

    def test_assert_tenant_access_denied(self, tmp_path: Path) -> None:
        mgr = TenantFilesystemManager(tmp_path)
        mgr.provision_tenant("juliet")

        outside_path = tmp_path / "other_tenant" / "secret.txt"
        with pytest.raises(TenantIsolationError):
            mgr.assert_tenant_access("juliet", outside_path)

    def test_get_tenant_dir_not_found(self, tmp_path: Path) -> None:
        mgr = TenantFilesystemManager(tmp_path)
        with pytest.raises(FileNotFoundError):
            mgr.get_tenant_dir("nonexistent")

    def test_get_tenant_subdir_invalid_name(self, tmp_path: Path) -> None:
        mgr = TenantFilesystemManager(tmp_path)
        mgr.provision_tenant("kilo")
        with pytest.raises(ValueError, match="Unknown tenant subdirectory"):
            mgr.get_tenant_subdir("kilo", "secrets")

    def test_get_tenant_subdir_success(self, tmp_path: Path) -> None:
        mgr = TenantFilesystemManager(tmp_path)
        mgr.provision_tenant("lima")
        result = mgr.get_tenant_subdir("lima", "evidence")
        assert result.name == "evidence"
        assert result.is_dir()


# ═══════════════════════════════════════════════════════════════════
# Cross-Tenant Access
# ═══════════════════════════════════════════════════════════════════


class TestCrossTenantAccess:
    """Tests for cross_tenant_check() and cross-tenant scenarios."""

    def test_same_tenant_allowed(self, tmp_path: Path) -> None:
        mgr = TenantFilesystemManager(tmp_path)
        # Should not raise
        mgr.cross_tenant_check("alpha", "Alpha")  # Case normalisation

    def test_different_tenant_denied(self, tmp_path: Path) -> None:
        mgr = TenantFilesystemManager(tmp_path)
        with pytest.raises(TenantIsolationError):
            mgr.cross_tenant_check("alpha", "bravo")

    def test_tenant_a_cannot_access_tenant_b_path(self, tmp_path: Path) -> None:
        mgr = TenantFilesystemManager(tmp_path)
        mgr.provision_tenant("tenant-a")
        tenant_b_dir = mgr.provision_tenant("tenant-b")

        with pytest.raises(TenantIsolationError):
            mgr.assert_tenant_access("tenant-a", tenant_b_dir / "evidence" / "secret.json")


# ═══════════════════════════════════════════════════════════════════
# Convenience Functions
# ═══════════════════════════════════════════════════════════════════


class TestEnforceTenantIsolation:
    """Tests for the enforce_tenant_isolation() one-shot function."""

    def test_disabled_returns_default(self) -> None:
        cfg = RedCheckConfig(multi_tenant_enabled=False, default_tenant_id="default")
        result = enforce_tenant_isolation(cfg, None)
        assert result == "default"

    def test_enabled_no_tenant_id_raises(self) -> None:
        cfg = RedCheckConfig(multi_tenant_enabled=True, default_tenant_id="default")
        with pytest.raises(TenantIsolationError):
            enforce_tenant_isolation(cfg, None)

    def test_enabled_empty_tenant_id_raises(self) -> None:
        cfg = RedCheckConfig(multi_tenant_enabled=True, default_tenant_id="default")
        with pytest.raises(TenantIsolationError):
            enforce_tenant_isolation(cfg, "")

    def test_enabled_valid_tenant_id(self, tmp_path: Path) -> None:
        cfg = RedCheckConfig(
            multi_tenant_enabled=True,
            default_tenant_id="default",
            project_root=tmp_path,
        )
        result = enforce_tenant_isolation(cfg, "acme-corp")
        assert result == "acme-corp"

    def test_enabled_with_target_path_isolation(self, tmp_path: Path) -> None:
        cfg = RedCheckConfig(
            multi_tenant_enabled=True,
            default_tenant_id="default",
            project_root=tmp_path,
        )
        # Create tenant dir structure
        mgr = get_tenant_manager(cfg)
        mgr.provision_tenant("acme-corp")
        valid_path = tmp_path / "tenants" / "acme-corp" / "evidence" / "scan.json"

        # Should not raise for path within tenant
        result = enforce_tenant_isolation(cfg, "acme-corp", target_path=valid_path)
        assert result == "acme-corp"

    def test_enabled_with_target_path_outside_raises(self, tmp_path: Path) -> None:
        cfg = RedCheckConfig(
            multi_tenant_enabled=True,
            default_tenant_id="default",
            project_root=tmp_path,
        )
        mgr = get_tenant_manager(cfg)
        mgr.provision_tenant("acme-corp")

        evil_path = tmp_path / "other" / "steal.txt"
        with pytest.raises(TenantIsolationError):
            enforce_tenant_isolation(cfg, "acme-corp", target_path=evil_path)


class TestGetTenantManager:
    """Tests for get_tenant_manager() factory."""

    def test_returns_manager_instance(self, tmp_path: Path) -> None:
        cfg = RedCheckConfig(project_root=tmp_path, multi_tenant_enabled=True)
        mgr = get_tenant_manager(cfg)
        assert isinstance(mgr, TenantFilesystemManager)
        assert mgr.base_dir == tmp_path.resolve()

    def test_disabled_skips_creation(self, tmp_path: Path) -> None:
        cfg = RedCheckConfig(project_root=tmp_path, multi_tenant_enabled=False)
        mgr = get_tenant_manager(cfg)
        assert isinstance(mgr, TenantFilesystemManager)
