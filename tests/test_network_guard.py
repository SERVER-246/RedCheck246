"""Tests for NetworkGuard — scope validation, port validation, anti-pivot."""

from __future__ import annotations

import pytest

from redcheck.core.network_guard import NetworkGuard  # noqa: I001

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def guard() -> NetworkGuard:
    """NetworkGuard with a simple scope."""
    return NetworkGuard(["192.168.1.0/24", "testhost.local"])


@pytest.fixture
def guard_with_ports() -> NetworkGuard:
    """NetworkGuard with explicit port allowlist."""
    return NetworkGuard(
        ["10.0.0.0/8"],
        allowed_ports=[80, 443, 8080],
    )


# ---------------------------------------------------------------------------
# check_destination — host scope
# ---------------------------------------------------------------------------


class TestCheckDestinationHost:
    """Validate host scope enforcement."""

    def test_allows_ip_in_scope(self, guard: NetworkGuard):
        assert guard.check_destination("192.168.1.10", 80) is True

    def test_allows_hostname_in_scope(self, guard: NetworkGuard):
        assert guard.check_destination("testhost.local", 443) is True

    def test_denies_ip_out_of_scope(self, guard: NetworkGuard):
        assert guard.check_destination("10.0.0.1", 80) is False

    def test_denies_hostname_out_of_scope(self, guard: NetworkGuard):
        assert guard.check_destination("evil.example.com", 80) is False

    def test_allows_cidr_boundary_ip(self, guard: NetworkGuard):
        assert guard.check_destination("192.168.1.1", 80) is True
        assert guard.check_destination("192.168.1.254", 80) is True


# ---------------------------------------------------------------------------
# check_destination — port validation
# ---------------------------------------------------------------------------


class TestCheckDestinationPort:
    """Validate port range and allowlist enforcement."""

    def test_rejects_port_zero(self, guard: NetworkGuard):
        assert guard.check_destination("192.168.1.10", 0) is False

    def test_rejects_negative_port(self, guard: NetworkGuard):
        assert guard.check_destination("192.168.1.10", -1) is False

    def test_rejects_port_above_65535(self, guard: NetworkGuard):
        assert guard.check_destination("192.168.1.10", 70000) is False

    def test_allows_valid_port_without_allowlist(self, guard: NetworkGuard):
        assert guard.check_destination("192.168.1.10", 8888) is True

    def test_allows_port_in_allowlist(self, guard_with_ports: NetworkGuard):
        assert guard_with_ports.check_destination("10.0.0.1", 80) is True
        assert guard_with_ports.check_destination("10.0.0.1", 443) is True
        assert guard_with_ports.check_destination("10.0.0.1", 8080) is True

    def test_denies_port_not_in_allowlist(self, guard_with_ports: NetworkGuard):
        assert guard_with_ports.check_destination("10.0.0.1", 22) is False
        assert guard_with_ports.check_destination("10.0.0.1", 3306) is False


# ---------------------------------------------------------------------------
# check_inbound — anti-pivot
# ---------------------------------------------------------------------------


class TestCheckInbound:
    """Anti-pivot: inbound connections always denied."""

    def test_inbound_always_denied(self, guard: NetworkGuard):
        assert guard.check_inbound(80) is False
        assert guard.check_inbound(443) is False
        assert guard.check_inbound(8080) is False

    def test_inbound_denied_any_port(self):
        g = NetworkGuard(["0.0.0.0/0"])
        assert g.check_inbound(1) is False
        assert g.check_inbound(65535) is False


# ---------------------------------------------------------------------------
# authorized_scope property
# ---------------------------------------------------------------------------


class TestAuthorizedScope:
    """Verify authorized_scope returns a safe copy."""

    def test_returns_scope_list(self, guard: NetworkGuard):
        scope = guard.authorized_scope
        assert scope == ["192.168.1.0/24", "testhost.local"]

    def test_returns_copy_not_reference(self, guard: NetworkGuard):
        scope = guard.authorized_scope
        scope.append("evil.com")
        assert "evil.com" not in guard.authorized_scope

    def test_empty_scope(self):
        g = NetworkGuard([])
        assert g.authorized_scope == []


# ---------------------------------------------------------------------------
# Constructor edge cases
# ---------------------------------------------------------------------------


class TestConstructor:
    """Guard construction edge cases."""

    def test_empty_allowed_ports_treated_as_none(self):
        g = NetworkGuard(["10.0.0.0/8"], allowed_ports=[])
        # Empty list → frozenset is falsy, so allowed_ports is None
        # and any valid port is accepted
        assert g.check_destination("10.0.0.1", 9999) is True

    def test_single_host_scope(self):
        g = NetworkGuard(["192.168.1.1"])
        assert g.check_destination("192.168.1.1", 80) is True
        assert g.check_destination("192.168.1.2", 80) is False
