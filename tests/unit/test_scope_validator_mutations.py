"""Mutation-killing tests for ``redcheck.core.scope_validator``.

Every test asserts exact return values and targets specific mutmut mutations.
"""

from __future__ import annotations

import pytest

from redcheck.core.scope_validator import ScopeValidator

# ===================================================================
# validate_targets — @staticmethod and control-flow mutations
# ===================================================================


class TestValidateTargetsInstance:
    """Kills mutant 1 (remove @staticmethod from validate_targets).

    Calling via an instance ensures the @staticmethod decorator is present.
    Without @staticmethod the implicit ``self`` eats the first positional arg.
    """

    def test_via_instance(self) -> None:
        sv = ScopeValidator()
        ok, violations = sv.validate_targets(["10.0.0.1"], ["10.0.0.1"])
        assert ok is True
        assert violations == []


class TestValidateTargetsControlFlow:
    """Kill continue → break mutations (12, 13, 19, 23)."""

    def test_empty_auth_entry_then_valid_entry(self) -> None:
        """Kills mutant 12 (continue → break on empty authorized entry).

        If the empty entry causes ``break``, the second valid entry
        ('10.0.0.1') is never processed → target becomes violation.
        """
        ok, violations = ScopeValidator.validate_targets(
            ["10.0.0.1"],
            ["", "10.0.0.1"],
        )
        assert ok is True
        assert violations == []

    def test_ip_auth_then_wildcard_auth(self) -> None:
        """Kills mutant 13 (continue → break after IP parse).

        First authorized entry is an IP.  If ``break`` replaces
        ``continue``, the wildcard entry is never parsed.
        """
        ok, violations = ScopeValidator.validate_targets(
            ["sub.example.com"],
            ["10.0.0.1", "*.example.com"],
        )
        assert ok is True
        assert violations == []

    def test_cidr_auth_then_hostname_auth(self) -> None:
        """Ensure CIDR continue doesn't break before hostname is processed.

        After the CIDR entry parses successfully, the loop must continue
        to also parse the hostname entry.
        """
        ok, violations = ScopeValidator.validate_targets(
            ["example.com"],
            ["10.0.0.0/24", "example.com"],
        )
        assert ok is True
        assert violations == []

    def test_wildcard_auth_then_hostname_auth(self) -> None:
        """Kills mutant 19 (continue → break after wildcard parse).

        First authorized entry is a wildcard.  If ``break`` replaces
        ``continue``, 'other.com' (exact hostname) is never added.
        """
        ok, violations = ScopeValidator.validate_targets(
            ["other.com"],
            ["*.example.com", "other.com"],
        )
        assert ok is True
        assert violations == []

    def test_empty_target_then_oob_target(self) -> None:
        """Kills mutant 23 (continue → break on empty requested target).

        If ``break`` replaces ``continue``, the loop stops after the
        empty target, and 'evil.com' is never checked → no violations
        → incorrectly returns True.
        """
        ok, violations = ScopeValidator.validate_targets(
            ["", "evil.com"],
            ["good.com"],
        )
        assert ok is False
        assert violations == ["evil.com"]


class TestValidateTargetsStrictCidr:
    """Kills mutant 14 (strict=False → strict=True in ip_network)."""

    def test_non_strict_cidr_in_authorized(self) -> None:
        """Use a CIDR with host bits set (e.g. 10.0.0.5/24).

        With ``strict=False``: normalizes to 10.0.0.0/24, 10.0.0.1 is in it.
        With ``strict=True``: ValueError → network not added → violation.
        """
        ok, violations = ScopeValidator.validate_targets(
            ["10.0.0.1"],
            ["10.0.0.5/24"],
        )
        assert ok is True
        assert violations == []


# ===================================================================
# expand_cidr mutations
# ===================================================================


class TestExpandCidrInstance:
    """Kills mutant 27 (remove @staticmethod from expand_cidr)."""

    def test_via_instance(self) -> None:
        sv = ScopeValidator()
        hosts = sv.expand_cidr("192.168.1.0/30")
        assert len(hosts) == 2  # /30 has 2 usable hosts
        assert "192.168.1.1" in hosts
        assert "192.168.1.2" in hosts


class TestExpandCidrMutations:
    """Kill specific expand_cidr mutations."""

    def test_non_strict_cidr_expand(self) -> None:
        """Kills mutant 30 (strict=False → strict=True).

        Pass a CIDR with host bits set.  With strict=False it works.
        With strict=True it raises ValueError → re-raised with our message.
        """
        hosts = ScopeValidator.expand_cidr("10.0.0.5/24")
        assert len(hosts) > 0
        assert "10.0.0.1" in hosts

    def test_invalid_cidr_exact_message(self) -> None:
        """Kills mutant 32 (error message XX prefix/suffix)."""
        with pytest.raises(ValueError, match=r"^Invalid CIDR: not-a-cidr$"):
            ScopeValidator.expand_cidr("not-a-cidr")

    def test_expand_large_network_respects_cap(self) -> None:
        """Kills mutant 36 (break → continue in cap enforcement).

        Use a /8 network (16M hosts) with max_hosts=2.
        With ``break``: stops after 2 → instant.
        With ``continue``: iterates 16M hosts → timeout.
        """
        hosts = ScopeValidator.expand_cidr("10.0.0.0/8", max_hosts=2)
        assert len(hosts) == 2


# ===================================================================
# validate_port — @staticmethod mutation
# ===================================================================


class TestValidatePortInstance:
    """Kills mutant 38 (remove @staticmethod from validate_port)."""

    def test_via_instance(self) -> None:
        sv = ScopeValidator()
        assert sv.validate_port(80) is True
        assert sv.validate_port(0) is False
        assert sv.validate_port(65536) is False


# ===================================================================
# Exact return value assertions (general)
# ===================================================================


class TestExactReturnValues:
    """Ensure all return tuples are exact."""

    def test_empty_requested_exact(self) -> None:
        ok, violations = ScopeValidator.validate_targets([], ["10.0.0.1"])
        assert ok is True
        assert violations == []

    def test_violation_list_contains_exact_target(self) -> None:
        ok, violations = ScopeValidator.validate_targets(["evil.com"], ["good.com"])
        assert ok is False
        assert violations == ["evil.com"]

    def test_multiple_violations_are_in_order(self) -> None:
        ok, violations = ScopeValidator.validate_targets(
            ["b.com", "a.com"],
            ["good.com"],
        )
        assert ok is False
        assert violations == ["b.com", "a.com"]

    def test_validate_port_boundary_1(self) -> None:
        assert ScopeValidator.validate_port(1) is True

    def test_validate_port_boundary_65535(self) -> None:
        assert ScopeValidator.validate_port(65535) is True

    def test_validate_port_boundary_0(self) -> None:
        assert ScopeValidator.validate_port(0) is False

    def test_validate_port_boundary_65536(self) -> None:
        assert ScopeValidator.validate_port(65536) is False
