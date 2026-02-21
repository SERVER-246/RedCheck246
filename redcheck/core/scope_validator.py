"""RedCheck246 — Scope Validator.

Enforces target scope boundaries defined in the Rules of Engagement.
Supports IP addresses, CIDR ranges, hostnames, and wildcard domains.
"""

from __future__ import annotations

import ipaddress
import re

from redcheck.constants import SCOPE_MAX_CIDR_EXPANSION


class ScopeValidator:
    """Enforce target scope boundaries defined in RoE."""

    @staticmethod
    def validate_targets(
        requested: list[str],
        authorized: list[str],
    ) -> tuple[bool, list[str]]:
        """Check if all requested targets are within the authorized scope.

        Args:
            requested: List of targets the plugin wants to scan.
            authorized: List of authorized targets from the RoE.

        Returns:
            ``(all_valid, list_of_violations)`` — ``all_valid`` is ``True``
            only when every requested target matches at least one authorized
            entry.  ``list_of_violations`` contains the rejected targets.
        """
        if not requested:
            return True, []

        # Expand authorized entries into a set of concrete matches + patterns
        auth_ips: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
        auth_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        auth_hosts: set[str] = set()
        auth_wildcards: list[str] = []

        for entry in authorized:
            entry = entry.strip()
            if not entry:
                continue

            # Try as IP address
            try:
                auth_ips.add(ipaddress.ip_address(entry))
                continue
            except ValueError:
                pass

            # Try as CIDR network
            try:
                net = ipaddress.ip_network(entry, strict=False)
                auth_networks.append(net)
                continue
            except ValueError:
                pass

            # Wildcard domain
            if entry.startswith("*."):
                auth_wildcards.append(entry[2:].lower())
                continue

            # Exact hostname
            auth_hosts.add(entry.lower())

        violations: list[str] = []
        for target in requested:
            target_stripped = target.strip()
            if not target_stripped:
                continue
            if not _target_in_scope(
                target_stripped, auth_ips, auth_networks, auth_hosts, auth_wildcards
            ):
                violations.append(target_stripped)

        return len(violations) == 0, violations

    @staticmethod
    def expand_cidr(cidr: str, max_hosts: int | None = None) -> list[str]:
        """Deterministic CIDR expansion with hard cap.

        Args:
            cidr: CIDR notation string (e.g. ``10.0.0.0/24``).
            max_hosts: Maximum number of hosts to return.
                       Defaults to ``SCOPE_MAX_CIDR_EXPANSION`` (256).

        Returns:
            List of host IP address strings, up to ``max_hosts``.
        """
        if max_hosts is None:
            max_hosts = SCOPE_MAX_CIDR_EXPANSION

        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as e:
            msg = f"Invalid CIDR: {cidr}"
            raise ValueError(msg) from e

        hosts: list[str] = []
        for host in network.hosts():
            if len(hosts) >= max_hosts:
                break
            hosts.append(str(host))

        # For /32 or /128 (single host), include the network address
        if not hosts:
            hosts.append(str(network.network_address))

        return hosts

    @staticmethod
    def validate_port(port: int) -> bool:
        """Validate a port number is within valid range (1-65535)."""
        return 1 <= port <= 65535


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _target_in_scope(
    target: str,
    auth_ips: set[ipaddress.IPv4Address | ipaddress.IPv6Address],
    auth_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
    auth_hosts: set[str],
    auth_wildcards: list[str],
) -> bool:
    """Check if a single target is in scope."""
    target_lower = target.lower()

    # Strip port if present (e.g. "host:443")
    host_part = re.sub(r":\d+$", "", target_lower)

    # Exact hostname match
    if host_part in auth_hosts:
        return True

    # Wildcard match (*.example.com matches sub.example.com)
    for wc in auth_wildcards:
        if host_part.endswith("." + wc) or host_part == wc:
            return True

    # IP address match
    try:
        ip = ipaddress.ip_address(host_part)
        if ip in auth_ips:
            return True
        for net in auth_networks:
            if ip in net:
                return True
    except ValueError:
        pass

    return False
