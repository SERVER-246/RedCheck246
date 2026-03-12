"""RedCheck246 — Network Guard.

Validates outbound connections against RoE scope.  Injected into
plugin contexts as ``network_guard`` and checked by active plugins
before making outbound connections.

Passive plugins and existing plugins that don't use ``network_guard``
continue working unchanged.
"""

from __future__ import annotations

import structlog

from redcheck.core.scope_validator import ScopeValidator

log = structlog.get_logger(__name__)


class NetworkGuard:
    """Validates outbound connections against the authorized scope.

    Parameters
    ----------
    authorized:
        List of authorized targets/CIDRs/domains from the RoE.
    allowed_ports:
        Optional list of explicitly allowed ports.  When ``None``,
        any valid port (1–65535) is accepted.
    """

    def __init__(
        self,
        authorized: list[str],
        *,
        allowed_ports: list[int] | None = None,
    ) -> None:
        self._scope = list(authorized)
        self._allowed_ports: frozenset[int] | None = (
            frozenset(allowed_ports) if allowed_ports else None
        )

    def check_destination(self, host: str, port: int) -> bool:
        """Return ``True`` if the destination is within authorized scope.

        Validates both the host (against RoE scope) and the port
        (valid range + optional allowlist).
        """
        if not ScopeValidator.validate_port(port):
            log.warning(
                "network_guard_port_invalid",
                host=host,
                port=port,
            )
            return False

        if self._allowed_ports is not None and port not in self._allowed_ports:
            log.warning(
                "network_guard_port_denied",
                host=host,
                port=port,
            )
            return False

        valid, violations = ScopeValidator.validate_targets([host], self._scope)
        if not valid:
            log.warning(
                "network_guard_host_denied",
                host=host,
                violations=violations,
            )
        return valid

    def check_inbound(self, port: int) -> bool:
        """Inbound connections are **always** denied (anti-pivot).

        Returns ``False`` unconditionally — RedCheck must never open
        listening sockets.
        """
        log.warning("network_guard_inbound_denied", port=port)
        return False

    @property
    def authorized_scope(self) -> list[str]:
        """Return a copy of the authorized scope."""
        return list(self._scope)
