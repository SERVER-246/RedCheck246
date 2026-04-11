"""RedCheck246 — Deterministic Input Snapshotting (Phase L).

Captures DNS resolutions, HTTP response hashes, and per-plugin input
hashes before / during pipeline execution so that scan reproducibility
can be verified after the fact.
"""

from __future__ import annotations

import hashlib
import json
import socket
from datetime import datetime, timezone
from typing import Any

import structlog

from redcheck.models import InputSnapshot

log = structlog.get_logger(__name__)


def _sha256(data: bytes | str) -> str:
    """Return hex SHA-256 digest."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# DNS resolution capture
# ---------------------------------------------------------------------------


def resolve_dns(hostnames: list[str]) -> dict[str, list[str]]:
    """Resolve each hostname to its IP addresses.

    Failures are recorded as empty lists (not exceptions).
    """
    results: dict[str, list[str]] = {}
    for host in hostnames:
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            ips = sorted({info[4][0] for info in infos})
            results[host] = ips
        except (socket.gaierror, OSError) as exc:
            log.warning("dns_resolution_failed", hostname=host, error=str(exc))
            results[host] = []
    return results


# ---------------------------------------------------------------------------
# Target fingerprint
# ---------------------------------------------------------------------------


def compute_target_fingerprint(targets: list[str]) -> str:
    """Deterministic hash of all target identifiers."""
    canonical = json.dumps(sorted(targets), sort_keys=True)
    return _sha256(canonical)


# ---------------------------------------------------------------------------
# Plugin input hashing
# ---------------------------------------------------------------------------


def hash_plugin_input(plugin_name: str, context: dict[str, Any]) -> str:
    """Compute a deterministic hash of the context data a plugin receives.

    Private keys (starting with ``_``) are excluded because they contain
    runtime objects that are not serializable.
    """
    filtered = {k: v for k, v in context.items() if not k.startswith("_")}
    canonical = json.dumps(filtered, sort_keys=True, default=str)
    return _sha256(canonical)


# ---------------------------------------------------------------------------
# HTTP response hashing (for pipeline hook)
# ---------------------------------------------------------------------------


def hash_http_response(url: str, body: bytes) -> str:
    """Return SHA-256 of an HTTP response body."""
    return _sha256(body)


# ---------------------------------------------------------------------------
# Snapshot builder
# ---------------------------------------------------------------------------


class InputSnapshotCapture:
    """Captures input state for a single pipeline run.

    Usage::

        capture = InputSnapshotCapture(run_id, targets)
        capture.resolve_targets()       # DNS before pipeline
        capture.record_plugin_input("passive-recon", ctx)
        capture.record_http_response(url, body)
        snapshot = capture.finalise()   # immutable InputSnapshot
    """

    def __init__(self, run_id: str, targets: list[str]) -> None:
        self._run_id = run_id
        self._targets = list(targets)
        self._dns: dict[str, list[str]] = {}
        self._http: dict[str, str] = {}
        self._plugin_inputs: dict[str, str] = {}
        self._captured_at = datetime.now(timezone.utc)

    # -- Pre-pipeline --------------------------------------------------

    def resolve_targets(self) -> dict[str, list[str]]:
        """Resolve target hostnames and store the results."""
        self._dns = resolve_dns(self._targets)
        return dict(self._dns)

    # -- During pipeline -----------------------------------------------

    def record_plugin_input(self, plugin_name: str, context: dict[str, Any]) -> None:
        """Hash and store the input context for a plugin."""
        self._plugin_inputs[plugin_name] = hash_plugin_input(plugin_name, context)

    def record_http_response(self, url: str, body: bytes) -> None:
        """Hash and store an HTTP response body."""
        self._http[url] = hash_http_response(url, body)

    # -- Finalise ------------------------------------------------------

    def finalise(self) -> InputSnapshot:
        """Build the immutable InputSnapshot with a deterministic hash."""
        target_fp = compute_target_fingerprint(self._targets)

        # Compute snapshot_hash from all collected data
        parts = {
            "dns": self._dns,
            "http": self._http,
            "plugin_inputs": self._plugin_inputs,
            "target_fingerprint": target_fp,
        }
        canonical = json.dumps(parts, sort_keys=True, default=str)
        snapshot_hash = _sha256(canonical)

        return InputSnapshot(
            run_id=self._run_id,
            captured_at=self._captured_at,
            dns_resolutions=dict(self._dns),
            http_responses=dict(self._http),
            plugin_inputs=dict(self._plugin_inputs),
            target_fingerprint=target_fp,
            snapshot_hash=snapshot_hash,
        )
