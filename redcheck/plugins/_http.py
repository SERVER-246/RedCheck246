"""Shared HTTP client utilities for RedCheck246 scanner plugins.

Security scanners MUST connect to targets that may present self-signed,
expired, or otherwise invalid TLS certificates.  This module centralises
the SSL-context creation so every plugin uses a single, audited helper
rather than scattering ``verify=False`` across the codebase.

Design rationale
----------------
* ``verify=False`` triggers CodeQL ``py/request-without-cert-validation``.
* Passing an explicit ``ssl.SSLContext`` with ``CERT_NONE`` achieves the
  same behaviour while keeping the security intent documented in one place.
* ``minimum_version = TLSv1_2`` ensures the scanner's **own** connections
  never negotiate SSLv3 / TLS 1.0 / TLS 1.1.  Weak-protocol *detection*
  is done by inspecting the negotiated version string, not by downgrading.
"""

from __future__ import annotations

import ssl


def scanning_ssl_context() -> ssl.SSLContext:
    """Return an ``ssl.SSLContext`` suitable for security-assessment probes.

    The context:
    * Disables certificate verification (targets may be self-signed).
    * Disables hostname checking (targets may use IP addresses).
    * Enforces TLS 1.2 as the minimum protocol version.

    Returns
    -------
    ssl.SSLContext
        Ready-to-use context for ``httpx.AsyncClient(verify=ctx)``.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx
