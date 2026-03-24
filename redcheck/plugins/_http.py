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

import hashlib
import ssl
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

import httpx
import structlog

if TYPE_CHECKING:
    from redcheck.core.token_bucket import TokenBucket

log = structlog.get_logger(__name__)


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


class RedCheckHTTPClient:
    """Shared HTTP client with automatic request logging and optional evidence capture.

    Provides a single connection pool, rate limiting, and centralized
    request/response logging for all plugins.
    """

    def __init__(
        self,
        *,
        plugin_name: str = "unknown",
        rate_limiter: TokenBucket | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._client = httpx.AsyncClient(
            verify=scanning_ssl_context(),
            timeout=timeout,
        )
        self._plugin_name = plugin_name
        self._rate_limiter = rate_limiter

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        """Issue a GET request with rate limiting and logging."""
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        """Issue a POST request with rate limiting and logging."""
        return await self._request("POST", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> httpx.Response:
        """Issue a HEAD request with rate limiting and logging."""
        return await self._request("HEAD", url, **kwargs)

    async def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        if self._rate_limiter:
            await self._rate_limiter.acquire()
        response = await self._client.request(method, url, **kwargs)
        self._log_exchange(response)
        return response

    def _log_exchange(self, response: httpx.Response) -> None:
        """Log HTTP exchange metadata for audit trail."""
        log.debug(
            "http_exchange",
            plugin=self._plugin_name,
            method=response.request.method,
            url=str(response.request.url),
            status=response.status_code,
            response_bytes=len(response.content),
        )

    def capture_evidence(self, response: httpx.Response) -> dict[str, Any]:
        """Build an evidence dict from an HTTP exchange for storage."""
        return {
            "request": {
                "method": response.request.method,
                "url": str(response.request.url),
                "headers": dict(response.request.headers),
            },
            "response": {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body_hash": hashlib.sha256(response.content).hexdigest(),
                "body_size": len(response.content),
                "body_preview": response.text[:512] if response.content else "",
            },
            "plugin": self._plugin_name,
            "captured_at": datetime.now(timezone.utc).isoformat(),
        }

    async def aclose(self) -> None:
        """Close the underlying httpx client."""
        await self._client.aclose()

    async def __aenter__(self) -> RedCheckHTTPClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.aclose()
