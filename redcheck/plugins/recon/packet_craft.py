"""RedCheck246 — Packet Craft: Bounded Network Sender.

Hard limits on payload size, repeat count, and inter-packet gap.
All bounds come from ``redcheck.constants`` and are NOT configurable
at runtime — they are immutable safety rails.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

from redcheck.constants import (
    PACKET_INTER_GAP_SECONDS,
    PACKET_MAX_PAYLOAD_BYTES,
    PACKET_MAX_REPEAT,
)

log = structlog.get_logger(__name__)


@dataclass
class SendResult:
    """Result of a bounded packet send operation."""

    target: str
    port: int
    success: bool
    responses: list[bytes] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    elapsed_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "port": self.port,
            "success": self.success,
            "response_count": len(self.responses),
            "errors": self.errors,
            "elapsed_ms": self.elapsed_ms,
        }


class PacketCraft:
    """Bounded network packet sender with hard safety limits.

    Hard limits (from ``redcheck.constants``):
    - Payload: max ``PACKET_MAX_PAYLOAD_BYTES`` (4096) bytes
    - Repeats: max ``PACKET_MAX_REPEAT`` (3)
    - Gap: min ``PACKET_INTER_GAP_SECONDS`` (1.0s) between repeats
    """

    def __init__(self, timeout: float = 5.0) -> None:
        self._timeout = timeout

    @staticmethod
    def validate_payload(payload: bytes) -> None:
        """Validate payload against hard size limit.

        Raises ``ValueError`` if payload exceeds ``PACKET_MAX_PAYLOAD_BYTES``.
        """
        if len(payload) > PACKET_MAX_PAYLOAD_BYTES:
            msg = (
                f"Payload size {len(payload)} exceeds hard limit "
                f"of {PACKET_MAX_PAYLOAD_BYTES} bytes"
            )
            raise ValueError(msg)

    @staticmethod
    def validate_repeat(repeat: int) -> None:
        """Validate repeat count against hard limit.

        Raises ``ValueError`` if repeat exceeds ``PACKET_MAX_REPEAT``.
        """
        if repeat < 1:
            msg = "repeat must be >= 1"
            raise ValueError(msg)
        if repeat > PACKET_MAX_REPEAT:
            msg = f"Repeat count {repeat} exceeds hard limit of {PACKET_MAX_REPEAT}"
            raise ValueError(msg)

    async def bound_send(
        self,
        target: str,
        port: int,
        payload: bytes,
        *,
        repeat: int = 1,
        protocol: str = "tcp",
    ) -> SendResult:
        """Send payload to target with hard-enforced bounds.

        Args:
            target: Target host or IP.
            port: Target port.
            payload: Raw payload bytes (max 4096B).
            repeat: Number of times to send (max 3).
            protocol: ``"tcp"`` or ``"udp"``.

        Returns:
            ``SendResult`` with responses and timing info.
        """
        self.validate_payload(payload)
        self.validate_repeat(repeat)

        result = SendResult(target=target, port=port, success=True)
        start = time.monotonic()

        for i in range(repeat):
            if i > 0:
                await asyncio.sleep(PACKET_INTER_GAP_SECONDS)

            try:
                if protocol == "tcp":
                    response = await self._tcp_send(target, port, payload)
                elif protocol == "udp":
                    response = await self._udp_send(target, port, payload)
                else:
                    msg = f"Unsupported protocol: {protocol}"
                    raise ValueError(msg)  # noqa: TRY301

                if response:
                    result.responses.append(response)
            except Exception as exc:
                result.errors.append(f"Send #{i + 1} failed: {exc}")
                result.success = False
                log.warning(
                    "packet_send_error",
                    target=target,
                    port=port,
                    attempt=i + 1,
                    error=str(exc),
                )

        result.elapsed_ms = (time.monotonic() - start) * 1000
        return result

    async def _tcp_send(self, target: str, port: int, payload: bytes) -> bytes:
        """Send payload via TCP and return response."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=self._timeout,
            )
            writer.write(payload)
            await writer.drain()
            response = await asyncio.wait_for(
                reader.read(4096),
                timeout=self._timeout,
            )
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            return response
        except asyncio.TimeoutError:
            msg = f"TCP connection to {target}:{port} timed out"
            raise TimeoutError(msg) from None

    async def _udp_send(self, target: str, port: int, payload: bytes) -> bytes:
        """Send payload via UDP and attempt to read response."""
        loop = asyncio.get_event_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self._timeout)
        try:
            await loop.run_in_executor(None, sock.sendto, payload, (target, port))
            try:
                data = await asyncio.wait_for(
                    loop.run_in_executor(None, sock.recv, 4096),
                    timeout=self._timeout,
                )
                return data
            except (TimeoutError, asyncio.TimeoutError):
                return b""
        finally:
            sock.close()

    async def tcp_syn_probe(
        self,
        target: str,
        port: int,
    ) -> tuple[bool, float]:
        """Test if a TCP port is open by attempting a connect.

        Returns ``(is_open, latency_ms)``.

        This is a connect-scan, not a raw SYN scan.  It requires no
        elevated privileges and works on all platforms.
        """
        start = time.monotonic()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=self._timeout,
            )
            latency = (time.monotonic() - start) * 1000
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            return True, latency
        except (OSError, asyncio.TimeoutError):
            latency = (time.monotonic() - start) * 1000
            return False, latency

    async def banner_grab(self, target: str, port: int) -> str:
        """Grab the service banner from an open TCP port.

        Connects, waits briefly for the server to send its banner,
        and returns the decoded string (or empty on failure/timeout).
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=self._timeout,
            )
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                return data.decode("utf-8", errors="replace").strip()
            finally:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
        except (OSError, asyncio.TimeoutError):
            return ""

    # Ports where no unsolicited banner is sent — the client must speak first.
    _HTTP_PORTS: frozenset[int] = frozenset({80, 8080, 8000, 8888})
    _HTTPS_PORTS: frozenset[int] = frozenset({443, 8443})

    async def active_banner_probe(self, target: str, port: int) -> str:
        """Send a protocol-appropriate probe when passive banner_grab is empty.

        For HTTP ports, sends a minimal ``GET / HTTP/1.0`` request.
        For HTTPS ports, performs a TLS handshake then sends the same request.
        Returns the first line(s) of the response or empty on failure.
        """
        request = b"GET / HTTP/1.0\r\nHost: " + target.encode() + b"\r\n\r\n"
        try:
            ssl_ctx: ssl.SSLContext | None = None
            if port in self._HTTPS_PORTS:
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port, ssl=ssl_ctx),
                timeout=self._timeout,
            )
            try:
                writer.write(request)
                await writer.drain()
                data = await asyncio.wait_for(reader.read(2048), timeout=3.0)
                return data.decode("utf-8", errors="replace").strip()
            finally:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
        except (OSError, asyncio.TimeoutError, ssl.SSLError):
            return ""

    async def tls_cert_info(self, target: str, port: int) -> dict[str, Any]:
        """Retrieve the TLS peer certificate for *target:port*.

        Returns a dict with ``subject``, ``issuer``, ``notBefore``,
        ``notAfter``, ``serialNumber``, and ``subjectAltName``
        when available, or an empty dict on failure.
        """
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port, ssl=ctx),
                timeout=self._timeout,
            )
            try:
                transport = writer.transport
                ssl_obj = transport.get_extra_info("ssl_object") if transport else None
                if ssl_obj is None:
                    return {}
                cert: dict[str, Any] = ssl_obj.getpeercert() or {}
                return {
                    "subject": cert.get("subject"),
                    "issuer": cert.get("issuer"),
                    "notBefore": cert.get("notBefore"),
                    "notAfter": cert.get("notAfter"),
                    "serialNumber": cert.get("serialNumber"),
                    "subjectAltName": cert.get("subjectAltName"),
                }
            finally:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
        except (OSError, asyncio.TimeoutError, ssl.SSLError):
            return {}
