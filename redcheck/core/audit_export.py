"""RedCheck246 — Audit Trail Export (Module 5.3).

Provides encrypted export/import of audit trails for compliance
and forensic review.  Uses AES-256-GCM for encryption with a
session-derived key.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

import structlog

from redcheck.constants import AUDIT_AAD, AUDIT_IV_BYTES

if TYPE_CHECKING:
    from pathlib import Path

log = structlog.get_logger(__name__)

# cryptography for AES-GCM
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    _HAS_CRYPTO = True
except ImportError:  # pragma: no cover
    _HAS_CRYPTO = False


class AuditExporter:
    """Export and import encrypted audit trail archives.

    The audit trail is serialised as JSON, then encrypted with
    AES-256-GCM using a session key.  The exported file format is::

        <12-byte IV> + <ciphertext + 16-byte GCM tag>
    """

    def __init__(self, session_key: bytes) -> None:
        if not _HAS_CRYPTO:
            raise ImportError(
                "cryptography package required for audit export. "
                "Install with: pip install cryptography"
            )
        if len(session_key) != 32:
            raise ValueError("Session key must be exactly 32 bytes (AES-256)")
        self._aesgcm = AESGCM(session_key)

    def export_audit_trail(
        self,
        entries: list[dict[str, Any]],
        output_path: Path,
        *,
        engagement_id: str = "",
    ) -> Path:
        """Encrypt and write audit entries to a file.

        Args:
            entries: List of audit entry dicts.
            output_path: Destination file path.
            engagement_id: Optional engagement ID for the metadata header.

        Returns:
            The output path.
        """
        payload = {
            "format": "redcheck-audit-export-v1",
            "engagement_id": engagement_id,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "entry_count": len(entries),
            "entries": entries,
        }

        plaintext = json.dumps(payload, default=str, ensure_ascii=False).encode("utf-8")
        iv = os.urandom(AUDIT_IV_BYTES)
        ciphertext = self._aesgcm.encrypt(iv, plaintext, AUDIT_AAD)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(iv + ciphertext)

        log.info(
            "audit_trail_exported",
            path=str(output_path),
            entry_count=len(entries),
        )
        return output_path

    def import_audit_trail(self, input_path: Path) -> dict[str, Any]:
        """Decrypt and read an audit trail archive.

        Returns:
            The decrypted payload dict with ``entries`` list.

        Raises:
            ValueError: If decryption fails (wrong key or tampered data).
        """
        raw = input_path.read_bytes()
        if len(raw) < AUDIT_IV_BYTES + 16:
            raise ValueError("Audit export file is too short to contain valid data")

        iv = raw[:AUDIT_IV_BYTES]
        ciphertext = raw[AUDIT_IV_BYTES:]

        try:
            plaintext = self._aesgcm.decrypt(iv, ciphertext, AUDIT_AAD)
        except Exception as exc:
            raise ValueError(f"Audit trail decryption failed: {exc}") from exc

        result: dict[str, Any] = json.loads(plaintext.decode("utf-8"))
        return result
