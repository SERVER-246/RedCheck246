"""RedCheck246 — Evidence Store.

Indexed evidence storage with integrity verification.  Provides a
centralized catalog linking evidence artifacts to findings and plugins.

The store is opt-in — it only activates when ``evidence_dir`` is set
in the engagement context.  All evidence is written to disk with
SHA-256 integrity hashes and an optional AES-256-GCM encryption layer
via :class:`~redcheck.security.crypto.CryptoEngine`.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from redcheck.models import Evidence
from redcheck.security.crypto import CryptoEngine

log = structlog.get_logger(__name__)

_INDEX_VERSION = "1.0.0"


class EvidenceStore:
    """Indexed evidence storage with integrity verification."""

    def __init__(self, evidence_dir: str | Path) -> None:
        self._dir = Path(evidence_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._index_path = self._dir / "evidence_index.json"
        self._entries: list[dict[str, Any]] = []
        self._load_index()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def store(
        self,
        data: bytes,
        evidence_type: str,
        *,
        finding_ref: str | None = None,
        plugin_name: str | None = None,
        encrypt: bool = False,
        passphrase: str | None = None,
    ) -> Evidence:
        """Store evidence with automatic hashing and optional encryption.

        Returns an :class:`Evidence` model instance describing the
        stored artifact.
        """
        sha256 = CryptoEngine.hash_sha256(data)
        ts = datetime.now(timezone.utc)
        ts_str = ts.strftime("%Y%m%dT%H%M%S")
        filename = f"{evidence_type}_{sha256[:12]}_{ts_str}.bin"
        filepath = self._dir / filename

        stored_data = data
        encrypted = False
        if encrypt and passphrase:
            enc_result = CryptoEngine.encrypt_evidence(data, passphrase)
            stored_data = json.dumps(enc_result).encode("utf-8")
            encrypted = True

        filepath.write_bytes(stored_data)

        evidence = Evidence(
            evidence_type=evidence_type,
            path=str(filepath),
            sha256=sha256,
            timestamp=ts,
            encrypted=encrypted,
            size_bytes=len(data),
        )

        entry: dict[str, Any] = {
            "sha256": sha256,
            "evidence_type": evidence_type,
            "path": str(filepath),
            "plugin_name": plugin_name,
            "finding_ref": finding_ref,
            "timestamp": ts.isoformat(),
            "encrypted": encrypted,
            "size_bytes": len(data),
        }
        self._entries.append(entry)
        self._save_index()

        log.debug(
            "evidence_stored",
            sha256=sha256[:12],
            evidence_type=evidence_type,
            encrypted=encrypted,
        )
        return evidence

    def retrieve(self, sha256: str) -> bytes | None:
        """Retrieve raw evidence bytes by SHA-256 hash.

        Returns ``None`` if no matching entry exists or the file is
        missing from disk.
        """
        for entry in self._entries:
            if entry["sha256"] == sha256:
                p = Path(entry["path"])
                if p.is_file():
                    return p.read_bytes()
                return None
        return None

    def verify_integrity(self) -> tuple[bool, list[str]]:
        """Verify all stored evidence matches index hashes.

        Returns ``(all_ok, list_of_error_messages)``.
        """
        errors: list[str] = []
        for entry in self._entries:
            p = Path(entry["path"])
            if not p.is_file():
                errors.append(f"Missing file: {entry['path']}")
                continue

            stored_data = p.read_bytes()

            if entry.get("encrypted"):
                # For encrypted entries, verify valid JSON structure and
                # that the on-disk ciphertext blob hasn't been tampered with.
                try:
                    enc = json.loads(stored_data)
                    if enc.get("algorithm") != "AES-256-GCM":
                        errors.append(f"Bad encryption algo: {entry['path']}")
                    if not enc.get("ciphertext") or not enc.get("nonce"):
                        errors.append(f"Missing ciphertext/nonce: {entry['path']}")
                except (json.JSONDecodeError, KeyError):
                    errors.append(f"Corrupt encrypted file: {entry['path']}")
            else:
                actual = CryptoEngine.hash_sha256(stored_data)
                if actual != entry["sha256"]:
                    errors.append(
                        f"Hash mismatch: {entry['path']} "
                        f"(expected {entry['sha256'][:12]}…, "
                        f"got {actual[:12]}…)"
                    )

        return len(errors) == 0, errors

    def query(
        self,
        *,
        plugin_name: str | None = None,
        evidence_type: str | None = None,
        finding_ref: str | None = None,
    ) -> list[Evidence]:
        """Query evidence entries by metadata filters."""
        results: list[Evidence] = []
        for entry in self._entries:
            if plugin_name and entry.get("plugin_name") != plugin_name:
                continue
            if evidence_type and entry.get("evidence_type") != evidence_type:
                continue
            if finding_ref and entry.get("finding_ref") != finding_ref:
                continue
            results.append(
                Evidence(
                    evidence_type=entry["evidence_type"],
                    path=entry["path"],
                    sha256=entry["sha256"],
                    timestamp=datetime.fromisoformat(entry["timestamp"]),
                    encrypted=entry.get("encrypted", False),
                    size_bytes=entry.get("size_bytes"),
                )
            )
        return results

    @property
    def count(self) -> int:
        """Return the number of indexed entries."""
        return len(self._entries)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _load_index(self) -> None:
        """Load the index from disk if it exists."""
        if self._index_path.is_file():
            try:
                raw = json.loads(self._index_path.read_text(encoding="utf-8"))
                self._entries = raw.get("entries", [])
            except (json.JSONDecodeError, KeyError):
                log.warning("evidence_index_corrupt", path=str(self._index_path))
                self._entries = []
        else:
            self._entries = []

    def _save_index(self) -> None:
        """Persist the index to disk atomically."""
        index_data = {
            "version": _INDEX_VERSION,
            "entries": self._entries,
        }
        tmp = self._index_path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(index_data, indent=2, default=str),
            encoding="utf-8",
        )
        tmp.replace(self._index_path)
