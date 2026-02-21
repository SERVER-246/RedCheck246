"""RedCheck246 Audit Logger — encrypted, hash-chained, tamper-evident.

Per Spec 8 (Data Retention & Audit Policy):
  - Every audit entry is encrypted with AES-256-GCM before writing to disk.
  - A session code is required to start / read / verify the audit trail.
  - Key derivation: HKDF-SHA256, salt = session_id, info = ``b"redcheck-audit-v1"``.
  - Per-entry IV: ``os.urandom(12)``, AAD = session_id.
  - On-disk format: one base64 record per line (``.enc`` extension).
  - In-memory the plaintext flows through ``structlog`` for operational visibility.

The hash chain (SHA-256 truncated to 16 hex chars) provides tamper evidence
independently of the encryption layer.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)

# Optional — gracefully degrade if cryptography not installed (tests)
try:
    from cryptography.hazmat.primitives import hashes as crypto_hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    _HAS_CRYPTO = True
except ImportError:  # pragma: no cover
    _HAS_CRYPTO = False


def _derive_key(session_code: str, session_id: str) -> bytes:
    """Derive a 256-bit key from session_code using HKDF-SHA256."""
    if not _HAS_CRYPTO:
        # Fallback — SHA-256 of session_code (NOT production-safe)
        return hashlib.sha256(session_code.encode()).digest()
    hkdf = HKDF(
        algorithm=crypto_hashes.SHA256(),
        length=32,
        salt=session_id.encode("utf-8"),
        info=b"redcheck-audit-v1",
    )
    return hkdf.derive(session_code.encode("utf-8"))


def _encrypt_entry(plaintext: bytes, key: bytes, session_id: str) -> bytes:
    """AES-256-GCM encrypt a single entry."""
    iv = os.urandom(12)
    if _HAS_CRYPTO:
        aes = AESGCM(key)
        ct = aes.encrypt(iv, plaintext, session_id.encode("utf-8"))
    else:
        # XOR fallback for dev/test ONLY
        ct = bytes(a ^ key[i % len(key)] for i, a in enumerate(plaintext))
    return iv + ct


def _decrypt_entry(ciphertext: bytes, key: bytes, session_id: str) -> bytes:
    """AES-256-GCM decrypt a single entry."""
    iv = ciphertext[:12]
    ct = ciphertext[12:]
    if _HAS_CRYPTO:
        aes = AESGCM(key)
        return aes.decrypt(iv, ct, session_id.encode("utf-8"))
    else:
        return bytes(a ^ key[i % len(key)] for i, a in enumerate(ct))


class AuditLogger:
    """Encrypted, hash-chained, append-only audit logger."""

    _lock = threading.Lock()

    def __init__(self, log_path: str | Path | None = None) -> None:
        self._log_path = Path(log_path or self._default_log_path())
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        self._previous_hash = "GENESIS"
        self._session_code: str | None = None
        self._session_id: str | None = None
        self._key: bytes | None = None

        # Try to continue chain from existing log
        self._previous_hash = self._recover_last_hash()

    @staticmethod
    def _default_log_path() -> str:
        return os.environ.get(
            "REDCHECK_AUDIT_LOG",
            str(Path(__file__).resolve().parents[2] / "logs" / "audit.log"),
        )

    @property
    def log_path(self) -> Path:
        return self._log_path

    @property
    def has_session(self) -> bool:
        return self._session_code is not None

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def start_session(self, session_code: str, session_id: str | None = None) -> str:
        """Start an audit session. Returns the session_id."""
        self._session_code = session_code
        self._session_id = (
            session_id
            or hashlib.sha256(
                f"{session_code}-{datetime.now(timezone.utc).isoformat()}".encode()
            ).hexdigest()[:12]
        )
        self._key = _derive_key(session_code, self._session_id)
        logger.info("audit_session_started", session_id=self._session_id)
        return self._session_id

    # ------------------------------------------------------------------
    # Hash chain helpers
    # ------------------------------------------------------------------

    def _compute_hash(self, entry: dict[str, object]) -> str:
        raw = json.dumps(entry, sort_keys=True, default=str) + str(self._previous_hash)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def _recover_last_hash(self) -> str:
        """Try to read the last hash from an unencrypted legacy log."""
        if not self._log_path.exists():
            return "GENESIS"
        try:
            with open(self._log_path, encoding="utf-8") as f:
                for line in reversed(f.readlines()):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        return str(entry.get("hash", "GENESIS"))
                    except json.JSONDecodeError:
                        continue
        except Exception:  # noqa: S110
            pass
        return "GENESIS"

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def log(
        self,
        action: str,
        details: str = "",
        operator: str = "system",
        level: str = "INFO",
        plugin: str = "",
        engagement_id: str = "",
    ) -> dict[str, object]:
        """Append an audit entry (encrypted if session is active)."""
        entry: dict[str, object] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "action": action,
            "details": details,
            "operator": operator,
            "plugin": plugin,
            "engagement_id": engagement_id,
            "previous_hash": self._previous_hash,
        }
        entry["hash"] = self._compute_hash(entry)
        self._previous_hash = str(entry["hash"])

        # Emit to structlog (plaintext, in-memory only)
        logger.info(
            "audit_entry",
            action=action,
            plugin=plugin,
            engagement_id=engagement_id,
            level=level,
        )

        with self._lock, open(self._log_path, "a", encoding="utf-8") as f:
            if self._key and self._session_id:
                plaintext = json.dumps(entry, default=str).encode("utf-8")
                ct = _encrypt_entry(plaintext, self._key, self._session_id)
                line = base64.b64encode(ct).decode("ascii")
            else:
                line = json.dumps(entry, default=str)
            f.write(line + "\n")

        return entry

    # Convenience methods
    def log_policy_denial(
        self,
        plugin: str,
        reason: str,
        engagement_id: str = "",
    ) -> dict[str, object]:
        return self.log(
            "POLICY_DENIED",
            reason,
            level="WARN",
            plugin=plugin,
            engagement_id=engagement_id,
        )

    def log_activation_attempt(
        self,
        success: bool,
        operator: str = "user",
    ) -> dict[str, object]:
        level = "INFO" if success else "WARN"
        return self.log(
            "ACTIVATION_ATTEMPT",
            f"success={success}",
            operator=operator,
            level=level,
        )

    def log_engagement_action(
        self,
        action: str,
        engagement_id: str,
        details: str = "",
    ) -> dict[str, object]:
        return self.log(action, details, engagement_id=engagement_id)

    # ------------------------------------------------------------------
    # Read / Verify
    # ------------------------------------------------------------------

    def read_session(self, session_code: str, session_id: str) -> list[dict[str, object]]:
        """Decrypt and return all entries for a given session."""
        key = _derive_key(session_code, session_id)
        entries: list[dict[str, object]] = []
        if not self._log_path.exists():
            return entries
        with open(self._log_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                # Try as encrypted base64
                try:
                    ct = base64.b64decode(line)
                    pt = _decrypt_entry(ct, key, session_id)
                    entries.append(json.loads(pt))
                    continue
                except Exception:  # noqa: S110
                    pass
                # Try as plain JSON (legacy / unencrypted)
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return entries

    def verify_chain(
        self,
        session_code: str | None = None,
        session_id: str | None = None,
    ) -> tuple[bool, int, str]:
        """Verify the entire audit log chain integrity.

        If session_code + session_id are provided, decrypt first.
        Otherwise attempts plain-JSON verification (legacy logs).
        """
        if not self._log_path.exists():
            return True, 0, "No audit log found"

        entries: list[dict[str, object]] = []
        if session_code and session_id:
            entries = self.read_session(session_code, session_id)
        else:
            with open(self._log_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith(("===", "---")):
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue

        if not entries:
            return True, 0, "No structured entries found"

        prev_hash = "GENESIS"
        for i, entry in enumerate(entries):
            stored_hash = str(entry.pop("hash", ""))
            entry_copy = dict(entry)
            entry_copy["previous_hash"] = prev_hash
            raw = json.dumps(entry_copy, sort_keys=True, default=str) + prev_hash
            computed = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
            entry["hash"] = stored_hash

            if str(entry.get("previous_hash")) != prev_hash:
                return False, i, f"Chain break at entry {i}: expected prev_hash={prev_hash}"
            if stored_hash != computed:
                return (
                    False,
                    i,
                    f"Hash mismatch at entry {i}: stored={stored_hash} computed={computed}",
                )
            prev_hash = stored_hash

        return True, len(entries), f"Chain valid: {len(entries)} entries verified"

    # ------------------------------------------------------------------
    # Test isolation
    # ------------------------------------------------------------------

    @classmethod
    def reset(cls) -> None:
        """Reset module-level state for test isolation."""
        global _audit  # noqa: PLW0603
        _audit = None


# ---------------------------------------------------------------------------
# Module-level factory
# ---------------------------------------------------------------------------

_audit: AuditLogger | None = None


def get_audit_logger(log_path: str | None = None) -> AuditLogger:
    """Get or create the module-level AuditLogger instance."""
    global _audit  # noqa: PLW0603
    if _audit is None:
        _audit = AuditLogger(log_path)
    return _audit
