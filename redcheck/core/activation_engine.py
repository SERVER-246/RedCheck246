"""RedCheck246 — Activation Engine.

Manages activation codes stored as salted hashes.
Preferred hash: Argon2id (via argon2-cffi). Fallback: SHA-512.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path

import structlog

from redcheck.core.audit import get_audit_logger
from redcheck.exceptions import ActivationError

log = structlog.get_logger(__name__)

_MAX_VERIFY_ATTEMPTS = 5
_LOCKOUT_DURATION_SECONDS = 300
_COOLDOWN_SECONDS = 2


class ActivationEngine:
    """Manages activation code verification via secure local file.

    The activation code is NEVER stored in plaintext.
    """

    def __init__(
        self,
        activation_path: str | Path | None = None,
        base_dir: str | Path | None = None,
    ) -> None:
        if activation_path:
            self._path = Path(activation_path)
        elif base_dir:
            self._path = Path(base_dir) / ".activation" / "activation.enc"
        else:
            self._path = Path(
                os.environ.get(
                    "REDCHECK_ACTIVATION_FILE",
                    str(Path(__file__).resolve().parents[2] / ".activation" / "activation.enc"),
                )
            )
        self.audit = get_audit_logger()
        # In-memory rate-limiting state
        self._failed_attempts = 0
        self._lockout_until: float = 0.0
        self._last_attempt: float = 0.0

    @property
    def is_configured(self) -> bool:
        """Check if an activation code has been set."""
        return self._path.exists() and self._path.stat().st_size > 0

    def set_code(self, code: str) -> tuple[bool, str]:
        """Hash and store a new activation code."""
        if not code or len(code) < 8:
            msg = "Code too short — minimum 8 characters required"
            log.warning("activation_set_failed", reason=msg)
            self.audit.log(action="ACTIVATION_SET_FAILED", details=msg, level="WARN")
            return False, msg

        has_alpha = any(c.isalpha() for c in code)
        has_digit = any(c.isdigit() for c in code)
        has_special = any(not c.isalnum() for c in code)
        if not (has_alpha and has_digit and has_special):
            msg = "Code must contain letters, digits, and special characters"
            log.warning("activation_set_failed", reason=msg)
            self.audit.log(action="ACTIVATION_SET_FAILED", details=msg, level="WARN")
            return False, msg

        # Prefer Argon2id, fall back to SHA-512
        algo, salt, code_hash = self._hash_code_preferred(code)

        data = {
            "salt": salt,
            "hash": code_hash,
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "algorithm": algo,
        }

        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        try:  # noqa: SIM105
            os.chmod(self._path, 0o600)
        except OSError:
            pass

        log.info("activation_code_set")
        self.audit.log(action="ACTIVATION_CODE_SET", details="New activation code configured")
        return True, "Activation code set successfully"

    def verify_code(self, code: str) -> bool:
        """Verify an activation code with rate limiting."""
        if not self.is_configured:
            log.warning("activation_verify_failed", reason="not_configured")
            return False

        now = time.monotonic()

        # Lockout check
        if self._lockout_until > now:
            remaining = int(self._lockout_until - now)
            raise ActivationError(
                f"Account locked. Too many failed attempts. Try again in {remaining}s."
            )

        # Cooldown
        if self._last_attempt and (now - self._last_attempt) < _COOLDOWN_SECONDS:
            raise ActivationError("Too fast. Wait before retrying.")

        self._last_attempt = now

        try:
            with open(self._path, encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            log.error("activation_read_failed", error=str(e))
            return False

        salt = data.get("salt", "")
        stored_hash = data.get("hash", "")
        algo = data.get("algorithm", "sha512")

        result = self._verify_hash(code, salt, stored_hash, algo)

        if not result:
            self._failed_attempts += 1
            log.warning("activation_verify_failed", attempts=self._failed_attempts)
            if self._failed_attempts >= _MAX_VERIFY_ATTEMPTS:
                self._lockout_until = now + _LOCKOUT_DURATION_SECONDS
                self.audit.log(action="ACTIVATION_LOCKOUT", level="WARN")
                log.warning("activation_lockout", duration=_LOCKOUT_DURATION_SECONDS)
        else:
            self._failed_attempts = 0

        return result

    def clear(self) -> bool:
        """Remove the stored activation code."""
        if self._path.exists():
            self._path.unlink()
            self.audit.log(action="ACTIVATION_CODE_CLEARED", details="Activation code removed")
            return True
        return False

    # ------------------------------------------------------------------
    # Hashing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _hash_code_preferred(code: str) -> tuple[str, str, str]:
        """Hash *code*, returning (algorithm, salt_hex, hash_hex).

        Tries Argon2id first, falls back to SHA-512.
        """
        try:
            from argon2 import PasswordHasher

            ph = PasswordHasher(
                time_cost=3,
                memory_cost=65536,
                parallelism=4,
                hash_len=32,
                salt_len=16,
            )
            # argon2-cffi produces its own salt inside the hash string
            argon_hash = ph.hash(code)
            return "argon2id", "", argon_hash
        except ImportError:
            salt = secrets.token_hex(32)
            h = hashlib.sha512((salt + code).encode("utf-8")).hexdigest()
            return "sha512", salt, h

    @staticmethod
    def _verify_hash(code: str, salt: str, stored_hash: str, algo: str) -> bool:
        """Verify *code* against *stored_hash* with the given *algo*."""
        if algo == "argon2id":
            try:
                from argon2 import PasswordHasher
                from argon2.exceptions import VerifyMismatchError

                ph = PasswordHasher()
                try:
                    return ph.verify(stored_hash, code)
                except VerifyMismatchError:
                    return False
            except ImportError:
                return False
        else:
            computed = hashlib.sha512((salt + code).encode("utf-8")).hexdigest()
            return secrets.compare_digest(computed, stored_hash)

    # ------------------------------------------------------------------
    # Test isolation
    # ------------------------------------------------------------------

    @classmethod
    def reset(cls) -> None:
        """Reset the module-level singleton."""
        global _activation_engine  # noqa: PLW0603
        _activation_engine = None


_activation_engine: ActivationEngine | None = None


def get_activation_engine(
    activation_path: str | Path | None = None,
) -> ActivationEngine:
    """Return the module-level ``ActivationEngine`` singleton."""
    global _activation_engine  # noqa: PLW0603
    if _activation_engine is None:
        _activation_engine = ActivationEngine(activation_path)
    return _activation_engine
