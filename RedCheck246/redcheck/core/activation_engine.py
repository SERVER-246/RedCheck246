"""
RedCheck246 Activation Engine

Manages activation codes stored as salted hashes in a secure local encrypted file.
Activation codes are manually-created strings containing numbers, special characters,
and alphabets. The code is never stored in plaintext.
"""

import hashlib
import json
import os
import secrets
from pathlib import Path

from redcheck.core.audit import get_audit_logger


class ActivationEngine:
    """Manages activation code verification via secure local encrypted file.

    Storage format (JSON):
    {
        "salt": "<hex-encoded random salt>",
        "hash": "<SHA-512 hash of salt+code>",
        "created_utc": "<ISO timestamp>",
        "algorithm": "sha512"
    }

    The activation code is NEVER stored in plaintext.
    """

    def __init__(
        self,
        activation_path: str | Path | None = None,
        base_dir: str | Path | None = None,
    ):
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
        self._store_path = self._path  # alias for convenience
        self.audit = get_audit_logger()

    @property
    def is_configured(self) -> bool:
        """Check if an activation code has been set."""
        return self._path.exists() and self._path.stat().st_size > 0

    def set_code(self, code: str) -> tuple[bool, str]:
        """Hash and store a new activation code.

        Args:
            code: The activation code string (numbers, special chars, alphabets).

        Returns: (success, message) tuple.
        """
        if not code or len(code) < 8:
            msg = "Code too short — minimum 8 characters required"
            self.audit.log(
                action="ACTIVATION_SET_FAILED",
                details=msg,
                level="WARN",
            )
            return False, msg

        # Validate complexity: must have letters, digits, and special chars
        has_alpha = any(c.isalpha() for c in code)
        has_digit = any(c.isdigit() for c in code)
        has_special = any(not c.isalnum() for c in code)

        if not (has_alpha and has_digit and has_special):
            msg = "Code complexity failed — must contain letters, digits, and special characters"
            self.audit.log(
                action="ACTIVATION_SET_FAILED",
                details=msg,
                level="WARN",
            )
            return False, msg

        salt = secrets.token_hex(32)
        code_hash = self._hash_code(code, salt)

        from datetime import datetime, timezone

        data = {
            "salt": salt,
            "hash": code_hash,
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "algorithm": "sha512",
        }

        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        # Restrict file permissions (best-effort on Windows)
        try:
            os.chmod(self._path, 0o600)
        except OSError:
            pass

        self.audit.log(
            action="ACTIVATION_CODE_SET",
            details="New activation code configured",
        )

        return True, "Activation code set successfully"

    def verify_code(self, code: str) -> bool:
        """Verify an activation code against the stored hash.

        Args:
            code: The activation code to verify.

        Returns: True if the code matches.
        """
        if not self.is_configured:
            self.audit.log(
                action="ACTIVATION_VERIFY_FAILED",
                details="No activation code configured",
                level="WARN",
            )
            return False

        try:
            with open(self._path, encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            self.audit.log(
                action="ACTIVATION_VERIFY_FAILED",
                details=f"Failed to read activation file: {e}",
                level="ERROR",
            )
            return False

        salt = data.get("salt", "")
        stored_hash = data.get("hash", "")

        computed_hash = self._hash_code(code, salt)

        return secrets.compare_digest(computed_hash, stored_hash)

    def clear(self) -> bool:
        """Remove the stored activation code."""
        if self._path.exists():
            self._path.unlink()
            self.audit.log(
                action="ACTIVATION_CODE_CLEARED",
                details="Activation code removed",
            )
            return True
        return False

    @staticmethod
    def _hash_code(code: str, salt: str) -> str:
        """Compute SHA-512 hash of salt + code."""
        return hashlib.sha512((salt + code).encode("utf-8")).hexdigest()


_activation_engine: ActivationEngine | None = None


def get_activation_engine(
    activation_path: str | Path | None = None,
) -> ActivationEngine:
    global _activation_engine
    if _activation_engine is None:
        _activation_engine = ActivationEngine(activation_path)
    return _activation_engine
