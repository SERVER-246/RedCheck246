"""RedCheck246 — Signature Verifier.

Verifies digital signatures on RoE documents and evidence files.
Supports HMAC-SHA256 (shared-secret) and Ed25519 (public-key) modes.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

import structlog
import yaml

from redcheck.exceptions import CryptoError

log = structlog.get_logger(__name__)


class SignatureVerifier:
    """Verify and generate signatures on RoE and evidence documents.

    Supports two modes:
    - **HMAC-SHA256**: shared-secret (default, ``secret`` parameter)
    - **Ed25519**: public-key (``private_key`` / ``public_key`` parameters,
      requires ``cryptography`` package)
    """

    def __init__(
        self,
        secret: str | None = None,
        *,
        private_key_pem: bytes | None = None,
        public_key_pem: bytes | None = None,
    ) -> None:
        self._secret = secret
        self._private_key_pem = private_key_pem
        self._public_key_pem = public_key_pem

    @property
    def is_configured(self) -> bool:
        return bool(self._secret) or bool(self._private_key_pem) or bool(self._public_key_pem)

    @property
    def mode(self) -> str:
        if self._private_key_pem or self._public_key_pem:
            return "ed25519"
        if self._secret:
            return "hmac-sha256"
        return "none"

    # ---- HMAC helpers ---------------------------------------------------

    def _hmac_sha256(self, data: bytes) -> str:
        """Compute HMAC-SHA256 with the configured secret."""
        if not self._secret:
            raise CryptoError("SignatureVerifier: no HMAC secret configured")
        return hmac.new(
            self._secret.encode("utf-8"),
            data,
            hashlib.sha256,
        ).hexdigest()

    # ---- Ed25519 helpers ------------------------------------------------

    def _ed25519_sign(self, data: bytes) -> bytes:
        """Sign *data* with the Ed25519 private key."""
        if not self._private_key_pem:
            raise CryptoError("SignatureVerifier: no Ed25519 private key configured")
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,  # noqa: TC002
            )
            from cryptography.hazmat.primitives.serialization import load_pem_private_key

            key: Ed25519PrivateKey = load_pem_private_key(self._private_key_pem, password=None)  # type: ignore[assignment]
            return key.sign(data)
        except ImportError as exc:
            raise CryptoError("Ed25519 requires the 'cryptography' package") from exc
        except Exception as exc:
            raise CryptoError(f"Ed25519 signing failed: {exc}") from exc

    def _ed25519_verify(self, data: bytes, signature: bytes) -> bool:
        """Verify *signature* over *data* with the Ed25519 public key."""
        pub = self._public_key_pem
        if not pub:
            # Try deriving public key from private key
            if self._private_key_pem:
                try:
                    from cryptography.hazmat.primitives.serialization import (
                        Encoding,
                        PublicFormat,
                        load_pem_private_key,
                    )

                    priv = load_pem_private_key(self._private_key_pem, password=None)
                    pub = priv.public_key().public_bytes(
                        Encoding.PEM,
                        PublicFormat.SubjectPublicKeyInfo,
                    )
                except Exception as exc:
                    raise CryptoError(f"Cannot derive public key: {exc}") from exc
            else:
                raise CryptoError("SignatureVerifier: no Ed25519 public key configured")
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,  # noqa: TC002
            )
            from cryptography.hazmat.primitives.serialization import load_pem_public_key

            key: Ed25519PublicKey = load_pem_public_key(pub)  # type: ignore[assignment]
            key.verify(signature, data)
            return True
        except ImportError as exc:
            raise CryptoError("Ed25519 requires the 'cryptography' package") from exc
        except Exception:
            return False

    # ---- Canonical content extraction -----------------------------------

    def _canonical_roe_content(self, roe_path: str | Path) -> bytes:
        """Extract canonical content from RoE (all fields except ``signature``),
        serialised as sorted JSON for deterministic hashing.
        """
        with open(roe_path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        canonical: dict[str, Any] = {k: v for k, v in data.items() if k != "signature"}

        # Convert datetimes to ISO strings for JSON serialisation
        for key, value in canonical.items():
            if hasattr(value, "isoformat"):
                canonical[key] = value.isoformat()

        return json.dumps(canonical, sort_keys=True, default=str).encode("utf-8")

    # ---- RoE signing / verification -------------------------------------

    def sign_roe(self, roe_path: str | Path) -> str:
        """Generate a signature for an RoE file.

        Returns a hex-encoded HMAC-SHA256 string **or** a hex-encoded
        Ed25519 signature depending on configuration.
        """
        if not self.is_configured:
            raise CryptoError("SignatureVerifier not configured")

        canonical = self._canonical_roe_content(roe_path)

        if self.mode == "ed25519":
            sig = self._ed25519_sign(canonical)
            log.info("roe_signed", mode="ed25519", path=str(roe_path))
            return sig.hex()

        sig_hex = self._hmac_sha256(canonical)
        log.info("roe_signed", mode="hmac-sha256", path=str(roe_path))
        return sig_hex

    def verify_roe(self, roe_path: str | Path) -> tuple[bool, str]:
        """Verify the signature on an RoE file.

        Returns ``(valid, message)``.
        """
        if not self.is_configured:
            return False, "Signature verifier not configured"

        path = Path(roe_path)
        if not path.exists():
            return False, f"RoE file not found: {path}"

        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        stored_sig = data.get("signature", "")
        if not stored_sig:
            return False, "No signature field in RoE"

        canonical = self._canonical_roe_content(roe_path)

        if self.mode == "ed25519":
            try:
                sig_bytes = bytes.fromhex(stored_sig)
            except ValueError:
                return False, "Invalid hex-encoded Ed25519 signature"
            valid = self._ed25519_verify(canonical, sig_bytes)
            msg = "Ed25519 signature verified" if valid else "Ed25519 signature mismatch"
            log.info("roe_verify", mode="ed25519", valid=valid, path=str(roe_path))
            return valid, msg

        expected = self._hmac_sha256(canonical)
        if hmac.compare_digest(stored_sig, expected):
            log.info("roe_verify", mode="hmac-sha256", valid=True, path=str(roe_path))
            return True, "HMAC-SHA256 signature verified"
        log.warning("roe_verify", mode="hmac-sha256", valid=False, path=str(roe_path))
        return False, "HMAC-SHA256 signature mismatch — RoE may have been tampered with"

    # ---- Evidence signing / verification --------------------------------

    def sign_evidence(self, data: bytes) -> str:
        """Sign evidence data. Returns hex-encoded signature."""
        if not self.is_configured:
            raise CryptoError("SignatureVerifier not configured")
        if self.mode == "ed25519":
            return self._ed25519_sign(data).hex()
        return self._hmac_sha256(data)

    def verify_evidence(self, data: bytes, signature: str) -> bool:
        """Verify evidence data against a signature."""
        if not self.is_configured:
            return False
        if self.mode == "ed25519":
            try:
                return self._ed25519_verify(data, bytes.fromhex(signature))
            except ValueError:
                return False
        expected = self._hmac_sha256(data)
        return hmac.compare_digest(signature, expected)
