"""RedCheck246 — Cryptographic Utilities.

Evidence encryption, key derivation, and secure hashing.
Uses AES-256-GCM for evidence encryption (``cryptography`` is a hard dependency).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from pathlib import Path

import structlog
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from redcheck.exceptions import CryptoError

log = structlog.get_logger(__name__)


class CryptoEngine:
    """Handles cryptographic operations for evidence and data protection."""

    SALT_SIZE = 32
    KEY_SIZE = 32  # 256-bit
    NONCE_SIZE = 12  # 96-bit for AES-GCM
    PBKDF2_ITERATIONS = 600_000

    # ---- Key Derivation -------------------------------------------------

    @staticmethod
    def derive_key(passphrase: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
        """Derive an AES-256 key from a passphrase using PBKDF2-HMAC-SHA512.

        Returns ``(key, salt)`` tuple.
        """
        if not passphrase:
            raise CryptoError("Passphrase must not be empty")
        if salt is None:
            salt = os.urandom(CryptoEngine.SALT_SIZE)
        key = hashlib.pbkdf2_hmac(
            "sha512",
            passphrase.encode("utf-8"),
            salt,
            CryptoEngine.PBKDF2_ITERATIONS,
            dklen=CryptoEngine.KEY_SIZE,
        )
        return key, salt

    # ---- Hashing --------------------------------------------------------

    @staticmethod
    def hash_sha256(data: bytes) -> str:
        """Return hex-encoded SHA-256 hash."""
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def hash_sha512(data: bytes) -> str:
        """Return hex-encoded SHA-512 hash."""
        return hashlib.sha512(data).hexdigest()

    @staticmethod
    def hmac_sha256(key: bytes, data: bytes) -> str:
        """Return hex-encoded HMAC-SHA256."""
        return hmac.new(key, data, hashlib.sha256).hexdigest()

    @staticmethod
    def hash_file(filepath: str | Path) -> str:
        """Calculate SHA-256 hash of a file (streaming, memory-safe)."""
        filepath = Path(filepath)
        if not filepath.is_file():
            raise CryptoError(f"File not found: {filepath}")
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    # ---- Encoding -------------------------------------------------------

    @staticmethod
    def encode_b64(data: bytes) -> str:
        """Base64 encode bytes to string."""
        return base64.b64encode(data).decode("ascii")

    @staticmethod
    def decode_b64(data: str) -> bytes:
        """Base64 decode string to bytes."""
        try:
            return base64.b64decode(data)
        except Exception as exc:
            raise CryptoError(f"Base64 decode failed: {exc}") from exc

    # ---- Utilities ------------------------------------------------------

    @staticmethod
    def generate_random_token(length: int = 32) -> str:
        """Generate a cryptographically secure random hex token."""
        return secrets.token_hex(length)

    @staticmethod
    def secure_compare(a: str, b: str) -> bool:
        """Timing-safe string comparison."""
        return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))

    # ---- AES-256-GCM Evidence Encryption --------------------------------

    @staticmethod
    def encrypt_evidence(plaintext: bytes, passphrase: str) -> dict[str, str | int]:
        """Encrypt evidence data using AES-256-GCM.

        Returns a dict with ``{algorithm, ciphertext, salt, nonce, kdf, iterations}``
        — all byte values base64-encoded.
        """
        try:
            key, salt = CryptoEngine.derive_key(passphrase)
            nonce = os.urandom(CryptoEngine.NONCE_SIZE)
            aesgcm = AESGCM(key)
            ct = aesgcm.encrypt(nonce, plaintext, None)

            log.debug("evidence_encrypted", size=len(plaintext))
            return {
                "algorithm": "AES-256-GCM",
                "ciphertext": CryptoEngine.encode_b64(ct),
                "salt": CryptoEngine.encode_b64(salt),
                "nonce": CryptoEngine.encode_b64(nonce),
                "kdf": "PBKDF2-HMAC-SHA512",
                "iterations": CryptoEngine.PBKDF2_ITERATIONS,
            }
        except CryptoError:
            raise
        except Exception as exc:
            raise CryptoError(f"Encryption failed: {exc}") from exc

    @staticmethod
    def decrypt_evidence(encrypted: dict[str, str], passphrase: str) -> bytes:
        """Decrypt evidence data previously encrypted with ``encrypt_evidence()``.

        Raises ``CryptoError`` on any failure (wrong passphrase, corrupt data, etc.).
        """
        algo = encrypted.get("algorithm", "")
        if algo != "AES-256-GCM":
            raise CryptoError(f"Unsupported algorithm: {algo}")

        try:
            salt = CryptoEngine.decode_b64(encrypted["salt"])
            nonce = CryptoEngine.decode_b64(encrypted["nonce"])
            ct = CryptoEngine.decode_b64(encrypted["ciphertext"])
            key, _ = CryptoEngine.derive_key(passphrase, salt)
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ct, None)
            log.debug("evidence_decrypted", size=len(plaintext))
            return plaintext
        except CryptoError:
            raise
        except Exception as exc:
            raise CryptoError(f"Decryption failed: {exc}") from exc
