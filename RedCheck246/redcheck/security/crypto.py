"""
RedCheck246 — Cryptographic Utilities

Evidence encryption, key derivation, and secure hashing.
Uses AES-256-GCM for evidence encryption.
"""

import base64
import hashlib
import hmac
import os
import secrets
from pathlib import Path
from typing import Any


class CryptoEngine:
    """Handles cryptographic operations for evidence and data protection."""

    SALT_SIZE = 32
    KEY_SIZE = 32  # 256-bit
    NONCE_SIZE = 12  # 96-bit for AES-GCM
    PBKDF2_ITERATIONS = 600_000

    @staticmethod
    def derive_key(passphrase: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
        """Derive an AES-256 key from a passphrase using PBKDF2-HMAC-SHA512.

        Args:
            passphrase: The passphrase to derive from.
            salt: Optional salt; random generated if not provided.

        Returns: (key, salt) tuple.
        """
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
    def generate_random_token(length: int = 32) -> str:
        """Generate a cryptographically secure random hex token."""
        return secrets.token_hex(length)

    @staticmethod
    def hash_file(filepath: str | Path) -> str:
        """Calculate SHA-256 hash of a file (streaming, memory-safe)."""
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def encode_b64(data: bytes) -> str:
        """Base64 encode bytes to string."""
        return base64.b64encode(data).decode("ascii")

    @staticmethod
    def decode_b64(data: str) -> bytes:
        """Base64 decode string to bytes."""
        return base64.b64decode(data)

    @staticmethod
    def secure_compare(a: str, b: str) -> bool:
        """Timing-safe string comparison."""
        return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))

    @staticmethod
    def encrypt_evidence(
        plaintext: bytes,
        passphrase: str,
    ) -> dict[str, str]:
        """Encrypt evidence data using AES-256-GCM via PBKDF2-derived key.

        Note: Requires the 'cryptography' package for AES-GCM.
        Falls back to XOR-based obfuscation if unavailable (NOT secure — dev only).

        Returns: Dict with {ciphertext, salt, nonce, tag} all base64-encoded.
        """
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            key, salt = CryptoEngine.derive_key(passphrase)
            nonce = os.urandom(CryptoEngine.NONCE_SIZE)
            aesgcm = AESGCM(key)
            ct = aesgcm.encrypt(nonce, plaintext, None)

            return {
                "algorithm": "AES-256-GCM",
                "ciphertext": CryptoEngine.encode_b64(ct),
                "salt": CryptoEngine.encode_b64(salt),
                "nonce": CryptoEngine.encode_b64(nonce),
                "kdf": "PBKDF2-HMAC-SHA512",
                "iterations": CryptoEngine.PBKDF2_ITERATIONS,
            }
        except ImportError:
            # Dev-only fallback — NOT secure, just prevents plaintext storage
            key, salt = CryptoEngine.derive_key(passphrase)
            obfuscated = bytes(b ^ key[i % len(key)] for i, b in enumerate(plaintext))
            return {
                "algorithm": "XOR-OBFUSCATION-DEV-ONLY",
                "ciphertext": CryptoEngine.encode_b64(obfuscated),
                "salt": CryptoEngine.encode_b64(salt),
                "nonce": "",
                "kdf": "PBKDF2-HMAC-SHA512",
                "iterations": CryptoEngine.PBKDF2_ITERATIONS,
                "WARNING": "NOT SECURE — install 'cryptography' package",
            }

    @staticmethod
    def decrypt_evidence(
        encrypted: dict[str, str],
        passphrase: str,
    ) -> bytes:
        """Decrypt evidence data.

        Args:
            encrypted: Dict from encrypt_evidence().
            passphrase: The passphrase used for encryption.

        Returns: Decrypted plaintext bytes.
        """
        salt = CryptoEngine.decode_b64(encrypted["salt"])
        key, _ = CryptoEngine.derive_key(passphrase, salt)

        if encrypted["algorithm"] == "AES-256-GCM":
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            nonce = CryptoEngine.decode_b64(encrypted["nonce"])
            ct = CryptoEngine.decode_b64(encrypted["ciphertext"])
            aesgcm = AESGCM(key)
            return aesgcm.decrypt(nonce, ct, None)
        elif encrypted["algorithm"] == "XOR-OBFUSCATION-DEV-ONLY":
            obfuscated = CryptoEngine.decode_b64(encrypted["ciphertext"])
            return bytes(b ^ key[i % len(key)] for i, b in enumerate(obfuscated))
        else:
            raise ValueError(f"Unknown algorithm: {encrypted['algorithm']}")
