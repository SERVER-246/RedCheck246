"""Tests for audit log Ed25519 signing (Phase O)."""

from __future__ import annotations

from pathlib import Path

import pytest

from redcheck.core.audit import AuditLogger

# Ed25519 is provided by the cryptography package
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False


@pytest.fixture
def ed25519_keys():
    """Generate a fresh Ed25519 keypair."""
    if not _HAS_CRYPTO:
        pytest.skip("cryptography not installed")
    privkey = Ed25519PrivateKey.generate()
    priv_bytes = privkey.private_bytes_raw()
    pub_bytes = privkey.public_key().public_bytes_raw()
    return priv_bytes, pub_bytes


@pytest.fixture
def signed_logger(tmp_path: Path, ed25519_keys) -> AuditLogger:
    priv_bytes, _ = ed25519_keys
    logger = AuditLogger(log_path=tmp_path / "audit.log", signing_key=priv_bytes)
    logger.start_session("test-code", "test-session")
    return logger


@pytest.fixture
def unsigned_logger(tmp_path: Path) -> AuditLogger:
    logger = AuditLogger(log_path=tmp_path / "audit_unsigned.log")
    logger.start_session("test-code", "test-session")
    return logger


class TestAuditSigning:
    def test_signed_entry_has_signature(self, signed_logger: AuditLogger):
        entry = signed_logger.log("TEST_ACTION", "testing signing")
        assert "signature" in entry
        assert isinstance(entry["signature"], str)
        assert len(entry["signature"]) > 0

    def test_unsigned_entry_has_no_signature(self, unsigned_logger: AuditLogger):
        entry = unsigned_logger.log("TEST_ACTION", "unsigned")
        assert "signature" not in entry

    def test_signature_verifies(self, signed_logger: AuditLogger, ed25519_keys):
        _, pub_bytes = ed25519_keys
        entry = signed_logger.log("VERIFY_TEST", "verify me")
        assert AuditLogger.verify_entry_signature(entry, pub_bytes) is True

    def test_wrong_key_fails_verification(self, signed_logger: AuditLogger):
        if not _HAS_CRYPTO:
            pytest.skip("cryptography not installed")
        entry = signed_logger.log("WRONG_KEY_TEST", "wrong key")
        # Generate a different keypair
        other = Ed25519PrivateKey.generate()
        other_pub = other.public_key().public_bytes_raw()
        assert AuditLogger.verify_entry_signature(entry, other_pub) is False

    def test_tampered_entry_fails_verification(self, signed_logger: AuditLogger, ed25519_keys):
        _, pub_bytes = ed25519_keys
        entry = signed_logger.log("TAMPER_TEST", "original")
        entry["hash"] = "tampered_hash_value"
        assert AuditLogger.verify_entry_signature(entry, pub_bytes) is False

    def test_missing_signature_fails(self, ed25519_keys):
        _, pub_bytes = ed25519_keys
        entry = {"hash": "abc123", "action": "TEST"}
        assert AuditLogger.verify_entry_signature(entry, pub_bytes) is False


class TestAuditLoggerInit:
    def test_accepts_signing_key(self, tmp_path: Path, ed25519_keys):
        priv_bytes, _ = ed25519_keys
        logger = AuditLogger(log_path=tmp_path / "test.log", signing_key=priv_bytes)
        assert logger._signing_key == priv_bytes

    def test_default_no_signing_key(self, tmp_path: Path):
        logger = AuditLogger(log_path=tmp_path / "test.log")
        assert logger._signing_key is None
