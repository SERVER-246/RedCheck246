"""Tests for CryptoEngine — encryption, hashing, key derivation."""

import pytest

from redcheck.exceptions import CryptoError
from redcheck.security.crypto import CryptoEngine


class TestKeyDerivation:
    """PBKDF2-HMAC-SHA512 key derivation tests."""

    def test_derive_key_returns_key_and_salt(self):
        key, salt = CryptoEngine.derive_key("test-passphrase")
        assert len(key) == CryptoEngine.KEY_SIZE  # 32 bytes
        assert len(salt) == CryptoEngine.SALT_SIZE  # 32 bytes

    def test_same_salt_produces_same_key(self):
        key1, salt = CryptoEngine.derive_key("deterministic")
        key2, _ = CryptoEngine.derive_key("deterministic", salt)
        assert key1 == key2

    def test_different_passphrase_different_key(self):
        key1, salt = CryptoEngine.derive_key("pass-one")
        key2, _ = CryptoEngine.derive_key("pass-two", salt)
        assert key1 != key2

    def test_empty_passphrase_raises(self):
        with pytest.raises(CryptoError, match="empty"):
            CryptoEngine.derive_key("")


class TestHashing:
    """SHA-256, SHA-512, and HMAC hashing tests."""

    def test_sha256_hash(self):
        h = CryptoEngine.hash_sha256(b"hello")
        assert len(h) == 64  # hex SHA-256
        assert h == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    def test_sha512_hash(self):
        h = CryptoEngine.hash_sha512(b"hello")
        assert len(h) == 128  # hex SHA-512

    def test_hmac_sha256(self):
        mac = CryptoEngine.hmac_sha256(b"secret-key", b"message")
        assert len(mac) == 64  # hex HMAC-SHA256

    def test_hmac_sha256_different_keys(self):
        mac1 = CryptoEngine.hmac_sha256(b"key-a", b"message")
        mac2 = CryptoEngine.hmac_sha256(b"key-b", b"message")
        assert mac1 != mac2

    def test_file_hash(self, tmp_path):
        p = tmp_path / "testfile.txt"
        p.write_bytes(b"file content for hashing")
        h = CryptoEngine.hash_file(p)
        assert len(h) == 64
        # Same content → same hash
        h2 = CryptoEngine.hash_file(p)
        assert h == h2

    def test_file_hash_missing_file(self):
        with pytest.raises(CryptoError, match="not found"):
            CryptoEngine.hash_file("/nonexistent/file.bin")


class TestEncoding:
    """Base64 encode/decode round-trip tests."""

    def test_b64_round_trip(self):
        original = b"binary\x00\xff\x80data"
        encoded = CryptoEngine.encode_b64(original)
        decoded = CryptoEngine.decode_b64(encoded)
        assert decoded == original

    def test_b64_decode_invalid_raises(self):
        with pytest.raises(CryptoError, match="Base64"):
            CryptoEngine.decode_b64("!!!not-base64!!!")


class TestEncryption:
    """AES-256-GCM encryption/decryption tests."""

    def test_encrypt_decrypt_round_trip(self):
        plaintext = b"sensitive evidence data"
        encrypted = CryptoEngine.encrypt_evidence(plaintext, "strong-pass")
        assert encrypted["algorithm"] == "AES-256-GCM"
        assert "ciphertext" in encrypted
        decrypted = CryptoEngine.decrypt_evidence(encrypted, "strong-pass")
        assert decrypted == plaintext

    def test_wrong_passphrase_fails(self):
        plaintext = b"secret"
        encrypted = CryptoEngine.encrypt_evidence(plaintext, "correct-pass")
        with pytest.raises(CryptoError):
            CryptoEngine.decrypt_evidence(encrypted, "wrong-pass")

    def test_empty_plaintext(self):
        encrypted = CryptoEngine.encrypt_evidence(b"", "pass")
        decrypted = CryptoEngine.decrypt_evidence(encrypted, "pass")
        assert decrypted == b""

    def test_large_data(self):
        plaintext = b"x" * 100_000
        encrypted = CryptoEngine.encrypt_evidence(plaintext, "pass")
        decrypted = CryptoEngine.decrypt_evidence(encrypted, "pass")
        assert decrypted == plaintext

    def test_unsupported_algorithm_raises(self):
        with pytest.raises(CryptoError, match="Unsupported"):
            CryptoEngine.decrypt_evidence(
                {"algorithm": "RC4", "ciphertext": "", "salt": "", "nonce": ""}, "p"
            )


class TestUtilities:
    """Random token and secure compare tests."""

    def test_random_token_uniqueness(self):
        t1 = CryptoEngine.generate_random_token()
        t2 = CryptoEngine.generate_random_token()
        assert t1 != t2
        assert len(t1) == 64  # 32 bytes → 64 hex chars

    def test_secure_compare_equal(self):
        assert CryptoEngine.secure_compare("abc123", "abc123") is True

    def test_secure_compare_unequal(self):
        assert CryptoEngine.secure_compare("abc123", "xyz789") is False
