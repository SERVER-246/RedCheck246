"""Tests for SignatureVerifier — HMAC-SHA256 and Ed25519 modes."""

from __future__ import annotations

from pathlib import Path

import yaml

from redcheck.exceptions import CryptoError
from redcheck.security.signature_verifier import SignatureVerifier


def _write_roe(path: Path, data: dict) -> Path:
    roe_file = path / "roe.yml"
    roe_file.write_text(yaml.dump(data, default_flow_style=False), encoding="utf-8")
    return roe_file


class TestSignatureVerifierProperties:
    def test_not_configured(self) -> None:
        sv = SignatureVerifier()
        assert not sv.is_configured
        assert sv.mode == "none"

    def test_hmac_mode(self) -> None:
        sv = SignatureVerifier(secret="mysecret")
        assert sv.is_configured
        assert sv.mode == "hmac-sha256"

    def test_ed25519_mode(self) -> None:
        sv = SignatureVerifier(private_key_pem=b"fake")
        assert sv.is_configured
        assert sv.mode == "ed25519"


class TestHMACSignVerifyRoE:
    def test_sign_and_verify_roe(self, tmp_path: Path) -> None:
        data = {
            "engagement_id": "E1",
            "authorizer": "admin",
            "targets": ["10.0.0.1"],
        }
        roe_file = _write_roe(tmp_path, data)
        sv = SignatureVerifier(secret="s3cret")
        sig = sv.sign_roe(roe_file)
        assert isinstance(sig, str)
        assert len(sig) == 64  # HMAC-SHA256 hex

        # Write signature into RoE
        data["signature"] = sig
        _write_roe(tmp_path, data)
        valid, msg = sv.verify_roe(roe_file)
        assert valid
        assert "verified" in msg.lower()

    def test_verify_tampered_roe(self, tmp_path: Path) -> None:
        data = {"engagement_id": "E1", "authorizer": "admin"}
        roe_file = _write_roe(tmp_path, data)
        sv = SignatureVerifier(secret="s3cret")
        sig = sv.sign_roe(roe_file)
        data["signature"] = "0" * 64  # wrong sig
        _write_roe(tmp_path, data)
        valid, msg = sv.verify_roe(roe_file)
        assert not valid
        assert "mismatch" in msg.lower()

    def test_verify_no_signature_field(self, tmp_path: Path) -> None:
        data = {"engagement_id": "E1"}
        roe_file = _write_roe(tmp_path, data)
        sv = SignatureVerifier(secret="s3cret")
        valid, msg = sv.verify_roe(roe_file)
        assert not valid
        assert "No signature" in msg

    def test_verify_file_not_found(self, tmp_path: Path) -> None:
        sv = SignatureVerifier(secret="s3cret")
        valid, msg = sv.verify_roe(tmp_path / "nope.yml")
        assert not valid
        assert "not found" in msg.lower()

    def test_verify_not_configured(self, tmp_path: Path) -> None:
        roe_file = _write_roe(tmp_path, {"x": 1})
        sv = SignatureVerifier()
        valid, msg = sv.verify_roe(roe_file)
        assert not valid
        assert "not configured" in msg.lower()

    def test_sign_not_configured(self, tmp_path: Path) -> None:
        roe_file = _write_roe(tmp_path, {"x": 1})
        sv = SignatureVerifier()
        try:
            sv.sign_roe(roe_file)
            assert False, "Should raise"
        except CryptoError:
            pass


class TestHMACEvidence:
    def test_sign_verify_evidence(self) -> None:
        sv = SignatureVerifier(secret="key")
        data = b"evidence payload"
        sig = sv.sign_evidence(data)
        assert sv.verify_evidence(data, sig)

    def test_verify_evidence_wrong_sig(self) -> None:
        sv = SignatureVerifier(secret="key")
        assert not sv.verify_evidence(b"data", "0" * 64)

    def test_sign_evidence_not_configured(self) -> None:
        sv = SignatureVerifier()
        try:
            sv.sign_evidence(b"data")
            assert False, "Should raise"
        except CryptoError:
            pass

    def test_verify_evidence_not_configured(self) -> None:
        sv = SignatureVerifier()
        assert not sv.verify_evidence(b"data", "sig")


class TestEd25519SignVerify:
    def _generate_ed25519_keys(self) -> tuple[bytes, bytes]:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            PublicFormat,
        )

        private_key = Ed25519PrivateKey.generate()
        private_pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        public_pem = private_key.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        )
        return private_pem, public_pem

    def test_sign_and_verify_roe_ed25519(self, tmp_path: Path) -> None:
        priv, pub = self._generate_ed25519_keys()
        data = {"engagement_id": "E1", "authorizer": "admin"}
        roe_file = _write_roe(tmp_path, data)

        sv = SignatureVerifier(private_key_pem=priv, public_key_pem=pub)
        sig = sv.sign_roe(roe_file)
        data["signature"] = sig
        _write_roe(tmp_path, data)
        valid, msg = sv.verify_roe(roe_file)
        assert valid
        assert "Ed25519" in msg

    def test_verify_with_derived_public_key(self, tmp_path: Path) -> None:
        priv, _ = self._generate_ed25519_keys()
        data = {"engagement_id": "E2"}
        roe_file = _write_roe(tmp_path, data)

        sv_sign = SignatureVerifier(private_key_pem=priv)
        sig = sv_sign.sign_roe(roe_file)
        data["signature"] = sig
        _write_roe(tmp_path, data)

        # Verify with only private key (derives public key)
        sv_verify = SignatureVerifier(private_key_pem=priv)
        valid, msg = sv_verify.verify_roe(roe_file)
        assert valid

    def test_ed25519_sign_evidence(self) -> None:
        priv, pub = self._generate_ed25519_keys()
        sv = SignatureVerifier(private_key_pem=priv, public_key_pem=pub)
        sig = sv.sign_evidence(b"test data")
        assert sv.verify_evidence(b"test data", sig)

    def test_ed25519_verify_bad_signature(self) -> None:
        priv, pub = self._generate_ed25519_keys()
        sv = SignatureVerifier(private_key_pem=priv, public_key_pem=pub)
        assert not sv.verify_evidence(b"test data", "aa" * 64)

    def test_ed25519_invalid_hex_sig_roe(self, tmp_path: Path) -> None:
        priv, pub = self._generate_ed25519_keys()
        data = {"engagement_id": "E1", "signature": "not-hex!"}
        roe_file = _write_roe(tmp_path, data)
        sv = SignatureVerifier(private_key_pem=priv, public_key_pem=pub)
        valid, msg = sv.verify_roe(roe_file)
        assert not valid
        assert "Invalid hex" in msg

    def test_ed25519_no_key_raises(self) -> None:
        sv = SignatureVerifier()
        sv._public_key_pem = None
        sv._private_key_pem = None
        try:
            sv._ed25519_sign(b"data")
            assert False
        except CryptoError:
            pass

    def test_ed25519_verify_no_keys_raises(self) -> None:
        sv = SignatureVerifier()
        try:
            sv._ed25519_verify(b"data", b"sig")
            assert False
        except CryptoError:
            pass

    def test_verify_evidence_invalid_hex(self) -> None:
        priv, pub = self._generate_ed25519_keys()
        sv = SignatureVerifier(private_key_pem=priv, public_key_pem=pub)
        assert not sv.verify_evidence(b"data", "not-hex!")
