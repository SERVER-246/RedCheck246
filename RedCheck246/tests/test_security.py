"""Tests for RoE validator and signature verifier."""

import pytest
import yaml
from datetime import datetime, timedelta, timezone

from redcheck.security.roe_validator import validate_roe_file
from redcheck.security.signature_verifier import SignatureVerifier


@pytest.fixture
def valid_roe(tmp_path):
    now = datetime.now(timezone.utc)
    roe = {
        "engagement_id": "SIG-TEST-001",
        "authorizer": "Sig Tester",
        "authorized_targets": [{"host": "sig.test.local"}],
        "allowed_tests": ["passive-recon"],
        "start_time_utc": (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "end_time_utc": (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "signature": "",
    }
    path = tmp_path / "roe_sig.yaml"
    with open(path, "w") as f:
        yaml.dump(roe, f)
    return path


class TestRoEValidator:
    def test_valid_roe(self, valid_roe):
        valid, msg, data = validate_roe_file(valid_roe)
        assert valid is True

    def test_nonexistent_file(self):
        valid, msg, data = validate_roe_file("/no/such/file.yaml")
        assert valid is False

    def test_non_yaml_extension(self, tmp_path):
        path = tmp_path / "roe.txt"
        path.write_text("not yaml")
        valid, msg, data = validate_roe_file(path)
        assert valid is False

    def test_empty_targets(self, tmp_path):
        now = datetime.now(timezone.utc)
        roe = {
            "engagement_id": "EMPTY",
            "authorizer": "Test",
            "authorized_targets": [],
            "allowed_tests": ["recon"],
            "start_time_utc": (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "end_time_utc": (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        path = tmp_path / "empty.yaml"
        with open(path, "w") as f:
            yaml.dump(roe, f)
        valid, msg, _ = validate_roe_file(path)
        assert valid is False
        assert "target" in msg.lower()


class TestSignatureVerifier:
    def test_sign_and_verify(self, valid_roe):
        sv = SignatureVerifier(secret="test-secret-key-246")
        sig = sv.sign_roe(valid_roe)
        assert len(sig) == 64  # SHA-256 hex

        # Write signature back
        with open(valid_roe, "r") as f:
            data = yaml.safe_load(f)
        data["signature"] = sig
        with open(valid_roe, "w") as f:
            yaml.dump(data, f)

        ok, msg = sv.verify_roe(valid_roe)
        assert ok is True

    def test_tampered_roe_fails(self, valid_roe):
        sv = SignatureVerifier(secret="test-secret-key-246")
        sig = sv.sign_roe(valid_roe)

        with open(valid_roe, "r") as f:
            data = yaml.safe_load(f)
        data["signature"] = sig
        data["authorizer"] = "TAMPERED"
        with open(valid_roe, "w") as f:
            yaml.dump(data, f)

        ok, msg = sv.verify_roe(valid_roe)
        assert ok is False
        assert "mismatch" in msg.lower()

    def test_no_secret_returns_false(self, valid_roe):
        sv = SignatureVerifier(secret=None)
        ok, msg = sv.verify_roe(valid_roe)
        assert ok is False

    def test_evidence_signing(self):
        sv = SignatureVerifier(secret="evidence-key")
        data = b"critical finding data"
        sig = sv.sign_evidence(data)
        assert sv.verify_evidence(data, sig) is True
        assert sv.verify_evidence(b"tampered", sig) is False
