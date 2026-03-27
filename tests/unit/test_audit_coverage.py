"""Coverage tests for redcheck/core/audit.py — XOR fallback + chain verification."""

from __future__ import annotations

import json

from redcheck.core.audit import AuditLogger, _decrypt_entry, _derive_key, _encrypt_entry


class TestDeriveKeyFallback:
    def test_no_crypto_sha256_fallback(self):
        import redcheck.core.audit as amod

        original = amod._HAS_CRYPTO
        try:
            amod._HAS_CRYPTO = False
            key = _derive_key("session_code", "session_id")
            assert isinstance(key, bytes)
            assert len(key) == 32
            # Deterministic
            assert _derive_key("session_code", "session_id") == key
        finally:
            amod._HAS_CRYPTO = original


class TestEncryptDecryptFallback:
    def test_xor_round_trip(self):
        import redcheck.core.audit as amod

        original = amod._HAS_CRYPTO
        try:
            amod._HAS_CRYPTO = False
            key = _derive_key("code", "sid")
            plaintext = b"hello world audit entry"
            ct = _encrypt_entry(plaintext, key, "sid")
            pt = _decrypt_entry(ct, key, "sid")
            assert pt == plaintext
        finally:
            amod._HAS_CRYPTO = original


class TestRecoverLastHash:
    def test_corrupted_json_returns_genesis(self, tmp_path):
        log_file = tmp_path / "audit.log"
        log_file.write_text("not valid json\n", encoding="utf-8")
        al = AuditLogger(log_path=str(log_file))
        assert al._previous_hash == "GENESIS"

    def test_valid_json_returns_hash(self, tmp_path):
        log_file = tmp_path / "audit.log"
        entry = {"action": "test", "hash": "abc123"}
        log_file.write_text(json.dumps(entry) + "\n", encoding="utf-8")
        al = AuditLogger(log_path=str(log_file))
        assert al._previous_hash == "abc123"


class TestReadSession:
    def test_read_encrypted_session(self, tmp_path):
        log_file = tmp_path / "audit.log"
        al = AuditLogger(log_path=str(log_file))
        al.start_session("mycode", "mysession")
        al.log("ACTION_1", "first entry")
        al.log("ACTION_2", "second entry")

        entries = al.read_session("mycode", "mysession")
        assert len(entries) == 2
        assert entries[0]["action"] == "ACTION_1"
        assert entries[1]["action"] == "ACTION_2"

    def test_read_plain_json_fallback(self, tmp_path):
        log_file = tmp_path / "audit.log"
        # Write plain JSON entries (unencrypted)
        entry1 = {"action": "A", "hash": "h1", "previous_hash": "GENESIS"}
        entry2 = {"action": "B", "hash": "h2", "previous_hash": "h1"}
        log_file.write_text(
            json.dumps(entry1) + "\n" + json.dumps(entry2) + "\n",
            encoding="utf-8",
        )
        al = AuditLogger(log_path=str(log_file))
        # Use a wrong session code so decryption fails, falls back to JSON
        entries = al.read_session("wrong_code", "wrong_sid")
        assert len(entries) == 2


class TestVerifyChain:
    def test_verify_unencrypted_chain(self, tmp_path):
        log_file = tmp_path / "audit.log"
        al = AuditLogger(log_path=str(log_file))
        al.log("A1", "detail1")
        al.log("A2", "detail2")
        al.log("A3", "detail3")

        ok, count, msg = al.verify_chain()
        assert ok is True
        assert count == 3

    def test_verify_encrypted_chain(self, tmp_path):
        log_file = tmp_path / "audit.log"
        al = AuditLogger(log_path=str(log_file))
        al.start_session("code123", "sess1")
        al.log("E1", "encrypted1")
        al.log("E2", "encrypted2")

        ok, count, msg = al.verify_chain("code123", "sess1")
        assert ok is True
        assert count == 2

    def test_verify_tampered_hash(self, tmp_path):
        log_file = tmp_path / "audit.log"
        al = AuditLogger(log_path=str(log_file))
        al.log("A1", "detail1")
        al.log("A2", "detail2")

        # Tamper with the log
        lines = log_file.read_text(encoding="utf-8").strip().split("\n")
        entry = json.loads(lines[1])
        entry["hash"] = "TAMPERED"
        lines[1] = json.dumps(entry, default=str)
        log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

        ok, idx, msg = al.verify_chain()
        assert ok is False
        assert "mismatch" in msg.lower() or "break" in msg.lower()

    def test_verify_tampered_previous_hash(self, tmp_path):
        log_file = tmp_path / "audit.log"
        al = AuditLogger(log_path=str(log_file))
        al.log("A1", "detail1")
        al.log("A2", "detail2")

        lines = log_file.read_text(encoding="utf-8").strip().split("\n")
        entry = json.loads(lines[1])
        entry["previous_hash"] = "WRONG"
        lines[1] = json.dumps(entry, default=str)
        log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

        ok, idx, msg = al.verify_chain()
        assert ok is False

    def test_verify_empty_log(self, tmp_path):
        log_file = tmp_path / "audit.log"
        log_file.write_text("", encoding="utf-8")
        al = AuditLogger(log_path=str(log_file))
        ok, count, msg = al.verify_chain()
        assert ok is True
