"""Tests for AuditLogger — encryption, hash chains, sessions."""

from __future__ import annotations

import json
from pathlib import Path

from redcheck.core.audit import AuditLogger, _decrypt_entry, _derive_key, _encrypt_entry


class TestDeriveKey:
    def test_returns_32_bytes(self) -> None:
        key = _derive_key("session123", "sid-abc")
        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_deterministic(self) -> None:
        k1 = _derive_key("code", "sid")
        k2 = _derive_key("code", "sid")
        assert k1 == k2

    def test_different_inputs(self) -> None:
        k1 = _derive_key("a", "sid")
        k2 = _derive_key("b", "sid")
        assert k1 != k2


class TestEncryptDecrypt:
    def test_round_trip(self) -> None:
        key = _derive_key("code", "sid")
        plaintext = b"hello world"
        ct = _encrypt_entry(plaintext, key, "sid")
        pt = _decrypt_entry(ct, key, "sid")
        assert pt == plaintext


class TestAuditLogger:
    def test_basic_log(self, tmp_path: Path) -> None:
        logger = AuditLogger(log_path=tmp_path / "audit.log")
        entry = logger.log("TEST_ACTION", details="test detail", operator="tester")
        assert entry["action"] == "TEST_ACTION"
        assert entry["operator"] == "tester"
        assert "hash" in entry

    def test_hash_chain(self, tmp_path: Path) -> None:
        logger = AuditLogger(log_path=tmp_path / "audit.log")
        e1 = logger.log("A1")
        e2 = logger.log("A2")
        assert e2["previous_hash"] == e1["hash"]

    def test_start_session_and_encrypted_log(self, tmp_path: Path) -> None:
        logger = AuditLogger(log_path=tmp_path / "audit.log")
        session_id = logger.start_session("mycode", "sid-123")
        assert session_id == "sid-123"
        assert logger.has_session
        logger.log("ENCRYPTED_ACTION")
        # Log file should contain base64 encrypted content
        content = (tmp_path / "audit.log").read_text(encoding="utf-8")
        lines = [entry for entry in content.splitlines() if entry.strip()]
        assert len(lines) == 1
        # Should not be plain JSON
        try:
            json.loads(lines[0])
            is_plain = True
        except json.JSONDecodeError:
            is_plain = False
        assert not is_plain  # encrypted

    def test_read_session(self, tmp_path: Path) -> None:
        logger = AuditLogger(log_path=tmp_path / "audit.log")
        logger.start_session("code", "sid-1")
        logger.log("ACTION_1", details="detail1")
        logger.log("ACTION_2", details="detail2")

        entries = logger.read_session("code", "sid-1")
        assert len(entries) == 2
        assert entries[0]["action"] == "ACTION_1"
        assert entries[1]["action"] == "ACTION_2"

    def test_verify_chain_empty_log(self, tmp_path: Path) -> None:
        logger = AuditLogger(log_path=tmp_path / "audit.log")
        valid, count, msg = logger.verify_chain()
        assert valid
        assert count == 0

    def test_verify_chain_unencrypted(self, tmp_path: Path) -> None:
        logger = AuditLogger(log_path=tmp_path / "audit.log")
        logger.log("A1")
        logger.log("A2")
        logger.log("A3")
        valid, count, msg = logger.verify_chain()
        assert valid
        assert count == 3

    def test_verify_chain_encrypted(self, tmp_path: Path) -> None:
        logger = AuditLogger(log_path=tmp_path / "audit.log")
        logger.start_session("code", "sid")
        logger.log("A1")
        logger.log("A2")
        valid, count, msg = logger.verify_chain("code", "sid")
        assert valid
        assert count == 2

    def test_log_policy_denial(self, tmp_path: Path) -> None:
        logger = AuditLogger(log_path=tmp_path / "audit.log")
        entry = logger.log_policy_denial("plug", "not allowed", engagement_id="E1")
        assert entry["action"] == "POLICY_DENIED"
        assert entry["level"] == "WARN"

    def test_log_activation_attempt(self, tmp_path: Path) -> None:
        logger = AuditLogger(log_path=tmp_path / "audit.log")
        entry = logger.log_activation_attempt(success=True)
        assert entry["action"] == "ACTIVATION_ATTEMPT"
        assert "True" in entry["details"]

        entry2 = logger.log_activation_attempt(success=False, operator="user")
        assert entry2["level"] == "WARN"

    def test_log_engagement_action(self, tmp_path: Path) -> None:
        logger = AuditLogger(log_path=tmp_path / "audit.log")
        entry = logger.log_engagement_action("START", "E1", details="started")
        assert entry["action"] == "START"
        assert entry["engagement_id"] == "E1"

    def test_recover_last_hash_from_existing(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.log"
        entry = {"action": "OLD", "hash": "abcdef1234567890"}
        log_path.write_text(json.dumps(entry) + "\n", encoding="utf-8")
        logger = AuditLogger(log_path=log_path)
        assert logger._previous_hash == "abcdef1234567890"

    def test_recover_last_hash_empty_file(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.log"
        log_path.write_text("", encoding="utf-8")
        logger = AuditLogger(log_path=log_path)
        assert logger._previous_hash == "GENESIS"

    def test_read_session_empty(self, tmp_path: Path) -> None:
        logger = AuditLogger(log_path=tmp_path / "audit.log")
        entries = logger.read_session("code", "sid")
        assert entries == []

    def test_default_log_path(self) -> None:
        path = AuditLogger._default_log_path()
        assert "audit.log" in path

    def test_reset(self, tmp_path: Path) -> None:
        AuditLogger.reset()
