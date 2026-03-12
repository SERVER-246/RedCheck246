"""Tests for EvidenceStore — store, retrieve, integrity, encryption, query."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from redcheck.core.evidence_store import EvidenceStore  # noqa: I001
from redcheck.models import Evidence

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def store(tmp_path: Path) -> EvidenceStore:
    """Create a fresh EvidenceStore in a temp directory."""
    return EvidenceStore(tmp_path / "evidence")


@pytest.fixture
def evidence_dir(tmp_path: Path) -> Path:
    return tmp_path / "evidence"


# ---------------------------------------------------------------------------
# Store basics
# ---------------------------------------------------------------------------


class TestStoreBasics:
    """Store and retrieve evidence artifacts."""

    def test_store_returns_evidence_model(self, store: EvidenceStore):
        ev = store.store(b"hello world", "screenshot")
        assert isinstance(ev, Evidence)
        assert ev.evidence_type == "screenshot"
        assert ev.encrypted is False
        assert ev.size_bytes == len(b"hello world")

    def test_store_writes_file_to_disk(self, store: EvidenceStore):
        ev = store.store(b"data-payload", "capture")
        assert Path(ev.path).is_file()
        assert Path(ev.path).read_bytes() == b"data-payload"

    def test_store_computes_sha256(self, store: EvidenceStore):
        from redcheck.security.crypto import CryptoEngine

        data = b"verify-hash"
        ev = store.store(data, "hash_test")
        expected = CryptoEngine.hash_sha256(data)
        assert ev.sha256 == expected

    def test_store_increments_count(self, store: EvidenceStore):
        assert store.count == 0
        store.store(b"one", "t")
        assert store.count == 1
        store.store(b"two", "t")
        assert store.count == 2

    def test_store_with_plugin_and_finding_ref(self, store: EvidenceStore):
        ev = store.store(
            b"data",
            "network_capture",
            plugin_name="recon",
            finding_ref="FINDING-001",
        )
        assert ev.evidence_type == "network_capture"


# ---------------------------------------------------------------------------
# Retrieve
# ---------------------------------------------------------------------------


class TestRetrieve:
    """Retrieve evidence by SHA-256 hash."""

    def test_retrieve_existing(self, store: EvidenceStore):
        ev = store.store(b"retrieve-me", "test")
        result = store.retrieve(ev.sha256)
        assert result == b"retrieve-me"

    def test_retrieve_nonexistent_returns_none(self, store: EvidenceStore):
        assert store.retrieve("0" * 64) is None

    def test_retrieve_after_file_deleted(self, store: EvidenceStore):
        ev = store.store(b"will-delete", "test")
        Path(ev.path).unlink()
        assert store.retrieve(ev.sha256) is None


# ---------------------------------------------------------------------------
# Integrity verification
# ---------------------------------------------------------------------------


class TestIntegrity:
    """Verify evidence integrity checks."""

    def test_integrity_ok_for_valid_evidence(self, store: EvidenceStore):
        store.store(b"valid", "test")
        ok, errors = store.verify_integrity()
        assert ok is True
        assert errors == []

    def test_integrity_detects_missing_file(self, store: EvidenceStore):
        ev = store.store(b"will-vanish", "test")
        Path(ev.path).unlink()
        ok, errors = store.verify_integrity()
        assert ok is False
        assert len(errors) == 1
        assert "Missing file" in errors[0]

    def test_integrity_detects_tampered_file(self, store: EvidenceStore):
        ev = store.store(b"original", "test")
        Path(ev.path).write_bytes(b"tampered")
        ok, errors = store.verify_integrity()
        assert ok is False
        assert len(errors) == 1
        assert "Hash mismatch" in errors[0]

    def test_integrity_multiple_entries(self, store: EvidenceStore):
        store.store(b"one", "a")
        ev2 = store.store(b"two", "b")
        store.store(b"three", "c")
        # Tamper with one
        Path(ev2.path).write_bytes(b"modified")
        ok, errors = store.verify_integrity()
        assert ok is False
        assert len(errors) == 1

    def test_integrity_empty_store(self, store: EvidenceStore):
        ok, errors = store.verify_integrity()
        assert ok is True
        assert errors == []


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------


class TestEncryption:
    """Store evidence with AES-256-GCM encryption."""

    def test_encrypted_store(self, store: EvidenceStore):
        ev = store.store(
            b"secret-data",
            "encrypted_capture",
            encrypt=True,
            passphrase="strong-pass-123",
        )
        assert ev.encrypted is True
        # Raw file should be valid JSON with AES-256-GCM structure
        raw = Path(ev.path).read_bytes()
        enc = json.loads(raw)
        assert enc["algorithm"] == "AES-256-GCM"

    def test_encrypted_integrity_check(self, store: EvidenceStore):
        store.store(
            b"enc-data",
            "enc_test",
            encrypt=True,
            passphrase="pass",
        )
        ok, errors = store.verify_integrity()
        assert ok is True
        assert errors == []

    def test_encrypted_corrupt_file(self, store: EvidenceStore):
        ev = store.store(
            b"enc-data",
            "enc_test",
            encrypt=True,
            passphrase="pass",
        )
        Path(ev.path).write_bytes(b"not-json")
        ok, errors = store.verify_integrity()
        assert ok is False
        assert "Corrupt encrypted file" in errors[0]

    def test_encrypt_without_passphrase_stores_plaintext(self, store: EvidenceStore):
        ev = store.store(b"no-pass", "test", encrypt=True)
        assert ev.encrypted is False
        assert Path(ev.path).read_bytes() == b"no-pass"


# ---------------------------------------------------------------------------
# Query
# ---------------------------------------------------------------------------


class TestQuery:
    """Query evidence by metadata filters."""

    def test_query_by_plugin_name(self, store: EvidenceStore):
        store.store(b"a", "t", plugin_name="recon")
        store.store(b"b", "t", plugin_name="sast")
        store.store(b"c", "t", plugin_name="recon")
        results = store.query(plugin_name="recon")
        assert len(results) == 2
        assert all(isinstance(r, Evidence) for r in results)

    def test_query_by_evidence_type(self, store: EvidenceStore):
        store.store(b"a", "screenshot", plugin_name="recon")
        store.store(b"b", "network_capture", plugin_name="recon")
        results = store.query(evidence_type="screenshot")
        assert len(results) == 1

    def test_query_by_finding_ref(self, store: EvidenceStore):
        store.store(b"a", "t", finding_ref="F-001")
        store.store(b"b", "t", finding_ref="F-002")
        results = store.query(finding_ref="F-001")
        assert len(results) == 1

    def test_query_combined_filters(self, store: EvidenceStore):
        store.store(b"a", "screenshot", plugin_name="recon", finding_ref="F-1")
        store.store(b"b", "screenshot", plugin_name="sast", finding_ref="F-2")
        store.store(b"c", "capture", plugin_name="recon", finding_ref="F-3")
        results = store.query(plugin_name="recon", evidence_type="screenshot")
        assert len(results) == 1

    def test_query_no_match(self, store: EvidenceStore):
        store.store(b"a", "t", plugin_name="recon")
        results = store.query(plugin_name="nonexistent")
        assert results == []

    def test_query_no_filters(self, store: EvidenceStore):
        store.store(b"a", "t1")
        store.store(b"b", "t2")
        results = store.query()
        assert len(results) == 2


# ---------------------------------------------------------------------------
# Index persistence
# ---------------------------------------------------------------------------


class TestIndexPersistence:
    """Verify JSON index is persisted and reloaded."""

    def test_index_file_created(self, evidence_dir: Path):
        store = EvidenceStore(evidence_dir)
        store.store(b"data", "test")
        idx_path = evidence_dir / "evidence_index.json"
        assert idx_path.is_file()
        idx = json.loads(idx_path.read_text(encoding="utf-8"))
        assert idx["version"] == "1.0.0"
        assert len(idx["entries"]) == 1

    def test_index_reload(self, evidence_dir: Path):
        store1 = EvidenceStore(evidence_dir)
        ev = store1.store(b"persist", "test")
        # New store instance loads existing index
        store2 = EvidenceStore(evidence_dir)
        assert store2.count == 1
        result = store2.retrieve(ev.sha256)
        assert result == b"persist"

    def test_corrupt_index_recovers(self, evidence_dir: Path):
        store = EvidenceStore(evidence_dir)
        store.store(b"data", "test")
        # Corrupt the index
        idx_path = evidence_dir / "evidence_index.json"
        idx_path.write_text("not-valid-json", encoding="utf-8")
        # New store should recover with empty entries
        store2 = EvidenceStore(evidence_dir)
        assert store2.count == 0

    def test_creates_evidence_dir_if_missing(self, tmp_path: Path):
        deep = tmp_path / "a" / "b" / "c" / "evidence"
        store = EvidenceStore(deep)
        assert deep.is_dir()
        store.store(b"nested", "test")
        assert store.count == 1
