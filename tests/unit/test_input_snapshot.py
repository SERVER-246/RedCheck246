"""Tests for InputSnapshotCapture and helpers (Phase L)."""

from __future__ import annotations

import hashlib
from unittest.mock import patch

from redcheck.core.input_snapshot import (
    InputSnapshotCapture,
    compute_target_fingerprint,
    hash_http_response,
    hash_plugin_input,
    resolve_dns,
)
from redcheck.models import InputSnapshot

# ---------------------------------------------------------------------------
# DNS resolution
# ---------------------------------------------------------------------------


class TestResolveDns:
    @patch("redcheck.core.input_snapshot.socket.getaddrinfo")
    def test_successful_resolution(self, mock_gai):
        mock_gai.return_value = [
            (2, 1, 6, "", ("93.184.216.34", 0)),
        ]
        result = resolve_dns(["example.com"])
        assert result["example.com"] == ["93.184.216.34"]

    @patch("redcheck.core.input_snapshot.socket.getaddrinfo", side_effect=OSError("fail"))
    def test_failed_resolution(self, mock_gai):
        result = resolve_dns(["nonexistent.invalid"])
        assert result["nonexistent.invalid"] == []


# ---------------------------------------------------------------------------
# Target fingerprint
# ---------------------------------------------------------------------------


class TestTargetFingerprint:
    def test_deterministic(self):
        fp1 = compute_target_fingerprint(["a.com", "b.com"])
        fp2 = compute_target_fingerprint(["b.com", "a.com"])
        assert fp1 == fp2  # sorted → same hash

    def test_different_targets_different_hash(self):
        fp1 = compute_target_fingerprint(["a.com"])
        fp2 = compute_target_fingerprint(["b.com"])
        assert fp1 != fp2


# ---------------------------------------------------------------------------
# Plugin input hashing
# ---------------------------------------------------------------------------


class TestHashPluginInput:
    def test_excludes_private_keys(self):
        ctx1 = {"target": "x", "_runtime": {"obj": object()}}
        ctx2 = {"target": "x", "_runtime": {"obj": "other"}}
        assert hash_plugin_input("p", ctx1) == hash_plugin_input("p", ctx2)

    def test_deterministic(self):
        ctx = {"a": 1, "b": 2}
        assert hash_plugin_input("p", ctx) == hash_plugin_input("p", ctx)


# ---------------------------------------------------------------------------
# HTTP response hashing
# ---------------------------------------------------------------------------


class TestHashHttpResponse:
    def test_returns_sha256(self):
        body = b"Hello"
        expected = hashlib.sha256(body).hexdigest()
        assert hash_http_response("http://x", body) == expected


# ---------------------------------------------------------------------------
# InputSnapshotCapture
# ---------------------------------------------------------------------------


class TestInputSnapshotCapture:
    @patch("redcheck.core.input_snapshot.resolve_dns")
    def test_full_lifecycle(self, mock_dns):
        mock_dns.return_value = {"example.com": ["1.2.3.4"]}

        cap = InputSnapshotCapture(run_id="run-1", targets=["example.com"])
        dns = cap.resolve_targets()
        assert dns == {"example.com": ["1.2.3.4"]}

        cap.record_plugin_input("passive-recon", {"target": "example.com"})
        cap.record_http_response("https://example.com", b"<html/>")

        snap = cap.finalise()
        assert isinstance(snap, InputSnapshot)
        assert snap.run_id == "run-1"
        assert snap.dns_resolutions == {"example.com": ["1.2.3.4"]}
        assert "https://example.com" in snap.http_responses
        assert "passive-recon" in snap.plugin_inputs
        assert snap.snapshot_hash  # non-empty
        assert snap.target_fingerprint  # non-empty

    @patch("redcheck.core.input_snapshot.resolve_dns", return_value={})
    def test_empty_snapshot(self, mock_dns):
        cap = InputSnapshotCapture(run_id="run-2", targets=[])
        snap = cap.finalise()
        assert snap.dns_resolutions == {}
        assert snap.plugin_inputs == {}
        assert snap.snapshot_hash  # still has a hash

    @patch("redcheck.core.input_snapshot.resolve_dns")
    def test_snapshot_hash_deterministic(self, mock_dns):
        mock_dns.return_value = {"a.com": ["1.1.1.1"]}
        cap1 = InputSnapshotCapture(run_id="r", targets=["a.com"])
        cap1.resolve_targets()
        cap1.record_plugin_input("p", {"x": 1})

        cap2 = InputSnapshotCapture(run_id="r", targets=["a.com"])
        cap2.resolve_targets()
        cap2.record_plugin_input("p", {"x": 1})

        # Same data → same snapshot_hash (captured_at differs but isn't in hash)
        s1 = cap1.finalise()
        s2 = cap2.finalise()
        assert s1.snapshot_hash == s2.snapshot_hash
