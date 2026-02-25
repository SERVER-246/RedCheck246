"""Tests for network_scan module — ServiceVersionDetector and NetworkScanner."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from redcheck.plugins.recon.network_scan import (
    NetworkScanner,
    ServiceVersionDetector,
    _get_fingerprints,
    _load_fingerprints,
)


class TestLoadFingerprints:
    def test_returns_dict(self) -> None:
        db = _load_fingerprints()
        assert isinstance(db, dict)

    def test_get_fingerprints_cached(self) -> None:
        db1 = _get_fingerprints()
        db2 = _get_fingerprints()
        assert db1 is db2


class TestServiceVersionDetector:
    def test_empty_banner_known_port(self) -> None:
        det = ServiceVersionDetector()
        svc, conf = det.detect("", port=80)
        # Either port-default or unknown
        assert isinstance(svc, str)
        assert isinstance(conf, float)

    def test_empty_banner_unknown_port(self) -> None:
        det = ServiceVersionDetector()
        svc, conf = det.detect("", port=99999)
        assert svc == "unknown"
        assert conf == 0.0

    def test_known_banner(self) -> None:
        det = ServiceVersionDetector()
        # Try a common banner substring
        svc, conf = det.detect("SSH-2.0-OpenSSH_8.9", port=22)
        # Should match something or fallback to port default
        assert isinstance(svc, str)
        assert conf > 0.0

    def test_no_banner_no_port(self) -> None:
        det = ServiceVersionDetector()
        svc, conf = det.detect("", port=None)
        assert svc == "unknown"
        assert conf == 0.0


class TestNetworkScanner:
    def test_dry_run_with_targets(self) -> None:
        plugin = NetworkScanner()
        result = plugin.dry_run(
            {
                "authorized_targets": [
                    {"host": "10.0.0.1", "ports": [80]},
                    "10.0.0.2",
                ]
            }
        )
        assert result.success
        assert result.metadata["mode"] == "dry-run"
        assert len(result.metadata["hosts"]) == 2

    def test_dry_run_no_targets(self) -> None:
        plugin = NetworkScanner()
        result = plugin.dry_run({"authorized_targets": []})
        assert result.success
        assert len(result.metadata["hosts"]) == 0

    def test_execute_no_targets(self) -> None:
        plugin = NetworkScanner()
        result = plugin.execute({"authorized_targets": []})
        assert result.success is False
        assert "No targets" in result.errors[0]

    def test_execute_with_mock(self) -> None:
        plugin = NetworkScanner()
        # Mock PacketCraft to avoid real network calls
        plugin._pkt = MagicMock()
        plugin._pkt.tcp_syn_probe = AsyncMock(return_value=(True, 5.0))

        result = plugin.execute(
            {
                "authorized_targets": [{"host": "10.0.0.1", "ports": [80, 443]}],
            }
        )
        assert result.success
        assert result.metadata["hosts_scanned"] == 1

    def test_execute_all_closed(self) -> None:
        plugin = NetworkScanner()
        plugin._pkt = MagicMock()
        plugin._pkt.tcp_syn_probe = AsyncMock(return_value=(False, 0.0))

        result = plugin.execute(
            {
                "authorized_targets": [{"host": "10.0.0.1", "ports": [80]}],
            }
        )
        assert result.success
        assert len(result.findings) == 0  # nothing open

    def test_health_check(self) -> None:
        plugin = NetworkScanner()
        ok, msg = plugin.health_check()
        assert isinstance(ok, bool)
        assert isinstance(msg, str)
