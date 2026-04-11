"""Tests for environment_probe (Phase N)."""

from __future__ import annotations

from unittest.mock import patch

from redcheck.core.environment_probe import (
    EnvironmentStatus,
    _check_dns,
    _check_tcp_connect,
    probe_environment,
)

# ---------------------------------------------------------------------------
# DNS helper
# ---------------------------------------------------------------------------


class TestCheckDns:
    @patch("redcheck.core.environment_probe.socket.getaddrinfo")
    def test_ok(self, mock_gai):
        mock_gai.return_value = [(2, 1, 6, "", ("1.2.3.4", 0))]
        ok, ips = _check_dns("example.com")
        assert ok is True
        assert "1.2.3.4" in ips

    @patch("redcheck.core.environment_probe.socket.getaddrinfo", side_effect=OSError)
    def test_fail(self, mock_gai):
        ok, ips = _check_dns("bad.invalid")
        assert ok is False
        assert ips == []


# ---------------------------------------------------------------------------
# TCP connect helper
# ---------------------------------------------------------------------------


class TestCheckTcpConnect:
    @patch("redcheck.core.environment_probe.socket.create_connection")
    def test_ok(self, mock_conn):
        mock_conn.return_value.__enter__ = lambda s: s
        mock_conn.return_value.__exit__ = lambda s, *a: None
        mock_conn.return_value.close = lambda: None
        ok, lat = _check_tcp_connect("example.com", 443)
        assert ok is True
        assert lat is not None

    @patch("redcheck.core.environment_probe.socket.create_connection", side_effect=OSError)
    def test_fail(self, mock_conn):
        ok, lat = _check_tcp_connect("bad.invalid", 443)
        assert ok is False
        assert lat is None


# ---------------------------------------------------------------------------
# probe_environment
# ---------------------------------------------------------------------------


class TestProbeEnvironment:
    @patch("redcheck.core.environment_probe._check_tcp_connect", return_value=(True, 5.0))
    @patch("redcheck.core.environment_probe._check_dns", return_value=(True, ["1.2.3.4"]))
    def test_stable(self, mock_dns, mock_tcp):
        status = probe_environment(["example.com"])
        assert isinstance(status, EnvironmentStatus)
        assert status.network_status == "stable"
        assert status.dns_resolution == "ok"
        assert status.target_reachable is True

    @patch("redcheck.core.environment_probe._check_tcp_connect", return_value=(False, None))
    @patch("redcheck.core.environment_probe._check_dns", return_value=(True, ["1.2.3.4"]))
    def test_dns_ok_tcp_fail_unreachable(self, mock_dns, mock_tcp):
        status = probe_environment(["example.com"])
        assert status.network_status == "unreachable"
        assert status.target_reachable is False

    @patch("redcheck.core.environment_probe._check_tcp_connect", return_value=(False, None))
    @patch("redcheck.core.environment_probe._check_dns", return_value=(False, []))
    def test_unreachable(self, mock_dns, mock_tcp):
        status = probe_environment(["example.com"])
        assert status.network_status == "unreachable"
        assert status.dns_resolution == "failed"

    @patch("redcheck.core.environment_probe._check_tcp_connect", return_value=(True, 2.0))
    @patch("redcheck.core.environment_probe._check_dns", return_value=(True, ["1.2.3.4"]))
    def test_external_dependencies(self, mock_dns, mock_tcp):
        status = probe_environment(["example.com"], external_deps=["nvd.nist.gov:443"])
        d = status.to_dict()
        assert "network_status" in d
        assert "external_dependencies" in d

    def test_empty_targets(self):
        status = probe_environment([])
        assert status.network_status == "stable"
        assert status.target_reachable is False  # no targets = no reachable

    @patch("redcheck.core.environment_probe._check_tcp_connect", return_value=(True, 3.0))
    @patch(
        "redcheck.core.environment_probe._check_dns",
        side_effect=[(True, ["1.1.1.1"]), (False, [])],
    )
    def test_partial_dns(self, mock_dns, mock_tcp):
        status = probe_environment(["a.com", "b.com"])
        assert status.dns_resolution == "partial"
