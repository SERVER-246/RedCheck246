"""Tests for protocol fuzzer — payloads, rate limiting, mutation."""

import pytest

from redcheck.plugins.base_plugin import PluginRegistry


@pytest.fixture(autouse=True)
def register_fuzzer():
    from redcheck.plugins.fuzzing.protocol_fuzzer import FuzzingPlugin  # noqa: F401

    return


def _ctx(hosts=None):
    return {
        "authorized_targets": [
            {"host": h, "ports": [80], "protocols": ["tcp"]}
            for h in (hosts or ["fuzz-target.local"])
        ],
    }


class TestFuzzingPlugin:
    """Protocol fuzzer tests."""

    def test_plugin_registered(self):
        assert PluginRegistry.get("protocol-fuzzer") is not None

    def test_dry_run(self):
        plugin = PluginRegistry.get_instance("protocol-fuzzer")
        result = plugin.dry_run(_ctx())
        assert result.success is True
        assert result.metadata["mode"] == "dry-run"

    def test_payload_collections_loaded(self):
        """Verify payload lists are populated."""
        from redcheck.plugins.fuzzing.payloads import (
            ALL_PAYLOADS,
            SQLI_PAYLOADS,
            XSS_PAYLOADS,
        )

        assert len(SQLI_PAYLOADS) > 0
        assert len(XSS_PAYLOADS) > 0
        # ALL_PAYLOADS is a dict of category -> list
        assert len(ALL_PAYLOADS) >= 5
        total = sum(len(v) for v in ALL_PAYLOADS.values())
        assert total > 10

    def test_rate_limiter(self):
        """Rate limiter enforces interval."""
        from redcheck.plugins.fuzzing.protocol_fuzzer import _RateLimiter

        limiter = _RateLimiter(rps=1000)
        assert limiter._interval > 0

    def test_execute_returns_result(self):
        """Execute with no real server — still returns a result."""
        plugin = PluginRegistry.get_instance("protocol-fuzzer")
        result = plugin.execute(_ctx())
        assert result.plugin_name == "protocol-fuzzer"

    def test_plugin_requires_authorization(self):
        cls = PluginRegistry.get("protocol-fuzzer")
        assert cls.requires_authorization is True

    def test_plugin_category(self):
        cls = PluginRegistry.get("protocol-fuzzer")
        assert cls.category == "fuzzing"

    def test_health_check(self):
        plugin = PluginRegistry.get_instance("protocol-fuzzer")
        healthy, msg = plugin.health_check()
        assert healthy is True
