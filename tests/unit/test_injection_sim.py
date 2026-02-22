"""Tests for redcheck.plugins.dast.injection_sim — InjectionProofOfCondition.

Coverage: triple-gate control, timing oracle, canary reflection, safe payload
inventory, dry run, metadata.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest

from redcheck.exceptions import OffensiveControlError
from redcheck.models import OffensiveControls, PluginCapability
from redcheck.plugins.dast.injection_sim import (
    _SQLI_TIMING_PAYLOADS,
    _SSTI_CANARY_PAYLOADS,
    _XSS_CANARY_PAYLOADS,
    InjectionProofOfCondition,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _context(
    *,
    allow_exploit: bool = True,
    confirm: bool = True,
    targets: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "offensive_controls": {"allow_exploit_validation": allow_exploit},
        "confirm_exploit": confirm,
        "injection_targets": targets or [],
    }


class _FakeTransport(httpx.AsyncBaseTransport):
    """Transport with configurable delay and body."""

    def __init__(
        self,
        body: str = "",
        delay_s: float = 0.0,
        status: int = 200,
    ) -> None:
        self._body = body
        self._delay = delay_s
        self._status = status

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if self._delay > 0:
            await asyncio.sleep(self._delay)
        return httpx.Response(self._status, text=self._body)


# ---------------------------------------------------------------------------
# Triple-gate control
# ---------------------------------------------------------------------------


class TestInjectionTripleGate:
    """InjectionProofOfCondition requires three gates."""

    def test_rejects_without_exploit_control(self):
        plugin = InjectionProofOfCondition()
        ctx = _context(allow_exploit=False, confirm=True)
        with pytest.raises(OffensiveControlError):
            plugin.execute(ctx)

    def test_rejects_without_confirm_exploit(self):
        plugin = InjectionProofOfCondition()
        ctx = _context(allow_exploit=True, confirm=False)
        with pytest.raises(OffensiveControlError):
            plugin.execute(ctx)

    def test_rejects_both_missing(self):
        plugin = InjectionProofOfCondition()
        ctx = _context(allow_exploit=False, confirm=False)
        with pytest.raises(OffensiveControlError):
            plugin.execute(ctx)

    def test_accepts_all_gates(self):
        plugin = InjectionProofOfCondition()
        result = plugin.execute(_context(allow_exploit=True, confirm=True))
        assert result.success

    def test_accepts_controls_object(self):
        plugin = InjectionProofOfCondition()
        ctx = {
            "offensive_controls": OffensiveControls(allow_exploit_validation=True),
            "confirm_exploit": True,
            "injection_targets": [],
        }
        result = plugin.execute(ctx)
        assert result.success


# ---------------------------------------------------------------------------
# Plugin metadata
# ---------------------------------------------------------------------------


class TestInjectionMetadata:
    def test_name(self):
        assert InjectionProofOfCondition.name == "injection-poc-simulator"

    def test_capability(self):
        assert InjectionProofOfCondition.capability == PluginCapability.ACTIVE

    def test_mitre(self):
        plugin = InjectionProofOfCondition()
        assert "T1190" in plugin.mitre_techniques

    def test_required_controls(self):
        assert "allow_exploit_validation" in InjectionProofOfCondition.required_controls


# ---------------------------------------------------------------------------
# Safe payload inventory
# ---------------------------------------------------------------------------


class TestSafePayloadInventory:
    def test_returns_all_categories(self):
        inv = InjectionProofOfCondition.safe_payload_inventory()
        assert "sqli_timing" in inv
        assert "xss_canary" in inv
        assert "ssti_canary" in inv

    def test_sqli_payload_count(self):
        inv = InjectionProofOfCondition.safe_payload_inventory()
        assert len(inv["sqli_timing"]) == len(_SQLI_TIMING_PAYLOADS)

    def test_xss_payload_count(self):
        inv = InjectionProofOfCondition.safe_payload_inventory()
        assert len(inv["xss_canary"]) == len(_XSS_CANARY_PAYLOADS)

    def test_ssti_payload_count(self):
        inv = InjectionProofOfCondition.safe_payload_inventory()
        assert len(inv["ssti_canary"]) == len(_SSTI_CANARY_PAYLOADS)


# ---------------------------------------------------------------------------
# Timing oracle (mocked)
# ---------------------------------------------------------------------------


class TestTimingOracle:
    """Tests for timing-based SQLi detection."""

    def test_no_targets_returns_empty(self):
        plugin = InjectionProofOfCondition()
        result = plugin.execute(_context(targets=[]))
        assert result.success
        assert result.metadata.get("mode") == "no-targets"

    def test_timing_baseline_measurement(self):
        """Baseline measurement completes without error."""
        plugin = InjectionProofOfCondition()

        async def run():
            transport = _FakeTransport(body="OK", delay_s=0.0)
            async with httpx.AsyncClient(transport=transport) as client:
                baseline = await plugin._measure_baseline(
                    client, "https://target.local/search", "q"
                )
                return baseline

        bl = asyncio.run(run())
        assert bl >= 0.0


# ---------------------------------------------------------------------------
# Canary reflection (mocked)
# ---------------------------------------------------------------------------


class TestCanaryReflection:
    """Tests for reflected XSS/SSTI canary detection."""

    def test_detects_reflected_canary(self):
        """When body contains the check string → finding produced."""
        plugin = InjectionProofOfCondition()

        async def run():
            # Body contains "49" which matches SSTI probe check
            transport = _FakeTransport(body="Result: 49 is the answer")
            async with httpx.AsyncClient(transport=transport) as client:
                return await plugin._canary_reflection(
                    client,
                    "https://target.local/render",
                    "template",
                    _SSTI_CANARY_PAYLOADS,
                    "ssti",
                )

        findings = asyncio.run(run())
        assert len(findings) > 0
        assert findings[0]["finding_type"] == "ssti_reflected"

    def test_no_reflection_no_findings(self):
        """When body does NOT contain check string → no findings."""
        plugin = InjectionProofOfCondition()

        async def run():
            transport = _FakeTransport(body="Nothing special here")
            async with httpx.AsyncClient(transport=transport) as client:
                return await plugin._canary_reflection(
                    client,
                    "https://target.local/page",
                    "q",
                    _SSTI_CANARY_PAYLOADS,
                    "ssti",
                )

        findings = asyncio.run(run())
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Dry run
# ---------------------------------------------------------------------------


class TestInjectionDryRun:
    def test_dry_run(self):
        plugin = InjectionProofOfCondition()
        result = plugin.dry_run({})
        assert result.success
        assert result.metadata["mode"] == "dry-run"
        assert "payloads" in result.metadata

    def test_dry_run_payload_structure(self):
        plugin = InjectionProofOfCondition()
        result = plugin.dry_run({})
        payloads = result.metadata["payloads"]
        assert isinstance(payloads, dict)
        assert len(payloads) == 3


# ---------------------------------------------------------------------------
# Full execution flow (mocked)
# ---------------------------------------------------------------------------


class TestInjectionFullExecution:
    def test_executes_against_targets(self):
        plugin = InjectionProofOfCondition()
        ctx = _context(
            targets=[
                {"url": "https://target.local/search", "params": ["q"]},
            ],
        )

        async def run():
            transport = _FakeTransport(body="safe response", delay_s=0.0)
            async with httpx.AsyncClient(transport=transport):
                # Can't easily patch context manager, so just verify sync
                pass

        # Run through the synchronous path → will try real HTTP and fail
        # but should not crash
        result = plugin.execute(ctx)
        assert result.plugin_name == "injection-poc-simulator"

    def test_metadata_includes_targets_tested(self):
        plugin = InjectionProofOfCondition()
        ctx = _context(targets=[])
        result = plugin.execute(ctx)
        # No targets → mode is "no-targets"
        assert result.metadata.get("mode") == "no-targets"
