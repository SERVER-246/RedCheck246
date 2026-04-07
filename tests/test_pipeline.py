"""Tests for the Pipeline Executor (redcheck.core.pipeline)."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from redcheck.core.orchestrator import Orchestrator
from redcheck.core.pipeline import (
    DEFAULT_CHAIN_ORDER,
    PipelineExecutor,
    _extract_services,
)
from redcheck.exceptions import ChainModeError
from redcheck.models import (
    EngagementContext,
    Finding,
    FindingSeverity,
    OffensiveControls,
    PluginResult,
    RuntimeMode,
)


def _make_engagement(*, chain_mode: bool = True) -> EngagementContext:
    """Create a minimal valid EngagementContext for pipeline tests."""
    return EngagementContext(
        engagement_id="pipe-eng-1",
        authorizer="Test Authorizer",
        targets=["192.168.1.0/24"],
        allowed_tests=["passive_recon"],
        start_time_utc=datetime.now(timezone.utc) - timedelta(hours=1),
        end_time_utc=datetime.now(timezone.utc) + timedelta(hours=1),
        roe_signed=True,
        activation_verified=True,
        session_code="PIPE-SESSION",
        runtime_mode=RuntimeMode.TEST,
        offensive_controls=OffensiveControls(
            allow_auth_testing=True,
            allow_exploit_validation=True,
            chain_mode=chain_mode,
        ),
    )


def _make_result(
    plugin_name: str,
    *,
    success: bool = True,
    findings: list[Finding] | None = None,
) -> PluginResult:
    return PluginResult(
        plugin_name=plugin_name,
        success=success,
        findings=findings or [],
    )


class TestDefaultChainOrder:
    def test_is_non_empty_list(self):
        assert len(DEFAULT_CHAIN_ORDER) > 0
        assert isinstance(DEFAULT_CHAIN_ORDER, list)

    def test_no_duplicate_entries(self):
        assert len(DEFAULT_CHAIN_ORDER) == len(set(DEFAULT_CHAIN_ORDER))

    def test_recon_before_dast(self):
        """Recon plugins should appear before dynamic analysis plugins."""
        recon_idx = DEFAULT_CHAIN_ORDER.index("passive-recon")
        dast_idx = DEFAULT_CHAIN_ORDER.index("dast-scanner")
        assert recon_idx < dast_idx


class TestExtractServices:
    def test_empty_results(self):
        assert _extract_services({}) == []

    def test_extracts_service_detection_findings(self):
        finding = Finding(
            finding_type="service-detection",
            target="192.168.1.1",
            detail="OpenSSH 8.9",
            severity=FindingSeverity.INFO,
        )
        result = _make_result("network-scanner", findings=[finding])
        services = _extract_services({"network-scanner": result})
        assert len(services) == 1
        assert services[0]["finding_type"] == "service-detection"

    def test_extracts_service_title_findings(self):
        finding = Finding(
            finding_type="recon",
            target="192.168.1.1",
            detail="HTTP service detected on port 80",
            severity=FindingSeverity.INFO,
        )
        result = _make_result("passive-recon", findings=[finding])
        services = _extract_services({"passive-recon": result})
        assert len(services) == 1

    def test_ignores_non_service_findings(self):
        finding = Finding(
            finding_type="vulnerability",
            target="192.168.1.1",
            detail="SQL Injection in /login",
            severity=FindingSeverity.HIGH,
        )
        result = _make_result("dast-scanner", findings=[finding])
        services = _extract_services({"dast-scanner": result})
        assert services == []


class TestPipelineExecutor:
    def test_empty_pipeline(self):
        orch = MagicMock(spec=Orchestrator)
        pipe = PipelineExecutor(orch)
        eng = _make_engagement()

        results = asyncio.run(pipe.execute_pipeline(eng, []))
        assert results == {}

    def test_single_plugin(self):
        orch = MagicMock(spec=Orchestrator)
        orch.arun_plugin = AsyncMock(return_value=_make_result("p1"))

        pipe = PipelineExecutor(orch)
        eng = _make_engagement()

        results = asyncio.run(pipe.execute_pipeline(eng, ["p1"]))
        assert "p1" in results
        assert results["p1"].success is True
        orch.arun_plugin.assert_called_once()

    def test_multiple_plugins_ordered(self):
        call_order: list[str] = []

        async def mock_run(name, _eng, *, dry_run=False, extra_context=None):
            call_order.append(name)
            return _make_result(name)

        orch = MagicMock(spec=Orchestrator)
        orch.arun_plugin = mock_run

        pipe = PipelineExecutor(orch)
        eng = _make_engagement()

        results = asyncio.run(pipe.execute_pipeline(eng, ["a", "b", "c"]))
        assert list(results.keys()) == ["a", "b", "c"]
        assert call_order == ["a", "b", "c"]

    def test_chain_mode_requires_offensive_control(self):
        orch = MagicMock(spec=Orchestrator)
        pipe = PipelineExecutor(orch)
        eng = _make_engagement(chain_mode=False)

        with pytest.raises(ChainModeError):
            asyncio.run(pipe.execute_pipeline(eng, ["p1"], chain=True))

    def test_chain_mode_injects_upstream_context(self):
        """When chain=True, extra_context has upstream_findings for 2nd plugin."""
        captured_extra: list[dict | None] = []

        finding = Finding(
            finding_type="service-detection",
            target="192.168.1.1:22",
            detail="Open port 22 - SSH",
            severity=FindingSeverity.INFO,
        )
        result_with_findings = _make_result("fake-recon", findings=[finding])

        async def mock_run(name, _eng, *, dry_run=False, extra_context=None):
            captured_extra.append(extra_context)
            if name == "fake-recon":
                return result_with_findings
            return _make_result(name)

        orch = MagicMock(spec=Orchestrator)
        orch.arun_plugin = mock_run

        pipe = PipelineExecutor(orch)
        eng = _make_engagement(chain_mode=True)

        asyncio.run(pipe.execute_pipeline(eng, ["fake-recon", "fake-dast"], chain=True))

        # First plugin: no upstream context
        assert captured_extra[0] is None
        # Second plugin: has upstream findings
        assert captured_extra[1] is not None
        assert "upstream_findings" in captured_extra[1]
        assert "upstream_plugins" in captured_extra[1]
        assert captured_extra[1]["upstream_plugins"] == ["fake-recon"]
        assert len(captured_extra[1]["upstream_findings"]) == 1
        assert "discovered_services" in captured_extra[1]

    def test_chain_mode_discovered_services(self):
        """Service findings are extracted into discovered_services."""
        captured_extra: list[dict | None] = []

        finding = Finding(
            finding_type="service-detection",
            target="192.168.1.1:80",
            detail="HTTP service on port 80 - Apache",
            severity=FindingSeverity.INFO,
        )
        result_with_service = _make_result("fake-recon", findings=[finding])

        async def mock_run(name, _eng, *, dry_run=False, extra_context=None):
            captured_extra.append(extra_context)
            if name == "fake-recon":
                return result_with_service
            return _make_result(name)

        orch = MagicMock(spec=Orchestrator)
        orch.arun_plugin = mock_run

        pipe = PipelineExecutor(orch)
        eng = _make_engagement(chain_mode=True)

        asyncio.run(pipe.execute_pipeline(eng, ["fake-recon", "fake-cve"], chain=True))
        assert len(captured_extra[1]["discovered_services"]) == 1

    def test_plugin_failure_isolated_not_raised(self):
        orch = MagicMock(spec=Orchestrator)
        orch.arun_plugin = AsyncMock(side_effect=RuntimeError("boom"))

        pipe = PipelineExecutor(orch)
        eng = _make_engagement()

        # P8: errors are isolated — pipeline continues, no exception raised
        asyncio.run(pipe.execute_pipeline(eng, ["bad_plugin"]))
        result = pipe.results["bad_plugin"]
        assert result.success is False
        assert result.metadata.get("isolated") is True

    def test_partial_results_on_failure(self):
        """When 2nd plugin fails, both results are accessible."""
        call_count = 0

        async def mock_run(name, _eng, *, dry_run=False, extra_context=None):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise RuntimeError("second plugin failed")
            return _make_result(name)

        orch = MagicMock(spec=Orchestrator)
        orch.arun_plugin = mock_run

        pipe = PipelineExecutor(orch)
        eng = _make_engagement()

        # P8: pipeline continues past failure
        asyncio.run(pipe.execute_pipeline(eng, ["good", "bad"]))

        assert "good" in pipe.results
        assert pipe.results["good"].success is True
        assert "bad" in pipe.results
        assert pipe.results["bad"].success is False
        assert pipe.results["bad"].metadata.get("isolated") is True

    def test_dry_run_forwarded(self):
        orch = MagicMock(spec=Orchestrator)
        orch.arun_plugin = AsyncMock(return_value=_make_result("p1"))

        pipe = PipelineExecutor(orch)
        eng = _make_engagement()

        asyncio.run(pipe.execute_pipeline(eng, ["p1"], dry_run=True))
        orch.arun_plugin.assert_called_once_with("p1", eng, dry_run=True, extra_context=None)

    def test_results_property_returns_copy(self):
        orch = MagicMock(spec=Orchestrator)
        orch.arun_plugin = AsyncMock(return_value=_make_result("p1"))

        pipe = PipelineExecutor(orch)
        eng = _make_engagement()

        asyncio.run(pipe.execute_pipeline(eng, ["p1"]))
        r1 = pipe.results
        r2 = pipe.results
        assert r1 == r2
        assert r1 is not r2  # Should be a copy

    def test_no_chain_no_extra_context(self):
        """Without chain=True, no extra_context should be injected."""
        captured_extra: list[dict | None] = []

        async def mock_run(name, _eng, *, dry_run=False, extra_context=None):
            captured_extra.append(extra_context)
            return _make_result(name)

        orch = MagicMock(spec=Orchestrator)
        orch.arun_plugin = mock_run

        pipe = PipelineExecutor(orch)
        eng = _make_engagement()

        asyncio.run(pipe.execute_pipeline(eng, ["a", "b"], chain=False))
        assert all(ctx is None for ctx in captured_extra)
