"""Tests for redcheck.core.pipeline — cover extractors and PipelineExecutor."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from redcheck.core.pipeline import (
    PipelineExecutor,
    _extract_credentials,
    _extract_endpoints,
    _extract_packages,
    _extract_services,
)
from redcheck.exceptions import ChainModeError
from redcheck.models import Finding, FindingSeverity, OffensiveControls, PluginResult


def _finding(finding_type="test", detail="", metadata=None, **kw):
    return Finding(
        finding_type=finding_type,
        target=kw.get("target", "t"),
        severity=kw.get("severity", FindingSeverity.INFO),
        detail=detail,
        metadata=metadata or {},
    )


def _result(findings=None, plugin_name="p"):
    return PluginResult(
        plugin_name=plugin_name,
        success=True,
        findings=findings or [],
    )


class TestExtractServices:
    def test_open_port_finding(self):
        f = _finding(
            finding_type="open_port",
            metadata={
                "service_name": "ssh",
                "service_version": "OpenSSH 8.9",
                "port": 22,
            },
        )
        services = _extract_services({"net": _result([f])})
        assert len(services) == 1
        assert services[0]["service"] == "ssh"
        assert services[0]["port"] == "22"

    def test_service_keyword_in_type(self):
        f = _finding(finding_type="discovered_service", detail="HTTP on port 80")
        services = _extract_services({"r": _result([f])})
        assert len(services) == 1

    def test_service_keyword_in_detail(self):
        f = _finding(finding_type="other", detail="found a service running")
        services = _extract_services({"r": _result([f])})
        assert len(services) == 1

    def test_no_services(self):
        f = _finding(finding_type="xss", detail="cross-site scripting")
        assert _extract_services({"r": _result([f])}) == []

    def test_open_port_without_service_name(self):
        f = _finding(finding_type="open_port", metadata={"port": 8080})
        services = _extract_services({"r": _result([f])})
        assert services == []


class TestExtractCredentials:
    def test_hardcoded_secret(self):
        f = _finding(
            finding_type="hardcoded_secret",
            metadata={"secret_value": "s3cret"},
        )
        creds = _extract_credentials({"r": _result([f])})
        assert "s3cret" in creds["passwords"]

    def test_hardcoded_hash(self):
        f = _finding(
            finding_type="hardcoded_hash",
            metadata={"hash_value": "abc123"},
        )
        creds = _extract_credentials({"r": _result([f])})
        assert "abc123" in creds["hashes"]

    def test_password_in_type(self):
        f = _finding(
            finding_type="leaked_password",
            metadata={"value": "pw123"},
        )
        creds = _extract_credentials({"r": _result([f])})
        assert "pw123" in creds["passwords"]

    def test_hash_in_detail(self):
        f = _finding(
            finding_type="other",
            detail="found hash in config",
            metadata={"value": "hashval"},
        )
        creds = _extract_credentials({"r": _result([f])})
        assert "hashval" in creds["hashes"]

    def test_no_credentials(self):
        f = _finding(finding_type="xss")
        creds = _extract_credentials({"r": _result([f])})
        assert creds == {"passwords": [], "hashes": []}

    def test_hardcoded_password(self):
        f = _finding(
            finding_type="hardcoded_password",
            metadata={"password": "hunter2"},
        )
        creds = _extract_credentials({"r": _result([f])})
        assert "hunter2" in creds["passwords"]


class TestExtractEndpoints:
    def test_url_from_metadata(self):
        f = _finding(metadata={"url": "https://example.com/api"})
        eps = _extract_endpoints({"r": _result([f])})
        assert "https://example.com/api" in eps

    def test_endpoint_from_metadata(self):
        f = _finding(metadata={"endpoint": "/api/v1"})
        eps = _extract_endpoints({"r": _result([f])})
        assert "/api/v1" in eps

    def test_no_duplicates(self):
        f1 = _finding(metadata={"url": "https://example.com"})
        f2 = _finding(metadata={"url": "https://example.com"})
        eps = _extract_endpoints({"r": _result([f1, f2])})
        assert len(eps) == 1


class TestExtractPackages:
    def test_package_name(self):
        f = _finding(metadata={"package": "requests"})
        pkgs = _extract_packages({"r": _result([f])})
        assert "requests" in pkgs

    def test_package_name_key(self):
        f = _finding(metadata={"package_name": "flask"})
        pkgs = _extract_packages({"r": _result([f])})
        assert "flask" in pkgs

    def test_no_duplicates(self):
        f1 = _finding(metadata={"package": "pip"})
        f2 = _finding(metadata={"package": "pip"})
        pkgs = _extract_packages({"r": _result([f1, f2])})
        assert len(pkgs) == 1


class TestPipelineExecutor:
    @pytest.fixture
    def mock_orch(self):
        orch = AsyncMock()
        return orch

    @pytest.fixture
    def executor(self, mock_orch):
        return PipelineExecutor(mock_orch)

    @pytest.fixture
    def engagement(self):
        eng = MagicMock()
        eng.engagement_id = "eng-001"
        eng.offensive_controls = OffensiveControls()
        eng.targets = ["example.com"]
        return eng

    @pytest.mark.asyncio
    async def test_empty_plugin_order(self, executor, engagement):
        result = await executor.execute_pipeline(engagement, [])
        assert result == {}

    @pytest.mark.asyncio
    async def test_single_plugin(self, executor, engagement, mock_orch):
        pr = PluginResult(plugin_name="recon", success=True, findings=[])
        mock_orch.arun_plugin = AsyncMock(return_value=pr)

        result = await executor.execute_pipeline(engagement, ["recon"])
        assert "recon" in result
        assert result["recon"].success is True

    @pytest.mark.asyncio
    async def test_chain_mode_without_control_raises(self, executor, engagement):
        with pytest.raises(ChainModeError):
            await executor.execute_pipeline(engagement, ["p1"], chain=True)

    @pytest.mark.asyncio
    async def test_chain_mode_with_control(self, executor, engagement, mock_orch):
        engagement.offensive_controls = OffensiveControls(chain_mode=True)
        pr1 = PluginResult(
            plugin_name="recon",
            success=True,
            findings=[
                _finding(
                    finding_type="open_port",
                    metadata={"service_name": "http", "service_version": "1.1", "port": 80},
                )
            ],
        )
        pr2 = PluginResult(plugin_name="dast", success=True, findings=[])
        mock_orch.arun_plugin = AsyncMock(side_effect=[pr1, pr2])

        result = await executor.execute_pipeline(engagement, ["recon", "dast"], chain=True)
        assert len(result) == 2
        # Second plugin should have received extra_context with upstream data
        call_args = mock_orch.arun_plugin.call_args_list[1]
        extra = call_args.kwargs.get("extra_context") or {}
        assert "upstream_findings" in extra
        assert "discovered_services" in extra

    @pytest.mark.asyncio
    async def test_plugin_failure_isolated(self, executor, engagement, mock_orch):
        mock_orch.arun_plugin = AsyncMock(side_effect=RuntimeError("boom"))

        result = await executor.execute_pipeline(engagement, ["broken"])
        assert "broken" in result
        assert result["broken"].success is False
        assert "Execution failed" in result["broken"].errors[0]

    @pytest.mark.asyncio
    async def test_results_property(self, executor, engagement, mock_orch):
        pr = PluginResult(plugin_name="p", success=True)
        mock_orch.arun_plugin = AsyncMock(return_value=pr)
        await executor.execute_pipeline(engagement, ["p"])
        results = executor.results
        assert "p" in results

    @pytest.mark.asyncio
    async def test_chain_with_credentials_and_endpoints(self, executor, engagement, mock_orch):
        engagement.offensive_controls = OffensiveControls(chain_mode=True)
        pr1 = PluginResult(
            plugin_name="sast",
            success=True,
            findings=[
                _finding(
                    finding_type="hardcoded_secret",
                    metadata={"secret_value": "key123"},
                ),
                _finding(metadata={"url": "https://target.com/admin"}),
                _finding(metadata={"package": "vuln-pkg"}),
            ],
        )
        pr2 = PluginResult(plugin_name="dast", success=True)
        mock_orch.arun_plugin = AsyncMock(side_effect=[pr1, pr2])

        await executor.execute_pipeline(engagement, ["sast", "dast"], chain=True)
        call_args = mock_orch.arun_plugin.call_args_list[1]
        extra = call_args.kwargs.get("extra_context") or {}
        assert "breach_passwords" in extra
        assert "idor_endpoints" in extra
        assert "typosquat_domains" in extra
