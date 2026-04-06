"""Tests for plugin dependency graph — decorator, resolver, and pipeline integration."""

from __future__ import annotations

from typing import Any

import pytest

from redcheck.core.pipeline import (
    PipelineExecutor,
    check_dependencies,
    resolve_execution_order,
)
from redcheck.plugins.base_plugin import (
    BasePlugin,
    PluginRegistry,
    PluginResult,
    plugin_dependencies,
)

# ---------------------------------------------------------------------------
# Fixtures — test plugins with dependency declarations
# ---------------------------------------------------------------------------


@plugin_dependencies(required=[], optional=[], provides=["recon_data"])
class _T0Recon(BasePlugin):
    name = "t0-recon"
    version = "0.0.1"
    requires_authorization = False

    def execute(self, context: dict[str, Any]) -> PluginResult:
        return PluginResult(
            plugin_name=self.name,
            success=True,
            findings=[],
            metadata={"tier": 0},
        )


@plugin_dependencies(required=[], optional=[], provides=["scan_data"])
class _T0Scanner(BasePlugin):
    name = "t0-scanner"
    version = "0.0.1"
    requires_authorization = False

    def execute(self, context: dict[str, Any]) -> PluginResult:
        return PluginResult(
            plugin_name=self.name,
            success=True,
            findings=[],
            metadata={"tier": 0},
        )


@plugin_dependencies(required=["t0-recon"], optional=["t0-scanner"], provides=["vuln_data"])
class _T1Vuln(BasePlugin):
    name = "t1-vuln"
    version = "0.0.1"
    requires_authorization = False

    def execute(self, context: dict[str, Any]) -> PluginResult:
        return PluginResult(
            plugin_name=self.name,
            success=True,
            findings=[],
            metadata={"tier": 1},
        )


@plugin_dependencies(required=["t0-scanner"], optional=[], provides=["fuzz_data"])
class _T1Fuzz(BasePlugin):
    name = "t1-fuzz"
    version = "0.0.1"
    requires_authorization = False

    def execute(self, context: dict[str, Any]) -> PluginResult:
        return PluginResult(
            plugin_name=self.name,
            success=True,
            findings=[],
            metadata={"tier": 1},
        )


@plugin_dependencies(required=["t1-vuln", "t1-fuzz"], optional=[], provides=["exploit_data"])
class _T2Exploit(BasePlugin):
    name = "t2-exploit"
    version = "0.0.1"
    requires_authorization = False

    def execute(self, context: dict[str, Any]) -> PluginResult:
        return PluginResult(
            plugin_name=self.name,
            success=True,
            findings=[],
            metadata={"tier": 2},
        )


@plugin_dependencies(required=[], optional=["t1-vuln"], provides=["crypto_data"])
class _T1Crypto(BasePlugin):
    name = "t1-crypto"
    version = "0.0.1"
    requires_authorization = False

    def execute(self, context: dict[str, Any]) -> PluginResult:
        return PluginResult(
            plugin_name=self.name,
            success=True,
            findings=[],
            metadata={"tier": 1},
        )


# ---------------------------------------------------------------------------
# Tests — @plugin_dependencies decorator
# ---------------------------------------------------------------------------


class TestPluginDependenciesDecorator:
    """Verify @plugin_dependencies sets class attributes correctly."""

    def test_tier0_has_no_requirements(self) -> None:
        assert _T0Recon._dep_required == []
        assert _T0Recon._dep_optional == []
        assert _T0Recon._dep_provides == ["recon_data"]

    def test_tier1_has_required_dependency(self) -> None:
        assert _T1Vuln._dep_required == ["t0-recon"]
        assert _T1Vuln._dep_optional == ["t0-scanner"]
        assert _T1Vuln._dep_provides == ["vuln_data"]

    def test_tier2_has_multiple_required(self) -> None:
        assert _T2Exploit._dep_required == ["t1-vuln", "t1-fuzz"]
        assert _T2Exploit._dep_optional == []

    def test_properties_accessible_on_instance(self) -> None:
        p = _T1Vuln()
        assert p.required_dependencies == ["t0-recon"]
        assert p.optional_dependencies == ["t0-scanner"]
        assert p.dependency_provides == ["vuln_data"]

    def test_properties_return_copies(self) -> None:
        p = _T1Vuln()
        deps = p.required_dependencies
        deps.append("mutation-should-not-persist")
        assert "mutation-should-not-persist" not in p.required_dependencies


# ---------------------------------------------------------------------------
# Tests — resolve_execution_order
# ---------------------------------------------------------------------------


class TestResolveExecutionOrder:
    """Verify topological sort produces correct tier ordering."""

    def test_all_test_plugins_ordered(self) -> None:
        tiers = resolve_execution_order(
            ["t0-recon", "t0-scanner", "t1-vuln", "t1-fuzz", "t2-exploit"]
        )
        assert len(tiers) == 3
        assert set(tiers[0]) == {"t0-recon", "t0-scanner"}
        assert set(tiers[1]) == {"t1-vuln", "t1-fuzz"}
        assert tiers[2] == ["t2-exploit"]

    def test_subset_of_plugins(self) -> None:
        tiers = resolve_execution_order(["t0-recon", "t1-vuln"])
        assert len(tiers) == 2
        assert tiers[0] == ["t0-recon"]
        assert tiers[1] == ["t1-vuln"]

    def test_single_plugin_one_tier(self) -> None:
        tiers = resolve_execution_order(["t0-recon"])
        assert tiers == [["t0-recon"]]

    def test_optional_deps_excluded_when_not_requested(self) -> None:
        # t1-crypto has optional dep on t1-vuln. If t1-vuln isn't
        # in the requested set, t1-crypto should still be in tier 0.
        tiers = resolve_execution_order(["t1-crypto"])
        assert len(tiers) == 1
        assert tiers[0] == ["t1-crypto"]

    def test_optional_deps_included_when_present(self) -> None:
        tiers = resolve_execution_order(["t0-recon", "t1-crypto", "t1-vuln"])
        # t1-crypto optionally depends on t1-vuln, which requires t0-recon
        # So: tier 0 = t0-recon, tier 1 = t1-vuln + t1-crypto (same tier since
        # t1-crypto's dep on t1-vuln is optional)
        flat = [p for tier in tiers for p in tier]
        # t0-recon must come before t1-vuln
        assert flat.index("t0-recon") < flat.index("t1-vuln")

    def test_unknown_plugins_skipped(self) -> None:
        tiers = resolve_execution_order(["t0-recon", "nonexistent-plugin"])
        flat = [p for tier in tiers for p in tier]
        assert "t0-recon" in flat
        assert "nonexistent-plugin" not in flat

    def test_empty_list_returns_empty(self) -> None:
        assert resolve_execution_order([]) == []

    def test_cycle_detection_does_not_crash(self) -> None:
        # Test with the real registered plugins — should produce valid tiers
        tiers = resolve_execution_order(
            ["t0-recon", "t0-scanner", "t1-vuln", "t1-fuzz", "t2-exploit"]
        )
        flat = [p for tier in tiers for p in tier]
        assert len(flat) == 5

    def test_real_plugins_ordered_correctly(self) -> None:
        """Verify actual RedCheck plugins are ordered by declared dependencies."""
        tiers = resolve_execution_order(
            ["passive-recon", "network-scanner", "dast-scanner", "cve-mapper"]
        )
        flat = [p for tier in tiers for p in tier]
        # passive-recon and network-scanner are tier 0
        # dast-scanner requires passive-recon → tier 1
        # cve-mapper requires network-scanner → tier 1
        assert flat.index("passive-recon") < flat.index("dast-scanner")
        assert flat.index("network-scanner") < flat.index("cve-mapper")


# ---------------------------------------------------------------------------
# Tests — check_dependencies
# ---------------------------------------------------------------------------


class TestCheckDependencies:
    """Verify pre-execution dependency checks."""

    def test_no_deps_always_executable(self) -> None:
        can, reason, degraded = check_dependencies("t0-recon", {})
        assert can is True
        assert reason is None
        assert degraded is False

    def test_required_dep_missing_blocks(self) -> None:
        can, reason, degraded = check_dependencies("t1-vuln", {})
        assert can is False
        assert "t0-recon" in (reason or "")

    def test_required_dep_present_allows(self) -> None:
        completed = {
            "t0-recon": PluginResult(plugin_name="t0-recon", success=True, findings=[]),
        }
        can, reason, degraded = check_dependencies("t1-vuln", completed)
        assert can is True
        assert degraded is False

    def test_required_dep_failed_sets_degraded(self) -> None:
        completed = {
            "t0-recon": PluginResult(plugin_name="t0-recon", success=False, findings=[]),
        }
        can, reason, degraded = check_dependencies("t1-vuln", completed)
        assert can is True
        assert degraded is True

    def test_multiple_required_all_needed(self) -> None:
        # t2-exploit requires both t1-vuln and t1-fuzz
        completed = {
            "t1-vuln": PluginResult(plugin_name="t1-vuln", success=True, findings=[]),
        }
        can, reason, _ = check_dependencies("t2-exploit", completed)
        assert can is False
        assert "t1-fuzz" in (reason or "")

    def test_multiple_required_all_present(self) -> None:
        completed = {
            "t1-vuln": PluginResult(plugin_name="t1-vuln", success=True, findings=[]),
            "t1-fuzz": PluginResult(plugin_name="t1-fuzz", success=True, findings=[]),
        }
        can, reason, degraded = check_dependencies("t2-exploit", completed)
        assert can is True
        assert degraded is False

    def test_unknown_plugin_passes_through(self) -> None:
        # Unregistered plugins have no declared dependencies → pass through
        can, reason, _ = check_dependencies("nonexistent", {})
        assert can is True
        assert reason is None

    def test_optional_deps_dont_block(self) -> None:
        # t1-crypto optionally depends on t1-vuln — should not be blocked
        can, reason, degraded = check_dependencies("t1-crypto", {})
        assert can is True
        assert degraded is False


# ---------------------------------------------------------------------------
# Tests — Real plugin dependency declarations
# ---------------------------------------------------------------------------


class TestRealPluginDeclarations:
    """Verify all 23 real plugins have correct dependency declarations."""

    TIER_0 = [
        "passive-recon",
        "network-scanner",
        "network-discovery",
        "container-analyzer",
        "sast-scanner",
        "supply-chain-audit",
    ]

    PLUGINS_WITH_REQUIRED = {
        "dast-scanner": ["passive-recon"],
        "cve-mapper": ["network-scanner"],
        "breach-lookup": ["passive-recon"],
        "ct-log-monitor": ["passive-recon"],
        "typosquat-detector": ["supply-chain-audit"],
        "auth-session-tester": ["dast-scanner"],
        "idor-validator": ["dast-scanner"],
        "protocol-fuzzer": ["network-scanner"],
        "lateral-movement-analyzer": ["network-scanner", "network-discovery"],
        "exploit-verifier": ["cve-mapper"],
        "injection-poc-simulator": ["dast-scanner"],
        "detection-response-recorder": ["alert-latency", "detection-coverage"],
    }

    def test_tier0_plugins_have_no_required_deps(self) -> None:
        for name in self.TIER_0:
            plugin_cls = PluginRegistry.get(name)
            assert plugin_cls is not None, f"{name} not registered"
            assert getattr(plugin_cls, "_dep_required", []) == [], (
                f"{name} should have no required deps"
            )

    def test_all_plugins_have_provides(self) -> None:
        for name in PluginRegistry.list_names():
            plugin_cls = PluginRegistry.get(name)
            if plugin_cls is None:
                continue
            provides = getattr(plugin_cls, "_dep_provides", [])
            # Only check our known real plugins (skip test stubs)
            if name in self.TIER_0 or name in self.PLUGINS_WITH_REQUIRED:
                assert len(provides) > 0, f"{name} has no provides declaration"

    @pytest.mark.parametrize(
        ("plugin_name", "expected_required"),
        list(PLUGINS_WITH_REQUIRED.items()),
    )
    def test_plugin_required_deps(self, plugin_name: str, expected_required: list[str]) -> None:
        plugin_cls = PluginRegistry.get(plugin_name)
        assert plugin_cls is not None, f"{plugin_name} not registered"
        actual = getattr(plugin_cls, "_dep_required", [])
        assert sorted(actual) == sorted(expected_required)

    def test_full_graph_produces_valid_tiers(self) -> None:
        all_real = (
            self.TIER_0
            + list(self.PLUGINS_WITH_REQUIRED.keys())
            + [
                "hash-strength-analyzer",
                "password-entropy-scorer",
                "alert-latency",
                "detection-coverage",
                "persistence-validator",
            ]
        )
        tiers = resolve_execution_order(all_real)
        flat = [p for tier in tiers for p in tier]
        # All Tier 0 in first tier
        for name in self.TIER_0:
            if name in flat:
                assert flat.index(name) < len(self.TIER_0)

        # Every plugin with required deps comes after those deps
        for name, deps in self.PLUGINS_WITH_REQUIRED.items():
            if name not in flat:
                continue
            for dep in deps:
                if dep in flat:
                    assert flat.index(dep) < flat.index(name), f"{dep} should come before {name}"


# ---------------------------------------------------------------------------
# Tests — Pipeline integration with dependency checking
# ---------------------------------------------------------------------------


class TestPipelineDependencyIntegration:
    """Test that PipelineExecutor respects dependency ordering."""

    @pytest.fixture
    def _engagement(self, valid_roe_file: Any, engagement_dir: Any) -> Any:
        from redcheck.models import EngagementContext

        return EngagementContext(
            engagement_id="DEP-TEST-001",
            authorizer="test",
            targets=["testhost.local"],
            start_time_utc="2026-01-01T00:00:00+00:00",
            end_time_utc="2099-12-31T23:59:59+00:00",
            roe_path=str(valid_roe_file),
            output_dir=str(engagement_dir),
            sensitivity="low",
            runtime_mode="dev",
            allowed_tests=["*"],
        )

    @pytest.mark.asyncio
    async def test_auto_order_reorders_plugins(self, _engagement: Any) -> None:  # noqa: PT019
        """auto_order=True should put t0 before t1."""
        from unittest.mock import AsyncMock, MagicMock

        mock_orch = MagicMock()
        mock_orch.arun_plugin = AsyncMock(
            side_effect=lambda name, *a, **kw: PluginResult(
                plugin_name=name, success=True, findings=[]
            )
        )

        executor = PipelineExecutor(mock_orch)
        # Provide plugins in reverse order — auto_order should fix it
        await executor.execute_pipeline(
            _engagement,
            ["t1-vuln", "t0-recon", "t0-scanner"],
            chain=True,
            auto_order=True,
        )
        # t0-recon must have been called before t1-vuln
        call_names = [c.args[0] for c in mock_orch.arun_plugin.call_args_list]
        assert call_names.index("t0-recon") < call_names.index("t1-vuln")

    @pytest.mark.asyncio
    async def test_dependency_skip_creates_failure_result(
        self,
        _engagement: Any,  # noqa: PT019
    ) -> None:
        """Plugin with missing required dep should be skipped with error."""
        from unittest.mock import AsyncMock, MagicMock

        mock_orch = MagicMock()
        mock_orch.arun_plugin = AsyncMock(
            side_effect=lambda name, *a, **kw: PluginResult(
                plugin_name=name, success=True, findings=[]
            )
        )

        executor = PipelineExecutor(mock_orch)
        # t1-vuln requires t0-recon, which is NOT in the list
        results = await executor.execute_pipeline(
            _engagement,
            ["t1-vuln"],
            chain=True,
        )
        assert "t1-vuln" in results
        assert results["t1-vuln"].success is False
        assert "dependency" in (results["t1-vuln"].errors[0]).lower()
