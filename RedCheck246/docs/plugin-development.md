# Plugin Development Guide — RedCheck246

This guide explains how to create custom plugins for RedCheck246.

## Plugin Architecture

Every plugin inherits from `BasePlugin` and auto-registers with the `PluginRegistry` when its class is defined. Plugins are categorized by risk level using `PluginCapability`.

## Quick Start

```python
from redcheck.plugins.base_plugin import BasePlugin, PluginResult
from redcheck.models import PluginCapability


class MyPlugin(BasePlugin):
    name = "my-custom-plugin"
    version = "1.0.0"
    description = "A custom security scanner"
    category = "custom"
    capability = PluginCapability.PASSIVE  # or ACTIVE, DESTRUCTIVE
    requires_authorization = True

    def execute(self, context: dict) -> PluginResult:
        """Main execution logic."""
        targets = context.get("authorized_targets", [])
        findings = []

        for target in targets:
            host = target.get("host", "") if isinstance(target, dict) else target
            # ... your scanning logic here ...
            findings.append({
                "type": "my_finding_type",
                "target": host,
                "detail": "Description of what was found",
                "data": {"severity": "MEDIUM"},
            })

        return PluginResult(
            plugin_name=self.name,
            success=True,
            findings=findings,
        )
```

That's it. The plugin is automatically registered and available via `redcheck list-plugins`.

## Plugin Anatomy

### Required Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `name` | `str` | Unique identifier (kebab-case) |
| `version` | `str` | Semver version string |
| `execute(context)` | method | Main execution logic |

### Optional Attributes

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `description` | `str` | `""` | Human-readable description |
| `category` | `str` | `"general"` | Category (recon, sast, dast, fuzzing, supply_chain) |
| `capability` | `PluginCapability` | `PASSIVE` | Risk classification |
| `requires_authorization` | `bool` | `True` | Whether RoE + activation is needed |

### Capability Levels

| Level | Description | Authorization |
|-------|-------------|---------------|
| `PASSIVE` | Read-only, no target interaction | Optional |
| `ACTIVE` | Sends requests to targets | Required |
| `DESTRUCTIVE` | May modify target state | Required + extra validation |

## Lifecycle Hooks

Plugins can override lifecycle methods:

```python
class MyPlugin(BasePlugin):
    name = "lifecycle-example"
    version = "1.0.0"

    def setup(self) -> None:
        """Called once before first execute(). Acquire resources."""
        self.client = httpx.AsyncClient(timeout=10.0)

    def teardown(self) -> None:
        """Called once after last execute(). Release resources."""
        asyncio.run(self.client.aclose())

    def health_check(self) -> tuple[bool, str]:
        """Liveness probe. Return (healthy, message)."""
        return True, "Ready"

    def validate_context(self, context: dict) -> tuple[bool, str]:
        """Validate that context has everything this plugin needs."""
        if not context.get("authorized_targets"):
            return False, "No targets provided"
        return True, "Context valid"

    def dry_run(self, context: dict) -> PluginResult:
        """Simulate execution without touching targets."""
        targets = context.get("authorized_targets", [])
        return PluginResult(
            plugin_name=self.name,
            success=True,
            metadata={
                "mode": "dry-run",
                "targets_count": len(targets),
            },
        )

    def execute(self, context: dict) -> PluginResult:
        """Full execution."""
        # ...
```

## Async Plugins

For network-intensive plugins, use async execution with `httpx.AsyncClient`:

```python
import asyncio
import httpx
from redcheck.plugins.base_plugin import BasePlugin, PluginResult


class AsyncPlugin(BasePlugin):
    name = "async-scanner"
    version = "1.0.0"
    capability = PluginCapability.ACTIVE
    requires_authorization = True

    def execute(self, context: dict) -> PluginResult:
        """Sync wrapper around async logic."""
        return asyncio.run(self._async_execute(context))

    async def _async_execute(self, context: dict) -> PluginResult:
        targets = context.get("authorized_targets", [])
        findings = []

        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            for target in targets:
                host = target.get("host", "") if isinstance(target, dict) else target
                try:
                    resp = await client.get(f"https://{host}/")
                    # Analyze response...
                    if "X-Powered-By" in resp.headers:
                        findings.append({
                            "type": "info_disclosure",
                            "target": host,
                            "detail": f"X-Powered-By: {resp.headers['X-Powered-By']}",
                            "data": {"severity": "LOW"},
                        })
                except httpx.RequestError:
                    pass

        return PluginResult(
            plugin_name=self.name,
            success=True,
            findings=findings,
        )
```

## Entry Point Discovery

Plugins can also be distributed as installable packages and discovered via entry points:

```toml
# In your plugin's pyproject.toml
[project.entry-points."redcheck.plugins"]
my-plugin = "my_package.plugin:MyPlugin"
```

The `PluginRegistry.discover_entry_points()` method scans the `redcheck.plugins` group.

## Context Object

The `context` dict passed to `execute()` contains:

```python
{
    "engagement_id": "ENG-001",
    "authorizer": "Admin Name",
    "authorized_targets": [
        {"host": "target.com", "ports": [80, 443], "protocols": ["tcp"]},
    ],
    "allowed_tests": ["passive-recon", "my-plugin"],
    "start_time_utc": "2025-01-01T00:00:00Z",
    "end_time_utc": "2025-12-31T23:59:59Z",
    "roe_path": "/path/to/roe.yaml",
    "roe_validated": True,
    "activation_verified": True,
    "safety_mode": "authorized-active",
    "sensitivity": "high",
}
```

## PluginResult

Every plugin must return a `PluginResult`:

```python
@dataclass
class PluginResult:
    plugin_name: str          # Your plugin name
    success: bool             # Did the scan complete?
    findings: list[dict]      # Security findings
    evidence: list[dict]      # Evidence artifacts
    errors: list[str]         # Error messages
    metadata: dict            # Arbitrary metadata
```

### Finding Format

```python
{
    "type": "sqli_detected",           # Finding type identifier
    "target": "https://target.com",    # Affected target
    "detail": "SQL injection in login", # Human-readable description
    "data": {
        "severity": "CRITICAL",        # CRITICAL, HIGH, MEDIUM, LOW, INFO
        "parameter": "username",
        "payload": "' OR 1=1--",
        "evidence": "SQL syntax error in response",
    },
}
```

## Testing Your Plugin

```python
import pytest
from redcheck.plugins.base_plugin import PluginRegistry


def test_plugin_registered():
    from my_package.plugin import MyPlugin  # noqa: F401
    assert PluginRegistry.get("my-custom-plugin") is not None


def test_dry_run():
    plugin = PluginRegistry.get_instance("my-custom-plugin")
    result = plugin.dry_run({"authorized_targets": [{"host": "test.local"}]})
    assert result.success is True
    assert result.metadata["mode"] == "dry-run"


def test_execute():
    plugin = PluginRegistry.get_instance("my-custom-plugin")
    result = plugin.execute({"authorized_targets": [{"host": "test.local"}]})
    assert result.plugin_name == "my-custom-plugin"
```

## Built-in Plugins Reference

| Plugin | Module | Tests |
|--------|--------|-------|
| `passive-recon` | `redcheck.plugins.recon.passive_recon` | 8 |
| `sast-scanner` | `redcheck.plugins.sast.sast_scanner` | 8 |
| `dast-scanner` | `redcheck.plugins.dast.dast_scanner` | 10 |
| `protocol-fuzzer` | `redcheck.plugins.fuzzing.protocol_fuzzer` | 8 |
| `supply-chain-audit` | `redcheck.plugins.supply_chain.supply_chain_audit` | 11 |
