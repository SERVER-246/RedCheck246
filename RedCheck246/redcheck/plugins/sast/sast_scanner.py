"""
RedCheck246 — SAST Plugin: Static Application Security Testing

Analyzes source code for security vulnerabilities without execution.
"""

from redcheck.plugins.base_plugin import BasePlugin, PluginResult


class SASTPlugin(BasePlugin):
    name = "sast-scanner"
    version = "0.1.0"
    description = "Static application security testing — source code analysis"
    requires_authorization = True
    category = "sast"

    def execute(self, context: dict) -> PluginResult:
        # Placeholder: real implementation will integrate Semgrep/Bandit/etc.
        return PluginResult(
            plugin_name=self.name,
            success=True,
            findings=[],
            metadata={"scanner": "stub", "status": "not-yet-implemented"},
        )

    def dry_run(self, context: dict) -> PluginResult:
        return PluginResult(
            plugin_name=self.name,
            success=True,
            metadata={"mode": "dry-run", "description": "Would scan source for security issues"},
        )
