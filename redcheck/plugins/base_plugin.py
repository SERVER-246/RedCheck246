"""RedCheck246 — Base Plugin & Plugin Registry.

All plugins MUST inherit from ``BasePlugin``.
Active plugins MUST pass PolicyEngine.authorize() before execution.
"""

from __future__ import annotations

import difflib
import importlib.metadata
from abc import ABC, abstractmethod
from typing import Any

import structlog

from redcheck.models import PluginCapability, PluginResult

__all__ = [
    "BasePlugin",
    "PluginCapability",
    "PluginRegistry",
    "PluginResult",
    "plugin_dependencies",
]

log = structlog.get_logger(__name__)


# ------------------------------------------------------------------
# Plugin Dependency Decorator
# ------------------------------------------------------------------


def plugin_dependencies(
    *,
    required: list[str] | None = None,
    optional: list[str] | None = None,
    provides: list[str] | None = None,
) -> Any:
    """Declare dependency metadata on a plugin class.

    Args:
        required: Plugin names that MUST have run successfully before this plugin.
        optional: Plugin names whose results will be injected if available.
        provides: Data keys this plugin produces for downstream consumers.
    """

    def decorator(cls: type[BasePlugin]) -> type[BasePlugin]:
        cls._dep_required = list(required or [])
        cls._dep_optional = list(optional or [])
        cls._dep_provides = list(provides or [])
        return cls

    return decorator


# ------------------------------------------------------------------
# Base Plugin
# ------------------------------------------------------------------


class BasePlugin(ABC):
    """Abstract base class for all RedCheck plugins.

    Every plugin must define:
    - ``name``: unique identifier
    - ``version``: semver string
    - ``requires_authorization``: whether RoE + activation is needed
    - ``execute(context)``: the main execution method

    Optional overrides:
    - ``capability``: risk classification (PASSIVE / ACTIVE / DESTRUCTIVE)
    - ``required_controls``: list of ``OffensiveControls`` flags needed
    - ``timeout_seconds``: per-execution timeout (1–600)
    - ``rate_limit_rps``: per-second rate limit (1–50)
    - ``mitre_techniques``: MITRE ATT&CK technique IDs
    - ``requires_isolation``: whether Docker sandbox is needed
    - ``setup()`` / ``teardown()``: lifecycle hooks
    - ``health_check()``: liveness probe
    - ``aexecute(context)``: async execution override
    """

    name: str = "unnamed"
    version: str = "0.0.0"
    description: str = ""
    requires_authorization: bool = True
    category: str = "general"  # recon, sast, dast, fuzzing, supply_chain
    capability: PluginCapability = PluginCapability.PASSIVE

    # Phase 1 extensions
    required_controls: list[str] = []
    timeout_seconds: int = 60
    rate_limit_rps: int = 10
    mitre_techniques: list[str] = []
    requires_isolation: bool = False

    # Dependency metadata (set via @plugin_dependencies decorator)
    _dep_required: list[str] = []
    _dep_optional: list[str] = []
    _dep_provides: list[str] = []

    @property
    def required_dependencies(self) -> list[str]:
        """Plugin names that MUST have run successfully before this plugin."""
        return list(self._dep_required)

    @property
    def optional_dependencies(self) -> list[str]:
        """Plugin names whose results will be injected if available."""
        return list(self._dep_optional)

    @property
    def dependency_provides(self) -> list[str]:
        """Data keys this plugin produces for downstream consumers."""
        return list(self._dep_provides)

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if not getattr(cls, "_abstract", False) and hasattr(cls, "name"):
            PluginRegistry.register(cls)

    # ---- lifecycle hooks ------------------------------------------------

    def setup(self) -> None:  # noqa: B027
        """Called once before the first ``execute()`` in a session.

        Override to acquire resources (HTTP clients, file handles, etc.).
        """

    def teardown(self) -> None:  # noqa: B027
        """Called once after the last ``execute()`` in a session.

        Override to release resources.
        """

    def health_check(self) -> tuple[bool, str]:
        """Return ``(healthy, message)``.  Default always healthy."""
        return True, "ok"

    # ---- execution ------------------------------------------------------

    @abstractmethod
    def execute(self, context: dict[str, Any]) -> PluginResult:
        """Execute the plugin within the given engagement context."""
        ...

    def dry_run(self, context: dict[str, Any]) -> PluginResult:
        """Simulate execution without touching targets."""
        return PluginResult(
            plugin_name=self.name,
            success=True,
            metadata={"mode": "dry-run", "description": f"Dry run of {self.name}"},
        )

    async def aexecute(self, context: dict[str, Any]) -> PluginResult:
        """Async execution entry point.

        Default implementation delegates to the synchronous ``execute()``
        method.  Override this in plugins that need true async I/O.
        """
        return self.execute(context)

    def validate_context(self, context: dict[str, Any]) -> tuple[bool, str]:
        """Validate that the context has everything this plugin needs."""
        if not context:
            return False, "Empty context"
        return True, "Context valid"

    def explain_missing_dependencies(self, context: dict[str, Any]) -> dict[str, Any]:
        """Return structured explanation of what upstream data is missing and why.

        Plugins SHOULD override this to give specific diagnostics when
        upstream data they need is absent.  The default implementation
        checks ``_dep_required`` against ``upstream_plugins`` in context.
        """
        upstream = set(context.get("upstream_plugins") or [])
        missing = [dep for dep in self._dep_required if dep not in upstream]
        return {
            "plugin": self.name,
            "missing_dependencies": missing,
            "explanation": (
                f"Requires data from {missing} but they did not execute"
                if missing
                else "All required dependencies satisfied"
            ),
        }

    def capture_evidence(
        self,
        context: dict[str, Any],
        data: bytes,
        evidence_type: str,
        *,
        finding_ref: str | None = None,
    ) -> Any:
        """Store evidence via the engagement's evidence store.

        Returns the Evidence model instance, or None if no store is available.
        """
        store = context.get("evidence_store")
        if store is None:
            # Check _runtime sub-dict (non-serializable runtime objects)
            runtime = context.get("_runtime", {})
            store = runtime.get("evidence_store")
        if store is None:
            return None
        return store.store(
            data,
            evidence_type,
            finding_ref=finding_ref,
            plugin_name=self.name,
        )

    def __repr__(self) -> str:
        auth = "AUTH-REQUIRED" if self.requires_authorization else "NO-AUTH"
        return f"<Plugin:{self.name} v{self.version} [{auth}] {self.capability.value}>"


# ------------------------------------------------------------------
# Plugin Registry
# ------------------------------------------------------------------


class PluginRegistry:
    """Central registry for all RedCheck plugins.

    Plugins are auto-registered when their class is defined
    (via ``__init_subclass__``).  Entry-point discovery adds plugins
    installed as packages.
    """

    _plugins: dict[str, type[BasePlugin]] = {}
    _plugin_hashes: dict[str, str] = {}

    @classmethod
    def register(cls, plugin_class: type[BasePlugin]) -> None:
        """Register a plugin class and record its source hash."""
        name = getattr(plugin_class, "name", None)
        if name and name != "unnamed":
            cls._plugins[name] = plugin_class
            # Compute SHA-256 of the plugin's source file for integrity (Phase O)
            cls._plugin_hashes[name] = cls._compute_source_hash(plugin_class)
            log.debug("plugin_registered", plugin=name)

    @classmethod
    def _compute_source_hash(cls, plugin_class: type[BasePlugin]) -> str:
        """Return SHA-256 hex digest of the plugin's source file."""
        import hashlib
        import inspect

        try:
            source_file = inspect.getfile(plugin_class)
            with open(source_file, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except (TypeError, OSError):
            return ""

    @classmethod
    def verify_plugin_integrity(cls, trusted_hashes: dict[str, str]) -> list[str]:
        """Check registered plugins against trusted hashes.

        Returns list of plugin names that fail integrity check.
        """
        violations: list[str] = []
        for name, expected in trusted_hashes.items():
            actual = cls._plugin_hashes.get(name, "")
            if not actual or actual != expected:
                violations.append(name)
        return violations

    @classmethod
    def discover_entry_points(cls, group: str = "redcheck.plugins") -> None:
        """Discover plugins via ``importlib.metadata`` entry points."""
        eps = importlib.metadata.entry_points()
        # Python 3.12+ returns a SelectableGroups; 3.10/3.11 returns dict
        selected = eps.select(group=group) if hasattr(eps, "select") else getattr(eps, group, [])
        for ep in selected:
            try:
                plugin_class = ep.load()
                cls.register(plugin_class)
                log.info("plugin_discovered", plugin=ep.name, entry_point=str(ep))
            except Exception:
                log.warning("plugin_discovery_failed", entry_point=str(ep), exc_info=True)

    @classmethod
    def get(cls, name: str) -> type[BasePlugin] | None:
        """Get a plugin class by name."""
        return cls._plugins.get(name)

    @classmethod
    def suggest(cls, name: str, n: int = 3, cutoff: float = 0.5) -> list[str]:
        """Return up to *n* registered plugin names similar to *name*."""
        return difflib.get_close_matches(name, cls._plugins.keys(), n=n, cutoff=cutoff)

    @classmethod
    def get_instance(cls, name: str) -> BasePlugin | None:
        """Get an instantiated plugin by name."""
        plugin_class = cls.get(name)
        if plugin_class:
            return plugin_class()
        return None

    @classmethod
    def list_plugins(cls) -> list[dict[str, Any]]:
        """List all registered plugins with metadata."""
        result: list[dict[str, Any]] = []
        for name, plugin_class in sorted(cls._plugins.items()):
            result.append(
                {
                    "name": name,
                    "version": getattr(plugin_class, "version", "0.0.0"),
                    "description": getattr(plugin_class, "description", ""),
                    "requires_authorization": getattr(plugin_class, "requires_authorization", True),
                    "category": getattr(plugin_class, "category", "general"),
                    "capability": getattr(
                        plugin_class, "capability", PluginCapability.PASSIVE
                    ).value,
                }
            )
        return result

    @classmethod
    def list_names(cls) -> list[str]:
        """List all registered plugin names."""
        return sorted(cls._plugins.keys())

    @classmethod
    def all_plugins(cls) -> dict[str, type[BasePlugin]]:
        """Return a copy of the plugin registry dict."""
        return dict(cls._plugins)

    @classmethod
    def unregister(cls, name: str) -> None:
        """Remove a plugin from the registry by name."""
        cls._plugins.pop(name, None)

    @classmethod
    def clear(cls) -> None:
        """Clear all registered plugins (for testing)."""
        cls._plugins.clear()
