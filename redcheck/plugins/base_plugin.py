"""RedCheck246 — Base Plugin & Plugin Registry.

All plugins MUST inherit from ``BasePlugin``.
Active plugins MUST pass PolicyEngine.authorize() before execution.
"""

from __future__ import annotations

import importlib.metadata
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import structlog

from redcheck.models import PluginCapability

log = structlog.get_logger(__name__)


# ------------------------------------------------------------------
# Lightweight dataclass result — used by the plugin layer itself.
# The Pydantic ``PluginResult`` model in ``models.py`` is used at
# the reporting / serialisation boundary.
# ------------------------------------------------------------------


@dataclass
class PluginResult:
    """Standard result returned by plugin execution."""

    plugin_name: str
    success: bool
    findings: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "plugin_name": self.plugin_name,
            "success": self.success,
            "findings": self.findings,
            "evidence": self.evidence,
            "errors": self.errors,
            "metadata": self.metadata,
        }


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

    @classmethod
    def register(cls, plugin_class: type[BasePlugin]) -> None:
        """Register a plugin class."""
        name = getattr(plugin_class, "name", None)
        if name and name != "unnamed":
            cls._plugins[name] = plugin_class
            log.debug("plugin_registered", plugin=name)

    @classmethod
    def discover_entry_points(cls, group: str = "redcheck.plugins") -> None:
        """Discover plugins via ``importlib.metadata`` entry points."""
        eps = importlib.metadata.entry_points()
        # Python 3.12+ returns a SelectableGroups; 3.10/3.11 returns dict
        selected = eps.select(group=group) if hasattr(eps, "select") else eps.get(group, [])
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
    def clear(cls) -> None:
        """Clear all registered plugins (for testing)."""
        cls._plugins.clear()
