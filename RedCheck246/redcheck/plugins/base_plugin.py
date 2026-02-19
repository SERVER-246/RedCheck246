"""
RedCheck246 Base Plugin & Plugin Registry

All plugins MUST inherit from BasePlugin.
Active plugins MUST call PolicyEngine.authorize() before execution.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class PluginResult:
    """Standard result returned by plugin execution."""

    plugin_name: str
    success: bool
    findings: list[dict] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "plugin_name": self.plugin_name,
            "success": self.success,
            "findings": self.findings,
            "evidence": self.evidence,
            "errors": self.errors,
            "metadata": self.metadata,
        }


class BasePlugin(ABC):
    """Abstract base class for all RedCheck plugins.

    Every plugin must define:
    - name: unique identifier
    - version: semver string
    - requires_authorization: whether RoE + activation is needed
    - execute(context): the main execution method
    """

    name: str = "unnamed"
    version: str = "0.0.0"
    description: str = ""
    requires_authorization: bool = True  # Default: require auth
    category: str = "general"  # recon, sast, dast, fuzzing, supply_chain

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        # Auto-register on subclass creation
        if not getattr(cls, "_abstract", False) and hasattr(cls, "name"):
            PluginRegistry.register(cls)

    @abstractmethod
    def execute(self, context: dict) -> PluginResult:
        """Execute the plugin within the given engagement context.

        Args:
            context: Dict containing engagement_id, targets, roe, config, etc.

        Returns: PluginResult with findings, evidence, and metadata.
        """
        ...

    def dry_run(self, context: dict) -> PluginResult:
        """Simulate execution without touching targets.

        Default implementation returns an empty successful result.
        Override for meaningful dry-run behavior.
        """
        return PluginResult(
            plugin_name=self.name,
            success=True,
            metadata={"mode": "dry-run", "description": f"Dry run of {self.name}"},
        )

    def validate_context(self, context: dict) -> tuple[bool, str]:
        """Validate that the context has everything this plugin needs.

        Override to add plugin-specific validation.
        """
        if not context:
            return False, "Empty context"
        return True, "Context valid"

    def __repr__(self) -> str:
        auth = "AUTH-REQUIRED" if self.requires_authorization else "NO-AUTH"
        return f"<Plugin:{self.name} v{self.version} [{auth}]>"


class PluginRegistry:
    """Central registry for all RedCheck plugins.

    Plugins are auto-registered when their class is defined (via __init_subclass__).
    """

    _plugins: dict[str, type[BasePlugin]] = {}

    @classmethod
    def register(cls, plugin_class: type[BasePlugin]) -> None:
        """Register a plugin class."""
        name = getattr(plugin_class, "name", None)
        if name and name != "unnamed":
            cls._plugins[name] = plugin_class

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
        result = []
        for name, plugin_class in sorted(cls._plugins.items()):
            result.append({
                "name": name,
                "version": getattr(plugin_class, "version", "0.0.0"),
                "description": getattr(plugin_class, "description", ""),
                "requires_authorization": getattr(plugin_class, "requires_authorization", True),
                "category": getattr(plugin_class, "category", "general"),
            })
        return result

    @classmethod
    def list_names(cls) -> list[str]:
        """List all registered plugin names."""
        return sorted(cls._plugins.keys())

    @classmethod
    def clear(cls) -> None:
        """Clear all registered plugins (for testing)."""
        cls._plugins.clear()
