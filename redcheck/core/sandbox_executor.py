"""RedCheck246 — Sandbox Executor (Phase M).

Provides resource-limited execution for plugins that declare
``requires_isolation = True``.  Uses subprocess isolation with
configurable memory limits and timeouts.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from typing import TYPE_CHECKING, Any

import structlog

from redcheck.plugins.base_plugin import PluginResult

if TYPE_CHECKING:
    from redcheck.models import PluginMetadata

log = structlog.get_logger(__name__)


try:
    import resource
except ModuleNotFoundError:  # Windows
    resource = None  # type: ignore[assignment]


def _apply_memory_limit(limit_mb: int) -> None:
    """Set the soft RSS limit (POSIX only, best-effort)."""
    if resource is None:
        return
    try:
        limit_bytes = limit_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, limit_bytes))
    except (AttributeError, ValueError, OSError):
        # Unsupported — silently ignore
        pass


def run_sandboxed(
    plugin_name: str,
    context: dict[str, Any],
    metadata: PluginMetadata,
    *,
    python: str | None = None,
) -> PluginResult:
    """Execute a plugin in a sandboxed subprocess.

    The plugin is imported and invoked in a fresh Python interpreter
    with a memory limit applied via ``resource.setrlimit`` (POSIX)
    or best-effort enforcement (Windows).

    Args:
        plugin_name: The registered plugin name.
        context: Execution context dict (JSON-serialisable subset).
        metadata: Plugin metadata with timeout_seconds and memory_limit_mb.
        python: Optional path to the Python interpreter.

    Returns:
        PluginResult parsed from the subprocess stdout JSON.
    """
    python = python or sys.executable
    timeout = metadata.timeout_seconds
    memory_limit_mb = metadata.memory_limit_mb

    # Build a minimal runner script
    runner_script = textwrap.dedent(f"""\
        import json, sys
        try:
            import resource
            limit = {memory_limit_mb} * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
        except Exception:
            pass
        from redcheck.plugins.base_plugin import PluginRegistry
        import redcheck.plugins  # trigger auto-discovery
        plugin_cls = PluginRegistry.get("{plugin_name}")
        if plugin_cls is None:
            json.dump({{"plugin_name": "{plugin_name}", "success": False,
                       "findings": [], "errors": ["Plugin not found in sandbox"]}},
                      sys.stdout)
            sys.exit(0)
        ctx = json.loads(sys.stdin.read())
        plugin = plugin_cls()
        result = plugin.execute(ctx)
        json.dump(result.model_dump(mode="json"), sys.stdout)
    """)

    log.info(
        "sandbox_execute",
        plugin=plugin_name,
        timeout=timeout,
        memory_limit_mb=memory_limit_mb,
    )

    try:
        proc = subprocess.run(  # noqa: S603
            [python, "-c", runner_script],
            input=json.dumps(_serialisable_context(context)),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return PluginResult(
            plugin_name=plugin_name,
            success=False,
            error_type="sandbox_timeout",
            error_message=f"Sandboxed plugin timed out after {timeout}s",
            failure_stage="execution",
            errors=[f"Sandboxed plugin timed out after {timeout}s"],
        )
    except OSError as exc:
        return PluginResult(
            plugin_name=plugin_name,
            success=False,
            error_type="sandbox_error",
            error_message=str(exc),
            failure_stage="init",
            errors=[f"Sandbox launch failed: {exc}"],
        )

    if proc.returncode != 0:
        stderr_snippet = (proc.stderr or "")[:500]
        return PluginResult(
            plugin_name=plugin_name,
            success=False,
            error_type="sandbox_crash",
            error_message=f"Subprocess exited with code {proc.returncode}",
            failure_stage="execution",
            errors=[f"Sandbox crash (rc={proc.returncode}): {stderr_snippet}"],
        )

    try:
        data = json.loads(proc.stdout)
        return PluginResult(**data)
    except (json.JSONDecodeError, Exception) as exc:
        return PluginResult(
            plugin_name=plugin_name,
            success=False,
            error_type="sandbox_parse_error",
            error_message=str(exc),
            failure_stage="post_execution",
            errors=[f"Failed to parse sandbox output: {exc}"],
        )


def _serialisable_context(context: dict[str, Any]) -> dict[str, Any]:
    """Produce a JSON-safe subset of the context dict."""
    safe: dict[str, Any] = {}
    for key, value in context.items():
        if key.startswith("_"):
            continue  # skip runtime internals
        try:
            json.dumps(value)
            safe[key] = value
        except (TypeError, ValueError):
            safe[key] = str(value)
    return safe
