"""RedCheck246 plugins — auto-discovery.

Importing this package triggers ``pkgutil.walk_packages`` which imports
every sub-module.  Each ``BasePlugin`` subclass auto-registers itself
via ``__init_subclass__``.  A broken module is logged and skipped — it
cannot crash the CLI or other plugins (BC-6).

If ``plugin_allowlist`` is set in the active config, only plugins whose
names appear in the allowlist are kept in the registry (Phase O).
"""

from __future__ import annotations

import importlib
import logging
import pkgutil

import redcheck.plugins as _pkg

_log = logging.getLogger(__name__)

for _importer, _modname, _ispkg in pkgutil.walk_packages(_pkg.__path__, prefix=_pkg.__name__ + "."):
    try:
        importlib.import_module(_modname)
    except Exception as _exc:  # noqa: BLE001
        _log.warning("plugin_import_failed: module=%s error=%s", _modname, _exc)


def enforce_plugin_allowlist() -> None:
    """Remove plugins not on the config allowlist from the registry.

    Safe to call multiple times. Does nothing if allowlist is None.
    """
    from redcheck.config import get_config
    from redcheck.plugins.base_plugin import PluginRegistry

    cfg = get_config()
    if cfg.plugin_allowlist is None:
        return

    allowed = set(cfg.plugin_allowlist)
    registered = list(PluginRegistry.all_plugins().keys())
    for name in registered:
        if name not in allowed:
            PluginRegistry.unregister(name)
            _log.info("plugin_blocked_by_allowlist: %s", name)
