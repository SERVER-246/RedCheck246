"""RedCheck246 plugins — auto-discovery.

Importing this package triggers ``pkgutil.walk_packages`` which imports
every sub-module.  Each ``BasePlugin`` subclass auto-registers itself
via ``__init_subclass__``.  A broken module is logged and skipped — it
cannot crash the CLI or other plugins (BC-6).
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
