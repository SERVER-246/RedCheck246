"""Tests for __main__.py module entry point."""

from __future__ import annotations

import contextlib
import runpy
from unittest.mock import patch


class TestMainModule:
    def test_main_invocation(self) -> None:
        with patch("redcheck.cli.app"), contextlib.suppress(SystemExit):
            runpy.run_module("redcheck", run_name="__main__")
        # The module imports app — even if it doesn't call it due to
        # __name__ guard, the import itself covers lines 3-4
