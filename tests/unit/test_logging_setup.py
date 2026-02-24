"""Tests for structured logging setup."""

from __future__ import annotations

import logging
from pathlib import Path

from redcheck.logging import setup_logging


class TestSetupLogging:
    def test_console_only_text(self) -> None:
        setup_logging(level="DEBUG", json_output=False)
        root = logging.getLogger()
        assert root.level == logging.DEBUG
        assert len(root.handlers) >= 1

    def test_console_json_mode(self) -> None:
        setup_logging(level="WARNING", json_output=True)
        root = logging.getLogger()
        assert root.level == logging.WARNING

    def test_with_file_handler(self, tmp_path: Path) -> None:
        log_file = tmp_path / "sub" / "test.log"
        setup_logging(level="INFO", json_output=False, log_file=log_file)
        root = logging.getLogger()
        assert log_file.parent.exists()
        # Should have console + file handler
        assert len(root.handlers) >= 2

    def test_suppresses_noisy_loggers(self) -> None:
        setup_logging()
        for name in ("httpx", "httpcore", "urllib3", "asyncio"):
            assert logging.getLogger(name).level >= logging.WARNING

    def test_invalid_level_defaults_to_info(self) -> None:
        setup_logging(level="NONEXISTENT")
        root = logging.getLogger()
        assert root.level == logging.INFO

    def test_reinit_clears_handlers(self) -> None:
        setup_logging()
        setup_logging()
        root = logging.getLogger()
        # Should not duplicate handlers
        handler_count = len(root.handlers)
        setup_logging()
        assert len(root.handlers) == handler_count
