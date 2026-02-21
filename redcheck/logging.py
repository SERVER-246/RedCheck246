"""RedCheck246 structured logging — ``structlog`` + stdlib integration.

Call ``setup_logging()`` once at application startup. All modules use
``structlog.get_logger()`` for operational logs; the ``AuditLogger``
(see ``core.audit``) handles the tamper-evident compliance trail separately.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path  # noqa: TC003

import structlog


def setup_logging(
    level: str = "INFO",
    json_output: bool = False,
    log_file: Path | None = None,
) -> None:
    """Configure structlog and stdlib logging for the entire application.

    Parameters
    ----------
    level:
        Root log level (``DEBUG``, ``INFO``, ``WARNING``, ``ERROR``).
    json_output:
        If *True*, render as JSON lines (for CI / production).
        If *False*, use rich coloured console output (dev).
    log_file:
        Optional path to a rotating log file.
    """
    log_level = getattr(logging, level.upper(), logging.INFO)

    # Shared pre-chain processors
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    if json_output:
        renderer: structlog.types.Processor = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
        foreign_pre_chain=shared_processors,
    )

    # Console handler
    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(formatter)

    handlers: list[logging.Handler] = [console]

    # Optional file handler
    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        from logging.handlers import RotatingFileHandler

        file_handler = RotatingFileHandler(
            str(log_file),
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5,
            encoding="utf-8",
        )
        file_formatter = structlog.stdlib.ProcessorFormatter(
            processors=[
                structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                structlog.processors.JSONRenderer(),
            ],
            foreign_pre_chain=shared_processors,
        )
        file_handler.setFormatter(file_formatter)
        handlers.append(file_handler)

    # Configure root logger
    root = logging.getLogger()
    root.setLevel(log_level)
    # Remove existing handlers to avoid duplicates on re-init
    root.handlers.clear()
    for h in handlers:
        root.addHandler(h)

    # Suppress noisy third-party loggers
    for name in ("httpx", "httpcore", "urllib3", "asyncio"):
        logging.getLogger(name).setLevel(logging.WARNING)
