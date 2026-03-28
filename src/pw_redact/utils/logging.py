# Copyright 2026 Protocol Wealth LLC
# Licensed under the Apache License, Version 2.0
# https://github.com/Protocol-Wealth/pw-redact

"""Structured logging with PII-safe output."""

from __future__ import annotations

import structlog

from ..config import settings


def configure_logging() -> None:
    """Configure structlog for the application."""
    processors: list = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.set_exc_info,
        structlog.processors.TimeStamper(fmt="iso"),
    ]
    if settings.environment == "production":
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            structlog.get_level_from_name(settings.log_level)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str = __name__) -> structlog.stdlib.BoundLogger:
    """Return a structured logger instance."""
    return structlog.get_logger(name)
