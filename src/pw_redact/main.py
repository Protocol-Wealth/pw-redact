# Copyright 2026 Protocol Wealth LLC
# Licensed under the Apache License, Version 2.0
# https://github.com/Protocol-Wealth/pw-redact

"""FastAPI application entry point."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI

from . import __version__
from .redactor.engine import PWRedactor

_redactor: PWRedactor | None = None


def get_redactor() -> PWRedactor:
    """Return the initialized redactor instance."""
    assert _redactor is not None, "Redactor not initialized"
    return _redactor


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    global _redactor
    _redactor = PWRedactor()
    yield
    _redactor = None


app = FastAPI(
    title="pw-redact",
    description="PII redaction engine for financial services AI pipelines",
    version=__version__,
    lifespan=lifespan,
)


@app.get("/v1/health")
async def health() -> dict:
    return {
        "status": "healthy",
        "version": __version__,
        "models_loaded": _redactor is not None,
    }
