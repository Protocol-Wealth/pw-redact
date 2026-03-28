# Copyright 2026 Protocol Wealth LLC
# Licensed under the Apache License, Version 2.0
# https://github.com/Protocol-Wealth/pw-redact

"""FastAPI application entry point."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import Depends, FastAPI

from . import __version__
from .auth import verify_api_key
from .models.requests import DetectRequest, RedactRequest, RehydrateRequest
from .redactor.engine import PWRedactor
from .rehydrator.engine import PWRehydrator

_redactor: PWRedactor | None = None
_rehydrator = PWRehydrator()


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


@app.post("/v1/redact")
async def redact(req: RedactRequest, _: None = Depends(verify_api_key)) -> dict:
    redactor = get_redactor()
    result = redactor.redact(req.text, context=req.context)
    return {
        "sanitized_text": result.sanitized_text,
        "manifest": result.manifest.to_dict(),
    }


@app.post("/v1/rehydrate")
async def rehydrate(req: RehydrateRequest, _: None = Depends(verify_api_key)) -> dict:
    restored = _rehydrator.rehydrate(req.text, req.manifest)
    return {"rehydrated_text": restored}


@app.post("/v1/detect")
async def detect(req: DetectRequest, _: None = Depends(verify_api_key)) -> dict:
    redactor = get_redactor()
    entities = redactor.detect(req.text, context=req.context)
    return {
        "entities": [
            {
                "entity_type": e.entity_type,
                "text": e.text,
                "start": e.start,
                "end": e.end,
                "score": e.score,
            }
            for e in entities
        ],
    }
