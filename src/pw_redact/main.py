# Copyright 2026 Protocol Wealth LLC
# Licensed under the Apache License, Version 2.0
# https://github.com/Protocol-Wealth/pw-redact

"""FastAPI application entry point with security hardening."""

from __future__ import annotations

import time
import uuid
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

from . import __version__
from .auth import verify_api_key
from .models.requests import DetectRequest, RedactRequest, RehydrateRequest
from .redactor.engine import PWRedactor
from .rehydrator.engine import PWRehydrator
from .security.input_validator import validate_input
from .security.output_validator import validate_output
from .security.prompt_injection_detector import detect_injection
from .security.rate_limiter import RateLimiter

_redactor: PWRedactor | None = None
_rehydrator = PWRehydrator()
_rate_limiter: RateLimiter | None = None


def get_redactor() -> PWRedactor:
    """Return the initialized redactor instance."""
    assert _redactor is not None, "Redactor not initialized"
    return _redactor


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    global _redactor, _rate_limiter
    _redactor = PWRedactor()
    _rate_limiter = RateLimiter()
    yield
    _redactor = None


app = FastAPI(
    title="pw-redact",
    description="PII redaction engine for financial services AI pipelines",
    version=__version__,
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Middleware: request ID + timing headers
# ---------------------------------------------------------------------------
@app.middleware("http")
async def add_request_context(request: Request, call_next):
    request_id = f"req_{uuid.uuid4().hex[:12]}"
    request.state.request_id = request_id
    start = time.monotonic()

    response = await call_next(request)

    elapsed_ms = round((time.monotonic() - start) * 1000, 1)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Processing-Time-Ms"] = str(elapsed_ms)
    return response


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/v1/health")
async def health() -> dict:
    return {
        "status": "healthy",
        "version": __version__,
        "models_loaded": _redactor is not None,
    }


@app.post("/v1/redact")
async def redact(
    req: RedactRequest,
    request: Request,
    _: None = Depends(verify_api_key),
) -> JSONResponse:
    request_id = getattr(request.state, "request_id", "unknown")

    # Rate limiting
    assert _rate_limiter is not None
    allowed, retry_after = _rate_limiter.check(req.context)
    if not allowed:
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded"},
            headers={"Retry-After": str(retry_after)},
        )

    # Input validation
    validation = validate_input(req.text)
    if not validation.is_valid:
        return JSONResponse(status_code=413, content={"detail": validation.error})

    # Prompt injection detection (advisory, not blocking)
    injection = detect_injection(validation.text)

    # Redact PII
    redactor = get_redactor()
    result = redactor.redact(validation.text, context=req.context)

    # Output validation
    manifest_dict = result.manifest.to_dict()
    output_check = validate_output(result.sanitized_text, manifest_dict)

    return JSONResponse(content={
        "sanitized_text": result.sanitized_text,
        "manifest": manifest_dict,
        "security": {
            "input_sanitized": len(validation.actions) > 0,
            "sanitization_actions": validation.actions,
            "injection_detected": injection.is_suspicious,
            "injection_score": injection.injection_score,
            "injection_patterns": injection.detected_patterns,
            "output_valid": output_check.is_valid,
            "output_warnings": output_check.warnings,
            "request_id": request_id,
        },
    })


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
