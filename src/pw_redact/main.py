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
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

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

_GITHUB_URL = "https://github.com/Protocol-Wealth/pw-redact"


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
# Landing page + machine-readable metadata
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def landing_page() -> HTMLResponse:
    return HTMLResponse(content=f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>pw-redact — PII Redaction for Financial Services</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
           Helvetica, Arial, sans-serif; max-width: 720px; margin: 40px auto;
           padding: 0 20px; color: #1a1a1a; line-height: 1.6; }}
    h1 {{ margin-bottom: 4px; }}
    .subtitle {{ color: #555; margin-top: 0; font-size: 1.1em; }}
    code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px;
            font-size: 0.9em; }}
    pre {{ background: #f4f4f4; padding: 16px; border-radius: 6px;
           overflow-x: auto; font-size: 0.85em; }}
    a {{ color: #0066cc; }}
    .endpoints {{ border-collapse: collapse; width: 100%; margin: 16px 0; }}
    .endpoints th, .endpoints td {{ border: 1px solid #ddd; padding: 8px 12px;
                                     text-align: left; }}
    .endpoints th {{ background: #f8f8f8; }}
    .tag {{ display: inline-block; background: #e8f4e8; color: #2a6e2a;
            padding: 2px 8px; border-radius: 12px; font-size: 0.8em;
            margin-right: 4px; }}
    footer {{ margin-top: 40px; padding-top: 16px; border-top: 1px solid #eee;
              color: #777; font-size: 0.85em; }}
  </style>
</head>
<body>
  <h1>pw-redact</h1>
  <p class="subtitle">Open-source PII redaction engine for financial services AI pipelines</p>

  <p>
    <span class="tag">v{__version__}</span>
    <span class="tag">Apache 2.0</span>
    <span class="tag">Python 3.12+</span>
    <span class="tag">Stateless</span>
  </p>

  <p>pw-redact strips personally identifiable information from financial text
  (meeting transcripts, tax notes, mortgage documents) before it reaches AI models,
  while preserving dollar amounts, percentages, tax brackets, and other financial
  data models need to work.</p>

  <h2>API Endpoints</h2>
  <table class="endpoints">
    <tr><th>Method</th><th>Path</th><th>Auth</th><th>Description</th></tr>
    <tr><td><code>POST</code></td><td><code>/v1/redact</code></td>
        <td>Bearer</td><td>Redact PII, return sanitized text + manifest</td></tr>
    <tr><td><code>POST</code></td><td><code>/v1/rehydrate</code></td>
        <td>Bearer</td><td>Restore original values from manifest</td></tr>
    <tr><td><code>POST</code></td><td><code>/v1/detect</code></td>
        <td>Bearer</td><td>Detect PII locations without redacting</td></tr>
    <tr><td><code>GET</code></td><td><code>/v1/health</code></td>
        <td>None</td><td>Service health check</td></tr>
  </table>

  <h2>Quick Example</h2>
  <pre>curl -X POST {_GITHUB_URL.replace('github.com/Protocol-Wealth/pw-redact',
  'pw-redact.fly.dev')}/v1/redact \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{{"text": "John Smith SSN 123-45-6789. AGI $425,000.", "context": "general"}}'</pre>

  <h2>Links</h2>
  <ul>
    <li><a href="{_GITHUB_URL}">GitHub Repository</a> — source code, docs, issues</li>
    <li><a href="{_GITHUB_URL}/blob/main/docs/architecture.md">Architecture</a>
        — four-layer pipeline design</li>
    <li><a href="{_GITHUB_URL}/blob/main/docs/deployment.md">Deployment Guide</a>
        — Docker, Fly.io, Railway, AWS/GCP</li>
    <li><a href="{_GITHUB_URL}/blob/main/docs/allow-list-guide.md">Allow-List Guide</a>
        — customize financial data preservation</li>
    <li><a href="/v1/health">Health Check</a></li>
    <li><a href="/llms.txt">llms.txt</a> — machine-readable project description</li>
    <li><a href="/docs">API Documentation</a> (OpenAPI / Swagger)</li>
  </ul>

  <footer>
    <p>Built by <a href="https://protocolwealthllc.com">Protocol Wealth LLC</a>
    — SEC-Registered Investment Adviser (CRD #335298)</p>
    <p>Security issues: <a href="mailto:security@protocolwealthllc.com">
    security@protocolwealthllc.com</a></p>
  </footer>
</body>
</html>""")


@app.get("/llms.txt", response_class=PlainTextResponse)
async def llms_txt() -> PlainTextResponse:
    return PlainTextResponse(content=f"""# pw-redact

> Open-source PII redaction engine for financial services AI pipelines

pw-redact is a stateless API that strips personally identifiable information
(PII) from financial text before it reaches AI models, while preserving
dollar amounts, percentages, tax brackets, and other financial data.

## API

Base URL: https://pw-redact.fly.dev
Auth: Bearer token in Authorization header
Health: GET /v1/health (no auth)

### POST /v1/redact
Redact PII from text. Returns sanitized text + manifest for rehydration.
Request: {{"text": "...", "context": "general"}}
Contexts: meeting_transcript, tax_return, financial_notes, mortgage, real_estate, general
Response includes: sanitized_text, manifest (for rehydration), security metadata

### POST /v1/rehydrate
Restore original values from placeholders using the manifest.
Request: {{"text": "...", "manifest": {{...}}}}

### POST /v1/detect
Detect PII locations without redacting. Returns entity positions and types.
Request: {{"text": "...", "context": "general"}}

## Entity Types Detected (30 regex + NLP)
PII: US_SSN, CREDIT_CARD, EMAIL, US_PHONE, EIN, DATE_OF_BIRTH, ACCOUNT_NUMBER,
     DRIVERS_LICENSE, STREET_ADDRESS, US_ROUTING, PERSON, LOCATION
Secrets: JWT, API_KEY, PASSWORD, SECRET_VALUE, AUTH_TOKEN, BEARER_TOKEN,
         DB_URL, MAGIC_LINK
Crypto: CRYPTO_PRIVATE_KEY, CRYPTO_ADDRESS, CRYPTO_SEED
Mortgage: NMLS_ID, LOAN_NUMBER, MERS_MIN, FHA_CASE_NUMBER, PARCEL_NUMBER,
          MLS_NUMBER, FILE_REFERENCE
System: CRM_ID, PLATFORM_ID

## Financial Data Preserved (never redacted)
Dollar amounts, percentages, tax brackets, basis points, planning years,
ages, IRS form references, 60+ financial acronyms (AGI, LTV, DTI, TILA, etc.)

## Key Design Principles
- Stateless: stores nothing, no database, manifests returned to caller
- Deterministic first: regex before NLP
- Financial data survives: allow-list preserves what AI models need
- Consistent placeholders: same text = same placeholder throughout document
- Security built in: input validation, prompt injection detection, rate limiting

## Source
Repository: {_GITHUB_URL}
License: Apache 2.0
Version: {__version__}
Built by: Protocol Wealth LLC (SEC-RIA, CRD #335298)
""")


@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots_txt() -> PlainTextResponse:
    return PlainTextResponse(content="""# pw-redact — PII redaction API
# Allow indexing of public metadata; block API endpoints

User-agent: *
Allow: /
Allow: /v1/health
Allow: /llms.txt
Allow: /robots.txt
Allow: /.well-known/security.txt
Disallow: /v1/redact
Disallow: /v1/rehydrate
Disallow: /v1/detect
Disallow: /docs
Disallow: /openapi.json
""")


@app.get("/.well-known/security.txt", response_class=PlainTextResponse)
async def security_txt() -> PlainTextResponse:
    return PlainTextResponse(content=f"""Contact: mailto:security@protocolwealthllc.com
Preferred-Languages: en
Canonical: https://pw-redact.fly.dev/.well-known/security.txt
Policy: {_GITHUB_URL}/blob/main/SECURITY.md
Expires: 2027-03-28T00:00:00.000Z
""")


# ---------------------------------------------------------------------------
# API routes
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
        return JSONResponse(
            status_code=413,
            content={"detail": validation.error},
        )

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
async def rehydrate(
    req: RehydrateRequest, _: None = Depends(verify_api_key),
) -> dict:
    restored = _rehydrator.rehydrate(req.text, req.manifest)
    return {"rehydrated_text": restored}


@app.post("/v1/detect")
async def detect(
    req: DetectRequest, _: None = Depends(verify_api_key),
) -> dict:
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
