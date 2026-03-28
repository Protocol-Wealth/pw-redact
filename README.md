# pw-redact

**Open-source PII redaction engine for financial services AI pipelines.**

[![CI](https://github.com/Protocol-Wealth/pw-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/Protocol-Wealth/pw-redact/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)

Built by [Protocol Wealth LLC](https://protocolwealthllc.com), an SEC-registered
investment adviser, to ensure client data never reaches third-party AI models.

> We believe transparency in how client data is handled shouldn't be a competitive
> secret — it should be an industry standard.

## Why This Exists

Financial advisors increasingly use AI for meeting transcription, tax analysis,
and planning recommendations. Most solutions send raw client data — names, SSNs,
addresses — to cloud AI providers. pw-redact sits between your data and the AI
model, stripping PII while preserving the financial data models need to work.

## How It Works

pw-redact uses a four-layer architecture to catch PII while preserving financial data:

```
Raw text (transcript, tax notes, mortgage docs)
        |
        v
   pw-redact /v1/redact
   |-- Layer 1: Deterministic regex (SSN, CC, EIN, loan numbers, crypto keys...)
   |-- Layer 2: Presidio NLP (names, addresses, phone, email)
   |-- Layer 3: Custom financial recognizers (CUSIP, account refs, policy numbers)
   |-- Layer 4: Allow-list (preserve $amounts, %, tax brackets, dates)
   `-- Returns: sanitized_text + redaction_manifest
        |
        v
   Sanitized text -> your AI model (safe to send externally)
        |
        v
   pw-redact /v1/rehydrate
   |-- Takes: AI model output + redaction_manifest
   `-- Returns: output with original values restored
```

**Key design principles:**

- **Stateless** — pw-redact stores nothing. Manifests are returned to the caller.
- **Deterministic first** — Regex patterns run before NLP. If regex catches it, NLP doesn't need to.
- **Financial data survives** — Dollar amounts, percentages, tax brackets, basis points pass through intact.
- **Consistent placeholders** — "John Smith" becomes `<PERSON_1>` everywhere in the document, so the AI model can track entity relationships.

## Quick Start

### Install

```bash
pip install -e ".[dev]"
python -m spacy download en_core_web_lg
```

### As a Library

```python
from pw_redact.redactor.engine import PWRedactor
from pw_redact.rehydrator.engine import PWRehydrator

redactor = PWRedactor()
rehydrator = PWRehydrator()

# Redact PII
result = redactor.redact(
    "John Smith has SSN 123-45-6789. His AGI is $425,000.",
    context="meeting_transcript",
)

print(result.sanitized_text)
# "<PERSON_1> has SSN <US_SSN_1>. His AGI is $425,000."

print(result.manifest.to_dict())
# {"version": "1.0", "redaction_id": "red_...", "placeholders": [...], "stats": {...}}

# Rehydrate after AI processing
ai_output = "Based on the data, <PERSON_1> should consider a Roth conversion."
restored = rehydrator.rehydrate(ai_output, result.manifest.to_dict())
print(restored)
# "Based on the data, John Smith should consider a Roth conversion."
```

### As an API Server

```bash
# Set your API key
export PW_REDACT_API_KEY=your-secret-key

# Start the server
uvicorn pw_redact.main:app --host 0.0.0.0 --port 8080
```

```bash
# Redact
curl -X POST http://localhost:8080/v1/redact \
  -H "Authorization: Bearer your-secret-key" \
  -H "Content-Type: application/json" \
  -d '{"text": "John Smith SSN 123-45-6789", "context": "general"}'

# Health check (no auth required)
curl http://localhost:8080/v1/health
```

### Docker

```bash
docker build -t pw-redact .
docker run -p 8080:8080 -e PW_REDACT_API_KEY=your-key pw-redact
```

## API Reference

### POST /v1/redact

Redact PII from text. Returns sanitized text and a manifest for later rehydration.

**Request:**
```json
{
  "text": "John Smith discussed his AGI of $425,000. SSN: 123-45-6789.",
  "context": "meeting_transcript",
  "options": {
    "preserve_amounts": true,
    "preserve_dates": true,
    "preserve_percentages": true,
    "redaction_style": "placeholder"
  }
}
```

**Context values:** `meeting_transcript` | `tax_return` | `financial_notes` | `mortgage` | `real_estate` | `general`

### POST /v1/rehydrate

Restore original values from placeholders using the manifest.

### POST /v1/detect

Detect PII locations without redacting. Returns entity positions and types for UI highlighting.

### GET /v1/health

Returns service status, version, and whether NLP models are loaded. No authentication required.

## Supported Entity Types

### Layer 1: Regex Detection (30 patterns)

All regex patterns run regardless of document context.

| Category | Entity Type | Example |
|----------|-------------|---------|
| **PII** | `US_SSN` | 123-45-6789 |
| | `CREDIT_CARD` | 4111 1111 1111 1111 |
| | `EMAIL` | john@example.com |
| | `US_PHONE` | (610) 555-1234 |
| | `EIN` | 12-3456789 |
| | `DATE_OF_BIRTH` | DOB: 03/15/1980, birthdate: 1980-03-15 |
| | `ACCOUNT_NUMBER` | account #12345678 |
| | `DRIVERS_LICENSE` | DL# A12345678 |
| | `STREET_ADDRESS` | 42 Oak Lane, 123 Main Street #201 |
| | `US_ROUTING` | routing: 021000021 |
| **Secrets** | `JWT` | eyJ... tokens |
| | `API_KEY` | api_key=..., STRIPE_API_KEY=... |
| | `PASSWORD` | password=..., passwd:... |
| | `SECRET_VALUE` | secret=..., SECRET_KEY=..., private_key=... |
| | `AUTH_TOKEN` | access_token=..., refresh_token=..., session_id=... |
| | `BEARER_TOKEN` | Bearer ... |
| | `DB_URL` | postgres://user:pass@host |
| | `MAGIC_LINK` | reset_link=https://... |
| **Crypto** | `CRYPTO_PRIVATE_KEY` | 0x + 64 hex chars (ETH private keys) |
| | `CRYPTO_ADDRESS` | 0x + 40 hex chars (ETH addresses) |
| | `CRYPTO_SEED` | Quoted seed phrases / mnemonics |
| **Mortgage/RE** | `NMLS_ID` | NMLS# 456789 |
| | `LOAN_NUMBER` | Loan #MTG-2025-004821 |
| | `MERS_MIN` | MERS# + 18 digits |
| | `FHA_CASE_NUMBER` | FHA case #123-4567890 |
| | `PARCEL_NUMBER` | APN: 07-14-302-015 |
| | `MLS_NUMBER` | MLS# PM23456789 |
| | `FILE_REFERENCE` | escrow# NCS-123456-LA |
| **System IDs** | `CRM_ID` | client_id: 987654 |
| | `PLATFORM_ID` | wallet_id=deadbeef... (hex/UUID) |

### Layer 2: Presidio NLP Detection

Presidio entities vary by context. spaCy `en_core_web_lg` provides the NER backbone.

| Entity | Detected In |
|--------|-------------|
| `PERSON` | All contexts |
| `LOCATION` | All contexts |
| `PHONE_NUMBER` | All contexts |
| `EMAIL_ADDRESS` | All contexts |
| `US_SSN` | All contexts (backup to regex) |
| `CREDIT_CARD` | All contexts (backup to regex) |
| `NRP` | meeting_transcript, mortgage |
| `CUSIP` | financial_notes |
| `ACCOUNT_REF` | All except general |
| `POLICY_NUMBER` | meeting_transcript, financial_notes, mortgage, real_estate |

### Layer 4: Financial Data Preserved

The allow-list ensures these are **never redacted**:

| Type | Examples |
|------|----------|
| Dollar amounts | $425,000, $50k, 95,000 |
| Percentages | 32%, 6.75% |
| Tax brackets | 32% bracket, 24% rate |
| Basis points | 250 bps, 50 bp |
| Planning years | 2032, 2026 |
| Ages | age 59.5, age 70.5 |
| Form references | Form 1040, Schedule D, IRC S1015 |
| Financial acronyms | AGI, RMD, QCD, 529, W2, 1099 |
| Mortgage/RE terms | LTV, DTI, PMI, TILA, RESPA, HMDA, ALTA, FNMA, VOE |

## Use Cases

- **Meeting transcript sanitization** before AI summarization
- **Tax return data extraction** with PII stripped
- **Mortgage/underwriting documents** processed for AI analysis
- **Real estate/title documents** with buyer/seller PII removed
- **Compliance-safe AI integration** for RIAs, broker-dealers, and lenders
- **Client communication review** before sending to AI for drafting

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_regex_patterns.py -v

# Run with timing
pytest tests/ -v --tb=short
```

**Current:** 276 tests, ~3s runtime (session-scoped spaCy model load).

## Security

pw-redact includes built-in security hardening for AI pipeline protection:

### Input Validation
- Max payload: 1MB / 50,000 lines (rejects with 413)
- Strips null bytes, ASCII control characters (preserves `\n` and `\t`)
- Strips invisible Unicode (zero-width spaces, bidi overrides, BOM)
- Detects and removes base64-encoded blocks >200 chars (could hide injected instructions)
- Strips HTML tags and `<script>` elements
- Strips markdown image references with external URLs (`![](http://...)`)
- Normalizes excessive whitespace while preserving paragraph structure

### Prompt Injection Detection
- Scans for known injection phrases: "ignore previous instructions", "reveal your prompt", identity manipulation ("pretend you are"), fake delimiters (`<|im_start|>`, `[INST]`), encoded variants (leetspeak, spaced characters)
- Returns a confidence score (0.0-1.0) and list of matched patterns
- **Advisory only** — flags suspicious input but does NOT block it. Advisors may legitimately paste client emails containing unusual text. The caller (your application) decides policy.
- Injection data is included in the `/v1/redact` response under a `security` key

### Output Validation
- Verifies no original PII values leaked into `sanitized_text`
- Validates all placeholders match the `<TYPE_N>` format
- Checks manifest structural integrity

### Rate Limiting
- In-memory token bucket per API key
- Default: 60 requests/minute, 10 requests/second burst
- Returns 429 with `Retry-After` header when exceeded
- Configurable via `RATE_LIMIT_RPM` env var

### Response Headers
- `X-Request-ID` — UUID for request tracing
- `X-Processing-Time-Ms` — Server-side processing time

## Performance

| Metric | Observed | Notes |
|--------|----------|-------|
| Test suite | 276 tests in ~3s | spaCy model loaded once per session |
| Short text (<100 words) | <500ms | Regex + Presidio on warm engine |
| Long transcript (~500 words) | ~1-2s | spaCy NER is the bottleneck |
| Cold start (Fly.io resume) | ~8-10s | spaCy en_core_web_lg model load |
| Memory | ~1.2GB steady-state | en_core_web_lg (~560MB) + Presidio + overhead |
| Docker image | ~1.0GB | Python 3.12 slim + spaCy model |

## Development

```bash
# Clone and install
git clone https://github.com/Protocol-Wealth/pw-redact.git
cd pw-redact
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m spacy download en_core_web_lg

# Run tests
pytest tests/ -v

# Lint
ruff check src/
```

## Deployment

pw-redact runs as a stateless container on any platform that supports Docker:
Fly.io, Railway, AWS ECS, Google Cloud Run, etc.

See `fly.toml.example` for a Fly.io template. Copy it to `fly.toml`, set your
app name and region, then deploy:

```bash
fly launch
fly secrets set PW_REDACT_API_KEY=your-strong-random-key
fly deploy
```

**Note:** Use at least 2GB RAM. The spaCy `en_core_web_lg` model loads at ~560MB;
1GB VMs will OOM during startup.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for code standards, test requirements, and PR process.

## License

Apache 2.0 — free for commercial use.

## Built By

[Protocol Wealth LLC](https://protocolwealthllc.com) — SEC-registered investment adviser
building transparent AI infrastructure for the advisory industry.

*Protocol Wealth LLC | SEC-Registered Investment Adviser (CRD #335298)*
