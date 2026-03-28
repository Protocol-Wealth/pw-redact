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
Raw text (transcript, tax notes, meeting notes)
        │
        ▼
   pw-redact /v1/redact
   ├── Layer 1: Deterministic regex (SSN, CC, account numbers, EIN)
   ├── Layer 2: Presidio NLP (names, addresses, phone, email)
   ├── Layer 3: Custom financial recognizers (CUSIP, routing numbers)
   ├── Layer 4: Allow-list (preserve $amounts, %, tax brackets, dates)
   └── Returns: sanitized_text + redaction_manifest
        │
        ▼
   Sanitized text → your AI model (safe to send externally)
        │
        ▼
   pw-redact /v1/rehydrate
   ├── Takes: AI model output + redaction_manifest
   └── Returns: output with original values restored
```

**Key design principles:**

- **Stateless** — pw-redact stores nothing. Manifests are returned to the caller.
- **Deterministic first** — Regex patterns run before NLP. If regex catches it, NLP doesn't need to.
- **Financial data survives** — Dollar amounts, percentages, tax brackets, basis points pass through intact.
- **Consistent placeholders** — "John Smith" → `<PERSON_1>` everywhere in the document, so the AI model can track entity relationships.

## Quick Start

### Install

```bash
pip install pw-redact
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
    "John Smith's SSN is 123-45-6789. His AGI is $425,000.",
    context="meeting_transcript",
)

print(result.sanitized_text)
# "<PERSON_1>'s SSN is <US_SSN_1>. His AGI is $425,000."

print(result.manifest.to_dict())
# {"version": "1.0", "redaction_id": "red_...", "placeholders": [...], "stats": {...}}

# Rehydrate after AI processing
ai_output = "Based on <PERSON_1>'s income, a Roth conversion is recommended."
restored = rehydrator.rehydrate(ai_output, result.manifest.to_dict())
# "Based on John Smith's income, a Roth conversion is recommended."
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

# Health check
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

**Context values:** `meeting_transcript` | `tax_return` | `financial_notes` | `general`

### POST /v1/rehydrate

Restore original values from placeholders using the manifest.

### POST /v1/detect

Detect PII locations without redacting. Returns entity positions and types for UI highlighting.

### GET /v1/health

Returns service status, version, and whether NLP models are loaded.

## What Gets Redacted (and What Doesn't)

### Redacted (PII)
| Type | Examples |
|------|----------|
| Names | "John Smith", "Dr. Jane Doe" |
| SSN | "123-45-6789", "123 45 6789" |
| Phone | "(610) 555-1234", "+1-610-555-1234" |
| Email | "john@example.com" |
| Address | "42 Oak Lane, City PA 19000" |
| Credit Card | "4111 1111 1111 1111" |
| EIN | "12-3456789" |
| Account Numbers | "account #12345678" |

### Preserved (Financial Data)
| Type | Examples |
|------|----------|
| Dollar amounts | "$425,000", "$50k", "95,000" |
| Percentages | "32%", "6.75%" |
| Tax brackets | "32% bracket", "24% rate" |
| Planning years | "2032", "2026" |
| Form references | "Form 1040", "Schedule D", "IRC §1015" |
| Financial acronyms | "AGI", "QCD", "RMD", "529 plan" |
| Ages | "age 70.5", "turning 59.5" |
| Basis points | "250 bps" |

## Use Cases

- **Meeting transcript sanitization** before AI summarization
- **Tax return data extraction** with PII stripped
- **Financial document processing** for AI analysis
- **Compliance-safe AI integration** for RIAs and broker-dealers
- **Client communication review** before sending to AI for drafting

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

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for code standards, test requirements, and PR process.

## License

Apache 2.0 — free for commercial use.

## Built By

[Protocol Wealth LLC](https://protocolwealthllc.com) — SEC-registered investment adviser
building transparent AI infrastructure for the advisory industry.

*Protocol Wealth LLC | SEC-Registered Investment Adviser (CRD #335298)*
