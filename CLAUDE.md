# CLAUDE.md — pw-redact

> **Repository:** pw-redact (PUBLIC — open source)
> **License:** MIT
> **GitHub:** github.com/Protocol-Wealth/pw-redact
> **Purpose:** Open-source PII redaction engine for financial services AI pipelines
> **Stack:** Python 3.12 · FastAPI · Presidio · spaCy · Fly.io
> **Status:** v0.1.0 DEPLOYED — pw-redact.fly.dev (ord region, 2GB RAM)
>
> **Open-source rationale:** pw-redact is infrastructure, not proprietary business logic.
> Publishing it demonstrates to regulators, clients, and the public exactly how Protocol
> Wealth handles client data before it reaches any AI model. The EMF framework, scoring
> pipeline, vault strategies, and client data remain private in separate repositories.

---

## 0. OPEN-SOURCE GROUND RULES

### What goes in this repo (public):
- All redaction logic, regex patterns, Presidio configuration
- Financial allow-list patterns
- API server code, tests, documentation
- Sample fixtures with SYNTHETIC data only
- Generic deployment examples (Docker, fly.toml.example)
- CLAUDE.md (this file — let people see how we build with AI)
- README.md with usage guide, architecture overview, and contribution guide

### What NEVER goes in this repo:
- API keys, secrets, tokens, passwords (use env vars exclusively)
- Internal URLs (no protocolwealthllc.com, nexusmcp.site, pwdashboard.com)
- Client data, real transcripts, real names, real SSNs
- PW-specific deployment config (actual fly.toml with app name, actual .env)
- References to specific clients, advisors, or internal business processes
- AGENTS.md or ria.md (those are private governance docs)

### Deployment separation:
- **Public repo:** github.com/Protocol-Wealth/pw-redact (code, tests, docs)
- **Private config:** Fly.io secrets, actual fly.toml, .env — managed outside the repo
- **fly.toml.example** in repo with placeholder values; actual fly.toml in .gitignore

### License header (every .py file):
```python
# Copyright 2026 Protocol Wealth LLC
# Licensed under the MIT License
# https://github.com/Protocol-Wealth/pw-redact
```

### README.md positioning:
pw-redact is positioned as a general-purpose financial services PII redactor, not a
PW-internal tool. The README should be useful to any RIA, fintech, or developer who
needs to sanitize financial text before sending it to AI models. This broadens adoption,
invites contributions, and builds PW's reputation as a builder in the space.

---

## 1. WHAT THIS SERVICE DOES

pw-redact is a stateless PII redaction API that sits between client-facing data ingestion (pw-portal) and external AI inference (RunPod/Nemotron, Claude API). It ensures no client PII ever reaches third-party model providers.

**Core flow:**
```
Raw client text (transcript, tax return, notes)
        │
        ▼
   pw-redact /v1/redact
   ├── Layer 1: Deterministic regex (SSN, CC, account numbers, EIN)
   ├── Layer 2: Presidio NLP (names, addresses, phone, email, DOB)
   ├── Layer 3: Custom financial recognizers (CUSIP, routing numbers)
   ├── Layer 4: Allow-list (preserve $amounts, %, tax brackets, dates)
   └── Returns: sanitized_text + redaction_manifest
        │
        ▼
   Sanitized text → RunPod/Nemotron or Claude API (safe to send externally)
        │
        ▼
   pw-redact /v1/rehydrate
   ├── Takes: AI model output + redaction_manifest
   └── Returns: output with original values restored for advisor display
```

**Key principles:**
- STATELESS: pw-redact stores nothing. Manifests are returned to the caller.
- DETERMINISTIC FIRST: Regex patterns run before NLP. If regex catches it, NLP doesn't need to.
- FINANCIAL DATA SURVIVES: Dollar amounts, percentages, tax brackets, dates, basis points — these are not PII and must pass through intact for AI models to analyze.
- SINGLE ENFORCEMENT POINT: Every PW service that sends client data externally calls pw-redact first. No exceptions.

---

## 2. ARCHITECTURE

### 2.1 Service Design

```
pw-redact (FastAPI on Fly.io)
├── PRODUCES: /v1/redact — PII redaction endpoint
├── PRODUCES: /v1/rehydrate — placeholder-to-original restoration
├── PRODUCES: /v1/health — health check
├── PRODUCES: /v1/detect — PII detection only (no redaction, returns locations)
├── CONSUMES: Nothing external — fully self-contained
├── AUTH: Internal API key (PW_REDACT_API_KEY) — service-to-service only
└── NOT client-facing — only called by pw-nexus and pw-portal backends
```

### 2.2 Cross-Repo Contracts

```
pw-nexus (CONSUMER) — CONFIRMED: integration patterns match built API
├── Calls POST /v1/redact before sending text to RunPod or Claude API
├── Calls POST /v1/rehydrate after receiving AI model output
├── Uses PW_REDACT_API_KEY for auth (Bearer token in Authorization header)
├── Request format: {"text": "...", "context": "meeting_transcript"}
├── Response format: {"sanitized_text": "...", "manifest": {...}}
└── Env vars: PW_REDACT_URL, PW_REDACT_API_KEY

pw-portal (CONSUMER) — CONFIRMED: integration patterns match built API
├── Calls POST /v1/redact from Go backend when advisor pastes/uploads text
├── Stores redaction_manifest in Neon alongside client_id
├── Calls POST /v1/rehydrate to display results to advisor
├── Rehydrate request: {"text": "...", "manifest": {...}}
├── Rehydrate response: {"rehydrated_text": "..."}
└── Env vars: PW_REDACT_URL, PW_REDACT_API_KEY

pw-redact (PRODUCER — this repo) — DEPLOYED: pw-redact.fly.dev
├── No database — stateless
├── No external API calls — all processing is local
├── spaCy en_core_web_lg loaded at startup via FastAPI lifespan (~560MB)
├── Presidio AnalyzerEngine initialized once, reused per request
├── 30 regex patterns + Presidio NLP + 3 custom recognizers + allow-list
├── 6 document contexts: general, meeting_transcript, tax_return,
│   financial_notes, mortgage, real_estate
├── Endpoints: /v1/redact, /v1/rehydrate, /v1/detect, /v1/health
└── Auth: Bearer token via PW_REDACT_API_KEY (health endpoint is public)
```

### 2.3 File Structure

```
pw-redact/
├── CLAUDE.md                    # This file — build instructions (public)
├── LICENSE                      # Apache 2.0
├── README.md                    # Public-facing docs, usage guide, architecture
├── CONTRIBUTING.md              # How to contribute, code standards
├── CHANGELOG.md                 # Version history
├── pyproject.toml               # Dependencies (uv/pip)
├── Dockerfile                   # Generic deployment container
├── fly.toml.example             # Fly.io template with placeholder values
├── .gitignore                   # MUST include: fly.toml, .env, *.secret
├── .env.example                 # Template with placeholder values
├── .github/
│   └── workflows/
│       └── ci.yml               # Lint + test on push
├── src/
│   └── pw_redact/
│       ├── __init__.py          # Package init with __version__
│       ├── main.py              # FastAPI app, lifespan, routes
│       ├── config.py            # Settings via pydantic-settings
│       ├── auth.py              # API key middleware
│       ├── redactor/
│       │   ├── __init__.py
│       │   ├── engine.py        # PWRedactor class — orchestrates all layers
│       │   ├── regex_patterns.py    # Layer 1: deterministic regex patterns
│       │   ├── presidio_config.py   # Layer 2: Presidio analyzer/anonymizer setup
│       │   ├── financial_recognizers.py  # Layer 3: custom Presidio recognizers
│       │   ├── allow_list.py    # Layer 4: patterns to preserve (not redact)
│       │   └── manifest.py      # Redaction manifest data structures
│       ├── rehydrator/
│       │   ├── __init__.py
│       │   └── engine.py        # Manifest-based placeholder restoration
│       ├── models/
│       │   ├── __init__.py
│       │   ├── requests.py      # Pydantic request models
│       │   └── responses.py     # Pydantic response models
│       └── utils/
│           ├── __init__.py
│           └── logging.py       # Structured logging with PII-safe output
├── tests/
│   ├── __init__.py
│   ├── conftest.py              # Shared fixtures
│   ├── test_redactor.py         # Unit tests for PWRedactor
│   ├── test_regex_patterns.py   # Regex pattern coverage
│   ├── test_financial_recognizers.py
│   ├── test_allow_list.py       # Verify financial data survives
│   └── fixtures/
│       ├── sample_transcript.txt      # SYNTHETIC — no real client data
│       ├── sample_tax_notes.txt       # SYNTHETIC
│       ├── sample_mortgage_notes.txt  # SYNTHETIC
│       └── sample_meeting_notes.txt   # SYNTHETIC
├── examples/
│   ├── quickstart.py            # Minimal usage example
│   ├── fastapi_integration.py   # How to integrate with your own FastAPI app
│   └── standalone_usage.py      # Use PWRedactor as a library without the server
└── docs/
    ├── architecture.md          # Four-layer design explanation
    ├── allow-list-guide.md      # How to customize financial preservation
    └── deployment.md            # Generic deployment guide (Docker, Fly, Railway)
```

---

## 3. API SPECIFICATION

### 3.1 POST /v1/redact

**Purpose:** Accept raw text, return sanitized text with PII replaced by consistent placeholders.

**Request:**
```json
{
  "text": "John Smith discussed his AGI of 425,000 with advisor. His SSN is 123-45-6789. His wife Colleen has W2 income of 95,000. They live at 42 Oak Lane, Havertown PA 19083.",
  "context": "meeting_transcript",
  "options": {
    "preserve_amounts": true,
    "preserve_dates": true,
    "preserve_percentages": true,
    "redaction_style": "placeholder"
  }
}
```

**`context` values:** `meeting_transcript` | `tax_return` | `financial_notes` | `general`
Each context tunes which recognizers are more/less aggressive.

**`redaction_style` values:**
- `placeholder` — `<PERSON_1>`, `<LOCATION_1>`, `<US_SSN_1>` (default, best for AI processing)
- `masked` — `***MASKED***` (for logging/display)
- `synthetic` — replace with realistic fake data (for testing/demos)

**Response:**
```json
{
  "sanitized_text": "<PERSON_1> discussed his AGI of 425,000 with advisor. His SSN is <US_SSN_1>. His wife <PERSON_2> has W2 income of 95,000. They live at <LOCATION_1>.",
  "manifest": {
    "version": "1.0",
    "redaction_id": "red_a1b2c3d4",
    "placeholders": [
      {"placeholder": "<PERSON_1>", "original": "John Smith", "entity_type": "PERSON", "start": 0, "end": 10},
      {"placeholder": "<US_SSN_1>", "original": "123-45-6789", "entity_type": "US_SSN", "start": 67, "end": 78},
      {"placeholder": "<PERSON_2>", "original": "Colleen", "entity_type": "PERSON", "start": 89, "end": 96},
      {"placeholder": "<LOCATION_1>", "original": "42 Oak Lane, Havertown PA 19083", "entity_type": "LOCATION", "start": 128, "end": 159}
    ],
    "stats": {
      "entities_found": 4,
      "entities_by_type": {"PERSON": 2, "US_SSN": 1, "LOCATION": 1},
      "text_length_original": 165,
      "text_length_sanitized": 148
    }
  }
}
```

### 3.2 POST /v1/rehydrate

**Purpose:** Take AI model output + manifest, restore original values.

**Request:**
```json
{
  "text": "Based on the data, <PERSON_1> should consider a Roth conversion. <PERSON_2>'s W2 income of 95,000 combined with rental income puts them in the 32% bracket.",
  "manifest": { ... }
}
```

**Response:**
```json
{
  "rehydrated_text": "Based on the data, John Smith should consider a Roth conversion. Colleen's W2 income of 95,000 combined with rental income puts them in the 32% bracket."
}
```

### 3.3 POST /v1/detect

**Purpose:** Detect PII locations without redacting. Used for UI highlighting.

**Request:**
```json
{
  "text": "John Smith's SSN is 123-45-6789.",
  "context": "general"
}
```

**Response:**
```json
{
  "entities": [
    {"entity_type": "PERSON", "text": "John Smith", "start": 0, "end": 10, "score": 0.95},
    {"entity_type": "US_SSN", "text": "123-45-6789", "start": 20, "end": 31, "score": 1.0}
  ]
}
```

### 3.4 GET /v1/health

Returns `{"status": "healthy", "version": "0.1.0", "models_loaded": true}`.

---

## 4. IMPLEMENTATION DETAILS

### 4.1 Layer 1: Deterministic Regex Patterns (regex_patterns.py)

Port these patterns from pw-nexus `mask_sensitive_data()` and extend:

```python
PATTERNS = {
    # === EXISTING (from pw-nexus) ===
    "US_SSN": r'\b\d{3}[- ]?\d{2}[- ]?\d{4}\b',
    "CREDIT_CARD": r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
    "API_KEY": r'["\']?(?:api[_-]?key|apikey)["\']?\s*[=:]\s*["\']?([A-Za-z0-9._-]{10,})["\']?',
    "BEARER_TOKEN": r'Bearer\s+([A-Za-z0-9._-]{20,})',
    "JWT": r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
    "DB_URL": r'(postgres|mysql|mongodb|redis)://[^:]+:[^@]+@',

    # === NEW (financial advisory specific) ===
    "US_PHONE": r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
    "US_ROUTING": r'\b[0-9]{9}\b',  # ABA routing number (9 digits)
    "ACCOUNT_NUMBER": r'\b(?:acct?\.?\s*(?:#|no\.?|number)?:?\s*)(\d{6,17})\b',
    "EIN": r'\b\d{2}[- ]?\d{7}\b',  # Employer ID Number
    "US_PASSPORT": r'\b[A-Z]?\d{8,9}\b',
    "EMAIL": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    "DATE_OF_BIRTH": r'\b(?:DOB|born|birthday|date of birth)[:\s]*(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})\b',
}
```

**Regex runs FIRST** — high-confidence, zero false positives for structured patterns like SSN/CC/EIN. Results feed into Presidio as pre-detected entities (no double-processing).

### 4.2 Layer 2: Presidio NLP Configuration (presidio_config.py)

```python
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine

def create_analyzer() -> AnalyzerEngine:
    """Initialize Presidio analyzer with spaCy NLP backend."""
    nlp_config = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}]
    }
    nlp_engine = NlpEngineProvider(nlp_configuration=nlp_config).create_engine()

    registry = RecognizerRegistry()
    registry.load_predefined_recognizers(nlp_engine=nlp_engine)

    # Add custom financial recognizers (Layer 3)
    from .financial_recognizers import get_financial_recognizers
    for recognizer in get_financial_recognizers():
        registry.add_recognizer(recognizer)

    return AnalyzerEngine(nlp_engine=nlp_engine, registry=registry)
```

**Presidio entity types to enable:**
- `PERSON` — names (critical for meeting transcripts)
- `LOCATION` — addresses
- `PHONE_NUMBER` — phone numbers
- `EMAIL_ADDRESS` — emails
- `US_SSN` — Social Security (backup to regex)
- `CREDIT_CARD` — credit cards (backup to regex)
- `DATE_TIME` — only when flagged as DOB, not general dates
- `NRP` — nationalities/religious/political groups (redact in advisory context)

**Presidio entity types to DISABLE (allow-listed):**
- `US_BANK_NUMBER` — too many false positives with dollar amounts
- Generic number recognition — financial data must survive

### 4.3 Layer 3: Custom Financial Recognizers (financial_recognizers.py)

Build custom Presidio `PatternRecognizer` instances for:

```python
from presidio_analyzer import PatternRecognizer, Pattern

def get_financial_recognizers():
    """Return list of custom recognizers for financial advisory context."""
    recognizers = []

    # CUSIP (9 chars: 6 alpha + 2 alphanum + 1 check digit)
    cusip = PatternRecognizer(
        supported_entity="CUSIP",
        patterns=[Pattern("cusip", r'\b[A-Z0-9]{6}[A-Z0-9]{2}[0-9]\b', 0.6)],
        context=["cusip", "security", "holding", "fund"]
    )
    recognizers.append(cusip)

    # Account reference patterns ("account ending in 7890")
    account_ref = PatternRecognizer(
        supported_entity="ACCOUNT_REF",
        patterns=[Pattern("acct_ref", r'(?:account|acct)[\s#]*(?:ending\s+in\s+)?(\d{4,})', 0.7)],
    )
    recognizers.append(account_ref)

    # Client ID / Policy numbers
    policy = PatternRecognizer(
        supported_entity="POLICY_NUMBER",
        patterns=[Pattern("policy", r'(?:policy|plan|contract)[\s#:]*([A-Z0-9]{6,20})', 0.6)],
    )
    recognizers.append(policy)

    return recognizers
```

### 4.4 Layer 4: Allow-List — Financial Data That MUST Survive (allow_list.py)

This is critical. Without the allow-list, Presidio will redact dollar amounts, percentages, and tax bracket numbers — destroying the data the AI model needs.

```python
from presidio_analyzer import PatternRecognizer, Pattern

def get_allow_list_patterns():
    """Patterns that should NEVER be redacted — financial data, not PII."""
    return [
        # Dollar amounts: $425,000 or 425000 or $50k
        r'\$[\d,]+(?:\.\d{2})?(?:k|K|M|B)?',
        r'\b\d{1,3}(?:,\d{3})*(?:\.\d{2})?\b',  # plain numbers with commas

        # Percentages: 32%, 6.75%, 0.95
        r'\b\d+\.?\d*\s*%',

        # Tax brackets / rates: "32% bracket", "24% rate"
        r'\b(?:10|12|22|24|32|35|37)\s*%\s*(?:bracket|rate|tier)',

        # Basis points: "250 bps", "50bp"
        r'\b\d+\s*(?:bps?|basis\s+points?)\b',

        # Years: 2024, 2025, 2032 (not DOBs, just planning years)
        r'\b20[2-9]\d\b',

        # Ages: "age 59.5", "turning 70.5", "age 65"
        r'\bage\s+\d{1,3}(?:\.\d)?\b',

        # Form numbers: "Form 1040", "Schedule D", "Form 8275"
        r'\b(?:Form|Schedule|IRC\s*§?)\s*[A-Z0-9.-]+\b',

        # Financial acronyms: AGI, MAGI, QBI, RMD, QCD, etc.
        r'\b(?:AGI|MAGI|QBI|RMD|QCD|NUA|IRA|SEP|SIMPLE|401k|403b|457b|529|HSA|FSA)\b',
    ]
```

The allow-list works by running AFTER Presidio detection: any detected entity whose text matches an allow-list pattern gets removed from the redaction candidates.

### 4.5 PWRedactor Engine (engine.py)

The main orchestrator class:

```python
class PWRedactor:
    """
    Protocol Wealth PII Redactor.

    Orchestrates four-layer redaction:
    1. Deterministic regex (high-confidence structured PII)
    2. Presidio NLP (names, addresses, contextual PII)
    3. Custom financial recognizers (CUSIP, account refs, policy numbers)
    4. Allow-list filtering (preserve financial data)

    Returns sanitized text + manifest for later rehydration.
    """

    def __init__(self):
        self.regex_patterns = compile_regex_patterns()
        self.analyzer = create_analyzer()
        self.anonymizer = AnonymizerEngine()
        self.allow_patterns = compile_allow_patterns()
        self._placeholder_counters: dict[str, int] = {}

    def redact(self, text: str, context: str = "general", options: dict = None) -> RedactionResult:
        """
        Redact PII from text.

        Args:
            text: Raw input text potentially containing PII
            context: One of 'meeting_transcript', 'tax_return', 'financial_notes', 'general'
            options: Override default preservation/style settings

        Returns:
            RedactionResult with sanitized_text and manifest
        """
        # Step 1: Regex detection
        regex_entities = self._detect_regex(text)

        # Step 2: Presidio NLP detection
        presidio_entities = self.analyzer.analyze(
            text=text,
            entities=self._get_entities_for_context(context),
            language="en",
            allow_list=self._get_allow_terms(text),
        )

        # Step 3: Merge detections, deduplicate, resolve overlaps
        # Regex wins on overlap (higher confidence for structured patterns)
        all_entities = self._merge_entities(regex_entities, presidio_entities)

        # Step 4: Apply allow-list filter
        filtered_entities = self._apply_allow_list(text, all_entities)

        # Step 5: Generate consistent placeholders and build manifest
        sanitized_text, manifest = self._anonymize(text, filtered_entities)

        return RedactionResult(
            sanitized_text=sanitized_text,
            manifest=manifest,
        )

    def _get_entities_for_context(self, context: str) -> list[str]:
        """Return which entity types to detect based on document context."""
        base = ["PERSON", "LOCATION", "PHONE_NUMBER", "EMAIL_ADDRESS", "US_SSN"]
        if context == "meeting_transcript":
            return base + ["ACCOUNT_REF", "POLICY_NUMBER"]
        elif context == "tax_return":
            return base + ["EIN", "ACCOUNT_REF", "US_ITIN"]
        elif context == "financial_notes":
            return base + ["CUSIP", "ACCOUNT_REF", "POLICY_NUMBER"]
        return base
```

### 4.6 Placeholder Consistency

Placeholders MUST be consistent within a document:
- First person detected → `<PERSON_1>`, second → `<PERSON_2>`
- Same name appearing multiple times → always same placeholder
- This allows AI models to understand entity relationships ("PERSON_1 is married to PERSON_2")

Implementation: maintain a `{original_text → placeholder}` dictionary during redaction. If the same text appears again, reuse the same placeholder.

---

## 5. DEPLOYMENT

### 5.1 Dockerfile

```dockerfile
FROM python:3.12-slim

WORKDIR /app

# Install system deps for spaCy
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps
COPY pyproject.toml .
RUN pip install --no-cache-dir -e ".[prod]"

# Download spaCy model at build time (not runtime)
RUN python -m spacy download en_core_web_lg

COPY src/ src/

EXPOSE 8080

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "2"]
```

### 5.2 fly.toml.example (committed to repo — generic template)

```toml
# Copy to fly.toml and customize for your deployment
# DO NOT commit fly.toml — it's in .gitignore
app = "your-app-name"
primary_region = "ewr"  # Pick closest region

[build]

[http_service]
  internal_port = 8080
  force_https = true
  auto_stop_machines = "suspend"
  auto_start_machines = true
  min_machines_running = 0

[vm]
  memory = "1gb"
  cpu_kind = "shared"
  cpus = 2

[checks]
  [checks.health]
    port = 8080
    type = "http"
    interval = "30s"
    timeout = "5s"
    path = "/v1/health"
```

### 5.3 .gitignore (critical for open-source safety)

```gitignore
# Private deployment config — NEVER commit
fly.toml
.env
*.secret

# Python
__pycache__/
*.pyc
.venv/
dist/
*.egg-info/

# IDE
.idea/
.vscode/
*.swp

# OS
.DS_Store
Thumbs.db
```

**Note:** 1GB RAM may be tight with en_core_web_lg (~560MB loaded). Monitor memory at startup. If needed, bump to 2GB or use en_core_web_md (~40MB, slightly less accurate on names). Start with `en_core_web_lg` and only downgrade if memory is a problem.

### 5.4 .env.example (committed to repo — template)

```bash
# Copy to .env and fill in real values
# DO NOT commit .env — it's in .gitignore

# Required
PW_REDACT_API_KEY=change-me-to-a-strong-random-key

# Optional
LOG_LEVEL=info
SPACY_MODEL=en_core_web_lg    # Options: en_core_web_lg (best), en_core_web_md (lighter)
ENVIRONMENT=development        # production | development
MAX_REQUEST_SIZE_MB=1          # Max request body in MB
```

---

## 6. AUTHENTICATION

Internal service-to-service only. Simple API key in the `Authorization` header:

```python
# src/auth.py
from fastapi import Header, HTTPException

async def verify_api_key(authorization: str = Header(...)):
    """Verify internal service API key."""
    expected = settings.pw_redact_api_key
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid auth format")
    token = authorization.removeprefix("Bearer ")
    if token != expected:
        raise HTTPException(status_code=403, detail="Invalid API key")
```

**NOT** OAuth, NOT JWT, NOT user-facing. This service is only called by pw-nexus and pw-portal backends. A strong random API key is sufficient and avoids unnecessary complexity.

---

## 7. TESTING REQUIREMENTS

### 7.1 Mandatory Test Cases

**PII Detection (must catch):**
- Full names: "John Smith", "Dr. Jane Doe", "Colleen Rygiel"
- SSN formats: "123-45-6789", "123 45 6789", "123456789"
- Phone: "(610) 555-1234", "610.555.1234", "+1-610-555-1234"
- Email: "john@example.com"
- Address: "42 Oak Lane, Havertown PA 19083"
- Account numbers: "account #12345678", "acct ending in 7890"
- EIN: "12-3456789"
- Credit card: "4111 1111 1111 1111"

**Financial Preservation (must NOT redact):**
- Dollar amounts: "$425,000", "$50k", "95,000"
- Percentages: "32%", "6.75%", "0.95"
- Tax brackets: "32% bracket", "24% rate"
- Planning years: "2032", "2026"
- Form references: "Form 1040", "Schedule D", "IRC §1015"
- Financial acronyms: "AGI", "QCD", "RMD", "529 plan"
- Ages/milestones: "age 70.5", "turning 59.5"

**Round-trip tests (redact → rehydrate):**
- Redact a sample transcript → verify manifest → rehydrate → compare to original
- Verify placeholder consistency (same name → same placeholder throughout)
- Verify no data loss in rehydration

**Context-specific tests:**
- `meeting_transcript` context detects names aggressively
- `tax_return` context detects EINs and ITINs
- Allow-list is properly applied across all contexts

### 7.2 Test Fixtures

Create realistic test fixtures in `tests/fixtures/`:

**sample_transcript.txt:**
```
Advisor: Good morning John, how are you and Colleen doing?
Client: Great, thanks. So our AGI last year was about 425,000 and Colleen's W2 was 95,000. The rental at 42 Oak Lane in Havertown is bringing in about 24,000.
Advisor: Perfect. With that income, you're solidly in the 32% bracket. I think we should consider a Roth conversion of about 50,000 this year. Also, Patrick starts college in 2032 — we should max out the 529.
Client: Sounds good. My SSN is 123-45-6789 if you need it for the paperwork. And can you look into refinancing our VA loan? Current rate is 6.75%.
```

**Expected sanitized output:**
```
Advisor: Good morning <PERSON_1>, how are you and <PERSON_2> doing?
Client: Great, thanks. So our AGI last year was about 425,000 and <PERSON_2>'s W2 was 95,000. The rental at <LOCATION_1> is bringing in about 24,000.
Advisor: Perfect. With that income, you're solidly in the 32% bracket. I think we should consider a Roth conversion of about 50,000 this year. Also, <PERSON_3> starts college in 2032 — we should max out the 529.
Client: Sounds good. My SSN is <US_SSN_1> if you need it for the paperwork. And can you look into refinancing our VA loan? Current rate is 6.75%.
```

---

## 8. DEPENDENCIES

### pyproject.toml

```toml
[project]
name = "pw-redact"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
    "fastapi>=0.115.0",
    "uvicorn[standard]>=0.30.0",
    "pydantic>=2.9.0",
    "pydantic-settings>=2.5.0",
    "presidio-analyzer>=2.2.0",
    "presidio-anonymizer>=2.2.0",
    "spacy>=3.7.0",
    "structlog>=24.0.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0.0",
    "pytest-asyncio>=0.24.0",
    "httpx>=0.27.0",
    "ruff>=0.7.0",
]
prod = []
```

**Post-install:** `python -m spacy download en_core_web_lg`

---

## 9. CONSUMER INTEGRATION GUIDE

> **Note:** This section is for Claude Code building pw-nexus and pw-portal integrations.
> It references internal PW services. The public README uses generic examples instead.

### 9.1 pw-nexus Integration (Python)

```python
# In pw-nexus MCP tool
import httpx

PW_REDACT_URL = os.getenv("PW_REDACT_URL")
PW_REDACT_KEY = os.getenv("PW_REDACT_API_KEY")

async def redact_text(text: str, context: str = "meeting_transcript") -> dict:
    """Redact PII via pw-redact service."""
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{PW_REDACT_URL}/v1/redact",
            json={"text": text, "context": context},
            headers={"Authorization": f"Bearer {PW_REDACT_KEY}"},
            timeout=30.0,
        )
        response.raise_for_status()
        return response.json()

async def rehydrate_text(text: str, manifest: dict) -> str:
    """Restore PII placeholders from manifest."""
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{PW_REDACT_URL}/v1/rehydrate",
            json={"text": text, "manifest": manifest},
            headers={"Authorization": f"Bearer {PW_REDACT_KEY}"},
            timeout=10.0,
        )
        response.raise_for_status()
        return response.json()["rehydrated_text"]
```

### 9.2 pw-portal Integration (Go)

```go
// In pw-portal backend handler
func (s *MeetingService) RedactText(ctx context.Context, text, docContext string) (*RedactResponse, error) {
    payload := map[string]interface{}{
        "text":    text,
        "context": docContext,
    }
    body, _ := json.Marshal(payload)

    req, _ := http.NewRequestWithContext(ctx, "POST",
        s.redactURL+"/v1/redact", bytes.NewReader(body))
    req.Header.Set("Authorization", "Bearer "+s.redactKey)
    req.Header.Set("Content-Type", "application/json")

    resp, err := s.httpClient.Do(req)
    // ... handle response
}
```

---

## 10. SECURITY REQUIREMENTS

1. **No logging of original PII.** Log sanitized text only. The `utils/logging.py` module must mask any PII that leaks into log output.
2. **No disk writes.** pw-redact never writes input text, manifests, or intermediate results to disk. Everything is in-memory, per-request.
3. **No external network calls.** pw-redact calls nothing outside its own process. spaCy model is loaded from the Docker image filesystem. Presidio runs locally.
4. **API key rotation.** PW_REDACT_API_KEY should be rotatable via `fly secrets set` without service restart (FastAPI reads from env on each request or via pydantic-settings reload).
5. **Request size limits.** Max request body: 1MB (covers transcripts up to ~250K words). Reject larger payloads with 413.
6. **Rate limiting.** Not required for V1 (internal service only) but add a simple token-bucket if exposed externally later.
7. **TLS only.** Fly.io handles TLS termination. The `force_https = true` in fly.toml enforces this.

---

## 11. PERFORMANCE TARGETS

| Metric | Target | Notes |
|--------|--------|-------|
| Latency (short text, <500 words) | <500ms | Regex + Presidio on warm engine |
| Latency (long transcript, 5000 words) | <3s | spaCy NER is the bottleneck |
| Cold start (Fly.io machine resume) | <10s | spaCy model load dominates |
| Memory usage | <1.5GB | spaCy en_core_web_lg is ~560MB |
| Concurrent requests | 10+ | 2 uvicorn workers, async handlers |

---

## 12. FUTURE EXTENSIONS (NOT V1)

- **Document type auto-detection:** Infer context from content (is this a transcript? tax return? estate doc?)
- **Batch endpoint:** POST /v1/redact/batch for processing multiple documents
- **Confidence thresholds:** Let callers specify minimum confidence for redaction (e.g., only redact PERSON entities with score > 0.8)
- **Custom entity types:** Allow pw-nexus to register new entity patterns via API
- **Metrics endpoint:** Prometheus metrics for monitoring redaction rates, entity type distributions
- **Google Drive integration:** Pull transcripts directly from Drive, redact, return (currently pw-nexus or pw-portal handles this)

---

## 13. BUILD SEQUENCE

When Claude Code builds this repo, follow this order:

1. **Scaffold** — pyproject.toml, Dockerfile, fly.toml.example, .env.example, .gitignore, LICENSE (Apache 2.0), directory structure
2. **README.md** — public-facing documentation (see §14 below)
3. **Config** — pydantic-settings, env var loading, auth middleware
4. **Layer 1** — regex_patterns.py with all patterns, unit tests
5. **Layer 2** — presidio_config.py, spaCy setup, unit tests
6. **Layer 3** — financial_recognizers.py, unit tests
7. **Layer 4** — allow_list.py with financial preservation patterns, unit tests
8. **Engine** — PWRedactor class orchestrating all layers, integration tests
9. **Rehydrator** — manifest-based restoration, round-trip tests
10. **API** — FastAPI routes, request/response models, API tests
11. **Fixtures** — sample transcripts and expected outputs (SYNTHETIC only)
12. **Examples** — quickstart.py, standalone_usage.py, fastapi_integration.py
13. **CI** — GitHub Actions workflow (lint + test)
14. **Docs** — architecture.md, allow-list-guide.md, deployment.md
15. **CONTRIBUTING.md** — code standards, PR process, test requirements
16. **Deploy** — fly launch (private), fly secrets set, verify /v1/health

### Build Notes (2026-03-27 actual build)

**What was built:** Steps 1-10, 15-16 completed. Steps 11 (fixtures) done inline
with step 8. Steps 12-14 deferred (examples/, docs/, CI workflow not yet created).

**Deviations from spec:**
- Dockerfile needed `COPY src/` before `pip install` (not after). Editable install
  (`-e`) doesn't work without source present; switched to `pip install "."` for production.
- 2GB RAM required on Fly.io. 1GB OOMs during spaCy model load (~560MB resident).
- `en_core_web_lg` spaCy model installed via direct wheel URL with `uv pip install`
  since `python -m spacy download` requires pip (not present in uv venvs).
- API_KEY regex pattern needed `(?i)` flag to catch uppercase env vars like
  `STRIPE_API_KEY=...`. The spec's pattern was case-sensitive.
- ACCOUNT_NUMBER regex needed `account` (full word) in addition to `acc`/`acct`.
- US_ROUTING pattern restricted to context keywords (routing/aba/transit) + ABA
  first-digit constraint ([0-3]) rather than the spec's bare `\b[0-9]{9}\b` which
  caused massive false positives.
- DRIVERS_LICENSE pattern restricted to context keywords (driver/DL) rather than
  bare `\b[A-Z]\d{7,14}\b` which matched nearly any alphanumeric reference.
- CRM_ID and PLATFORM_ID generalized from pw-nexus vendor-specific patterns
  (Wealthbox, Turnkey) to vendor-agnostic context keywords.
- Added 7 mortgage/RE patterns, 3 crypto patterns, and 4 secret patterns beyond
  the original spec, backported from pw-nexus mcp_pii_filter.py and secure_logging.py.
- `mortgage` and `real_estate` document contexts added (not in original spec).
- spaCy detects "John Smith's" (with possessive) as the full PERSON entity span.
  README examples updated to match actual behavior.
- "max" in "max out the 529" detected as PERSON by spaCy — known NLP limitation
  with common-word names. Acceptable for V1 (over-redacting is safer than under-redacting).

---

## 14. README.md SPECIFICATION

The README is the public face of the project. It should be clear, professional, and
useful to anyone in financial services who needs PII redaction for AI pipelines.

### Structure:

```markdown
# pw-redact

**Open-source PII redaction engine for financial services AI pipelines.**

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

[Four-layer architecture diagram]

1. **Regex Layer** — Catches structured PII (SSNs, credit cards, EINs) with zero false positives
2. **NLP Layer** — Presidio + spaCy detect names, addresses, phone numbers in natural language
3. **Financial Recognizers** — Custom patterns for CUSIPs, account references, policy numbers
4. **Allow-List** — Preserves dollar amounts, percentages, tax brackets, and financial
   terms that AI models need for analysis

## Quick Start

[pip install, basic usage example, Docker example]

## API Reference

[Endpoint docs for /v1/redact, /v1/rehydrate, /v1/detect]

## Use Cases

- Meeting transcript sanitization before AI summarization
- Tax return data extraction with PII stripped
- Financial document processing for AI analysis
- Compliance-safe AI integration for RIAs and broker-dealers

## Deployment

[Docker, Fly.io, Railway, or any container platform]

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)

## License

Apache 2.0 — free for commercial use.

## Built By

Protocol Wealth LLC — SEC-registered investment adviser building transparent
AI infrastructure for the advisory industry.
```

### README tone:
- Professional but accessible — a compliance officer should understand it
- Technical enough for developers to evaluate and adopt
- NOT marketing-heavy — let the code speak
- Include badges: CI status, license, Python version, PyPI (when published)

---

## 15. CONTRIBUTING.md SPECIFICATION

```markdown
# Contributing to pw-redact

## Code Standards
- Python 3.12+, type hints on all public functions
- Ruff for linting and formatting
- 90%+ test coverage for redactor module
- Every regex pattern must have at least 3 test cases (match + non-match)

## Adding New Entity Types
1. Add pattern to `regex_patterns.py` or create a recognizer in `financial_recognizers.py`
2. Add corresponding test cases
3. Verify allow-list doesn't conflict (financial data must still survive)
4. Update README if the new entity type is user-facing

## Adding Allow-List Patterns
1. Add pattern to `allow_list.py`
2. Add test case proving the pattern is preserved through redaction
3. Add test case proving actual PII near the pattern is still caught

## Pull Request Process
1. Fork and branch from `main`
2. All tests must pass: `pytest`
3. Lint must pass: `ruff check .`
4. Include test cases for any new functionality
5. Update CHANGELOG.md
```

---

*Protocol Wealth LLC | SEC-Registered Investment Adviser (CRD #335298)*
*pw-redact is open-source infrastructure under Apache 2.0.*
*Internal deployment config is private. Code and logic are public.*
