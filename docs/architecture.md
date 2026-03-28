# Architecture

pw-redact uses a four-layer pipeline where each layer serves a distinct role.
Layers run in sequence; earlier layers have higher confidence and lower latency.

## Pipeline Overview

```
                         Input Text
                             |
                     [ Input Validator ]
                     Strip control chars, invisible Unicode,
                     HTML, base64 blocks, external images
                             |
                  [ Prompt Injection Detector ]
                  Score 0.0-1.0, flag if > 0.7
                  (advisory only — does not block)
                             |
          +------------------+------------------+
          |                                     |
   [ Layer 1: Regex ]                  [ Layer 2: Presidio NLP ]
   30 deterministic patterns           spaCy en_core_web_lg NER
   SSN, CC, EIN, secrets,             Names, addresses, phone,
   crypto, mortgage IDs               email, contextual entities
   Score: 0.70-1.00                   Score: 0.50-0.95
          |                                     |
          +------------------+------------------+
                             |
                    [ Merge & Deduplicate ]
                    Regex wins on overlap ties
                    Higher score wins otherwise
                             |
                 [ Layer 3: Financial Recognizers ]
                 Custom Presidio PatternRecognizers
                 CUSIP, account refs, policy numbers
                 (already in Presidio results)
                             |
                    [ Layer 4: Allow-List ]
                    Remove detections matching
                    financial data patterns
                    ($amounts, %, years, acronyms)
                             |
                   [ Placeholder Generation ]
                   Consistent per-document mapping
                   Same text -> same placeholder
                             |
                   [ Output Validator ]
                   Verify no PII leaked
                   Validate placeholder format
                             |
                 { sanitized_text + manifest }
```

## Layer Details

### Layer 1: Deterministic Regex

**File:** `src/pw_redact/redactor/regex_patterns.py`

30 compiled regex patterns organized by category. Each pattern has a confidence
score (0.0-1.0) and an optional capture group for extracting just the sensitive
value from context-dependent patterns.

Regex runs first because:
- Zero false positives for structured patterns (SSN, CC, JWT)
- Sub-millisecond execution on any text length
- Results feed into the merge step as high-confidence anchors

**Key design decision:** Context-dependent patterns (US_ROUTING, DRIVERS_LICENSE,
NMLS_ID, etc.) require keyword context to avoid false positives on bare numbers.
For example, US_ROUTING requires "routing", "aba", or "transit" nearby, rather
than matching any 9-digit number.

### Layer 2: Presidio NLP

**File:** `src/pw_redact/redactor/presidio_config.py`

Microsoft Presidio with spaCy `en_core_web_lg` backend. Detects entities that
regex can't — primarily person names and unstructured addresses.

Entity selection is context-dependent:
- `meeting_transcript`: All entities + NRP (nationality/religion/politics)
- `financial_notes`: All entities + CUSIP
- `mortgage`: All entities + NRP + account refs + policy numbers
- `general`: Core entities only (PERSON, LOCATION, PHONE, EMAIL, SSN, CC)

### Layer 3: Custom Recognizers

**File:** `src/pw_redact/redactor/financial_recognizers.py`

Three Presidio `PatternRecognizer` instances for financial-specific entities
that Presidio's built-in recognizers don't cover: CUSIP, ACCOUNT_REF, POLICY_NUMBER.

### Layer 4: Allow-List

**File:** `src/pw_redact/redactor/allow_list.py`

Two mechanisms work together:
1. **Regex patterns** — checked via `re.fullmatch()` against detected entity text.
   If a detected "entity" is actually a dollar amount, percentage, year, etc.,
   it's removed from the redaction list.
2. **Literal terms** — passed to Presidio's `allow_list` parameter to prevent
   NLP detection of financial acronyms (AGI, RMD, LTV, etc.) as person names.

## Merge Algorithm

When regex and Presidio both detect entities, overlapping detections are resolved:

1. All detections sorted by `(start_position, -score, source_priority)`
2. Regex entities get source_priority=0 (preferred on ties)
3. NLP entities get source_priority=1
4. For overlapping spans, higher score wins
5. On equal score, longer span preferred
6. On equal score and span, regex wins (deterministic > probabilistic)

## Placeholder Consistency

Placeholders are generated per-request using a `{original_text -> placeholder}`
dictionary. The first occurrence of "John Smith" gets `<PERSON_1>`, and every
subsequent occurrence reuses the same placeholder. This preserves entity
relationships for AI models ("PERSON_1 is married to PERSON_2").

## Security Pipeline

The security layer wraps the redaction pipeline:

```
Request -> Rate Limiter -> Input Validator -> Injection Detector
                                                    |
                                             Redaction Pipeline
                                                    |
                                            Output Validator -> Response
```

Security results are included in the response (not silently applied) so callers
can implement their own policy decisions.

## Stateless Design

pw-redact stores nothing between requests:
- No database
- No disk writes
- No external API calls
- No request caching
- No session state

Manifests are returned to the caller, who is responsible for storage (typically
alongside the client record in their own database).
