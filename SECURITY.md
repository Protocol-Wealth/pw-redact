# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in pw-redact, **please report it responsibly**.

**Email:** [security@protocolwealthllc.com](mailto:security@protocolwealthllc.com)

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

**Do NOT** open a public GitHub issue for security vulnerabilities.

We will acknowledge receipt within 48 hours and provide a timeline for a fix.
Security patches are released as soon as possible, typically within 7 days.

## Scope

This policy covers the pw-redact codebase and its dependencies. It does **not**
cover Protocol Wealth's private infrastructure or other services.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Security Design

pw-redact is designed with the following security principles:

### Data Handling
- **Stateless**: pw-redact stores nothing. No input text, manifests, or intermediate
  results are written to disk or persisted in memory between requests.
- **No external calls**: All processing is local. spaCy models are loaded from the
  Docker image filesystem. No data leaves the process boundary.
- **No logging of PII**: The logging module masks any PII that reaches log output.

### Input Protection
- Input size limits (1MB / 50,000 lines) prevent resource exhaustion
- Invisible Unicode characters (zero-width spaces, bidi overrides) are stripped
  to prevent hidden instruction injection
- HTML/script elements are stripped
- Base64-encoded blocks >200 chars are flagged (potential encoded instructions)

### Prompt Injection Detection
- 25 regex patterns detect known injection phrases, encoded variants, and
  delimiter manipulation attempts
- Detection is **advisory only** — results are returned to the caller for
  policy decisions, not silently blocked
- Zero false positives verified against sample financial documents

### Authentication
- Bearer token authentication on all endpoints except `/v1/health`
- Tokens should be rotated regularly via your deployment platform's secrets management

### Rate Limiting
- In-memory token bucket prevents abuse (default: 60 RPM, 10 burst)
- Returns 429 with Retry-After header

## Dependencies

We monitor dependencies for known vulnerabilities. Key dependencies:
- [Presidio](https://github.com/microsoft/presidio) — Microsoft's PII detection engine
- [spaCy](https://spacy.io/) — NLP pipeline
- [FastAPI](https://fastapi.tiangolo.com/) — Web framework
- [Pydantic](https://pydantic.dev/) — Data validation

## Acknowledgments

We credit all security researchers who responsibly disclose vulnerabilities.
