# Changelog

All notable changes to pw-redact will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [0.1.0] - 2026-03-27

### Added
- Initial release: four-layer PII redaction engine (regex, Presidio NLP, financial recognizers, allow-list)
- FastAPI server with `/v1/redact`, `/v1/rehydrate`, `/v1/detect`, `/v1/health` endpoints
- 30 deterministic regex patterns across 6 categories:
  - **PII**: SSN, credit card, email, phone, EIN, DOB, account numbers, driver's license, street address, routing numbers
  - **Secrets**: JWT, API keys, passwords, secrets/credentials, auth tokens, bearer tokens, DB URLs, magic links
  - **Crypto**: Ethereum private keys (0x+64 hex), wallet addresses (0x+40 hex), seed phrases/mnemonics
  - **Mortgage/RE**: NMLS IDs, loan numbers, MERS MIN, FHA/VA/USDA case numbers, APN/parcel numbers, MLS numbers, escrow/title/instrument file references
  - **System IDs**: CRM record IDs, platform/infrastructure IDs (vendor-agnostic)
- Presidio NLP detection with spaCy `en_core_web_lg` for names, addresses, and contextual entities
- Custom Presidio recognizers for CUSIP, account references, and policy numbers
- Financial data allow-list preserving dollar amounts, percentages, tax brackets, basis points, years, ages, form references, and 60+ financial/mortgage/RE acronyms
- Consistent placeholder generation (`<PERSON_1>`, `<US_SSN_1>`, etc.) with manifest for round-trip rehydration
- 6 document contexts: `meeting_transcript`, `tax_return`, `financial_notes`, `mortgage`, `real_estate`, `general`
- API key authentication (Bearer token, service-to-service)
- 223 tests (regex patterns, financial recognizers, allow-list, integration, round-trip)
- Docker and Fly.io deployment support
- Sample test fixtures: meeting transcript, tax notes, meeting notes, mortgage pre-qualification
- Apache 2.0 license
