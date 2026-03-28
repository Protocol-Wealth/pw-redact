# Contributing to pw-redact

Thank you for your interest in contributing! pw-redact is open-source infrastructure
for financial services PII redaction. Contributions from the fintech and advisory
community are welcome.

**Security issues:** Do not open public issues. Email [security@protocolwealthllc.com](mailto:security@protocolwealthllc.com). See [SECURITY.md](SECURITY.md).

## Code Standards

- Python 3.12+, type hints on all public functions
- Ruff for linting and formatting (`ruff check src/`)
- Every regex pattern must have at least 3 test cases (match + non-match + extracted text)
- Apache 2.0 license header on every `.py` file:
  ```python
  # Copyright 2026 Protocol Wealth LLC
  # Licensed under the Apache License, Version 2.0
  # https://github.com/Protocol-Wealth/pw-redact
  ```

## Adding New Entity Types

1. Add pattern to `regex_patterns.py` (with `_PatternDef` including score and optional group)
2. Add corresponding test cases in `tests/test_regex_patterns.py`
3. Verify allow-list doesn't conflict (financial data must still survive)
4. Run full test suite: `pytest tests/ -v`
5. Update README.md "Supported Entity Types" table

## Adding Presidio Recognizers

1. Create a `PatternRecognizer` in `financial_recognizers.py`
2. Add the entity type to relevant context lists in `engine.py` (`_CONTEXT_ENTITIES`)
3. Add test cases in `tests/test_financial_recognizers.py`
4. Run full test suite

## Adding Allow-List Patterns

1. Add regex pattern to `ALLOW_PATTERNS` in `allow_list.py` (for pattern matching)
2. Add literal terms to `ALLOW_TERMS` in `allow_list.py` (for Presidio exclusion)
3. Add test case proving the pattern is preserved through redaction
4. Add test case proving actual PII near the pattern is still caught

## Adding Document Contexts

1. Add the context to `_CONTEXT_ENTITIES` in `engine.py`
2. Add the context to the `Literal` type in `models/requests.py` (both `RedactRequest` and `DetectRequest`)
3. Add a test fixture in `tests/fixtures/` (SYNTHETIC data only)
4. Add integration tests in `tests/test_redactor.py`

## Test Fixtures

All test fixtures must contain **synthetic data only**. Never include real client names,
real SSNs, real addresses, or any data derived from actual client records.

## Pull Request Process

1. Fork and branch from `main`
2. All tests must pass: `pytest tests/ -v`
3. Lint must pass: `ruff check src/`
4. Include test cases for any new functionality
5. Update CHANGELOG.md with your changes
6. Update README.md if adding user-visible features

## Development Setup

```bash
git clone https://github.com/Protocol-Wealth/pw-redact.git
cd pw-redact
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m spacy download en_core_web_lg
pytest tests/ -v
```
