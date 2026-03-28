---
name: Bug Report
about: Report a PII detection issue, false positive, or service error
title: "[BUG] "
labels: bug
assignees: ''
---

## Describe the Bug

A clear description of what the bug is.

## To Reproduce

```python
from pw_redact.redactor.engine import PWRedactor

redactor = PWRedactor()
result = redactor.redact("your input text here", context="general")
print(result.sanitized_text)
```

**Expected output:**
```
<what you expected>
```

**Actual output:**
```
<what actually happened>
```

## Type of Issue

- [ ] PII not detected (false negative — PII leaked through)
- [ ] Financial data incorrectly redacted (false positive — data destroyed)
- [ ] Placeholder inconsistency
- [ ] API error / crash
- [ ] Performance issue
- [ ] Security concern (if sensitive, email security@protocolwealthllc.com instead)

## Environment

- pw-redact version:
- Python version:
- spaCy model: en_core_web_lg / en_core_web_md
- OS:

## Additional Context

If this involves a false negative (PII leaked), please indicate which entity type
should have been detected (e.g., US_SSN, PERSON, EMAIL).

**IMPORTANT:** Do NOT include real PII in bug reports. Use synthetic/fake data.
