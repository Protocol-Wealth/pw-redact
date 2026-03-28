# Copyright 2026 Protocol Wealth LLC
# Licensed under the Apache License, Version 2.0
# https://github.com/Protocol-Wealth/pw-redact

"""Output validation — verify no PII leaks in the redaction response."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Valid placeholder format: <TYPE_N> where TYPE is uppercase/underscore, N is digits
_VALID_PLACEHOLDER = re.compile(r"<[A-Z][A-Z_]*_\d+>")


@dataclass
class OutputValidationResult:
    """Result of output validation."""

    is_valid: bool = True
    warnings: list[str] = field(default_factory=list)


def validate_output(
    sanitized_text: str,
    manifest: dict,
) -> OutputValidationResult:
    """Validate the redaction output for PII leaks and structural integrity.

    Checks:
    1. No original PII values appear in sanitized_text
    2. All placeholders in sanitized_text match the <TYPE_N> format
    3. Manifest has required structure
    """
    warnings: list[str] = []

    # Check manifest structure
    if "placeholders" not in manifest:
        warnings.append("manifest_missing_placeholders")
    if "version" not in manifest:
        warnings.append("manifest_missing_version")
    if "redaction_id" not in manifest:
        warnings.append("manifest_missing_redaction_id")

    placeholders = manifest.get("placeholders", [])

    # Check no original values leaked into sanitized text
    for entry in placeholders:
        original = entry.get("original", "")
        if len(original) >= 4 and original in sanitized_text:
            warnings.append(f"pii_leak:{entry.get('entity_type', 'UNKNOWN')}")

    # Check all placeholders in text match valid format
    found_placeholders = re.findall(r"<[^>]+>", sanitized_text)
    for ph in found_placeholders:
        if not _VALID_PLACEHOLDER.fullmatch(ph):
            warnings.append(f"invalid_placeholder_format:{ph}")

    # Check no original values appear in top-level response fields
    # (they should only be inside manifest.placeholders[].original)

    return OutputValidationResult(
        is_valid=len(warnings) == 0,
        warnings=warnings,
    )
