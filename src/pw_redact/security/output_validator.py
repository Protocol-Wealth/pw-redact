# Copyright 2026 Protocol Wealth LLC
# Licensed under the Apache License, Version 2.0
# https://github.com/Protocol-Wealth/pw-redact

"""Output validation — verify no PII leaks in the redaction response."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Valid placeholder format: <TYPE_N> where TYPE is uppercase/underscore, N is digits
_VALID_PLACEHOLDER = re.compile(r"<[A-Z][A-Z_]*_\d+>")

# Minimum original length to check for leaks (avoids false positives on short
# strings like "Mr", "Dr", "TX" that appear naturally in text)
_MIN_LEAK_CHECK_LENGTH = 5


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

    if not isinstance(placeholders, list):
        warnings.append("manifest_placeholders_not_list")
        return OutputValidationResult(is_valid=False, warnings=warnings)

    # Check no original values leaked into sanitized text
    for i, entry in enumerate(placeholders):
        if not isinstance(entry, dict):
            warnings.append(f"manifest_entry_{i}_not_dict")
            continue

        original = entry.get("original", "")
        entity_type = entry.get("entity_type", "UNKNOWN")

        # Only check strings long enough to be meaningful
        if len(original) >= _MIN_LEAK_CHECK_LENGTH:
            # Word-boundary-aware search to reduce false positives
            # (e.g. "Smith" in "Blacksmith" should not flag)
            pattern = r"\b" + re.escape(original) + r"\b"
            if re.search(pattern, sanitized_text):
                warnings.append(f"pii_leak:{entity_type}")

    # Check all placeholders in text match valid format
    found_placeholders = re.findall(r"<[^>]+>", sanitized_text)
    for ph in found_placeholders:
        if not _VALID_PLACEHOLDER.fullmatch(ph):
            warnings.append(f"invalid_placeholder_format:{ph}")

    return OutputValidationResult(
        is_valid=len(warnings) == 0,
        warnings=warnings,
    )
