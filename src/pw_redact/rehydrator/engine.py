# Copyright 2026 Protocol Wealth LLC
# Licensed under the Apache License, Version 2.0
# https://github.com/Protocol-Wealth/pw-redact

"""Manifest-based placeholder restoration (rehydration)."""

from __future__ import annotations


class PWRehydrator:
    """Restores original PII values from placeholders using a redaction manifest."""

    @staticmethod
    def rehydrate(text: str, manifest: dict) -> str:
        """
        Replace placeholders in text with original values from the manifest.

        Args:
            text: Text containing placeholders (e.g. AI model output).
            manifest: Redaction manifest dict with 'placeholders' list.

        Returns:
            Text with placeholders replaced by original values.
        """
        result = text
        for entry in manifest.get("placeholders", []):
            result = result.replace(entry["placeholder"], entry["original"])
        return result
