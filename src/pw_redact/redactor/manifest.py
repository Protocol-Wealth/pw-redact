# Copyright 2026 Protocol Wealth LLC
# Licensed under the Apache License, Version 2.0
# https://github.com/Protocol-Wealth/pw-redact

"""Redaction manifest data structures."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PlaceholderEntry:
    """A single placeholder mapping in the redaction manifest."""

    placeholder: str
    original: str
    entity_type: str
    start: int
    end: int


@dataclass
class RedactionManifest:
    """Manifest tracking all redactions for rehydration."""

    redaction_id: str
    placeholders: list[PlaceholderEntry] = field(default_factory=list)
    original_length: int = 0
    sanitized_length: int = 0
    version: str = "1.0"

    def to_dict(self) -> dict:
        """Serialize to API response format."""
        return {
            "version": self.version,
            "redaction_id": self.redaction_id,
            "placeholders": [
                {
                    "placeholder": p.placeholder,
                    "original": p.original,
                    "entity_type": p.entity_type,
                    "start": p.start,
                    "end": p.end,
                }
                for p in self.placeholders
            ],
            "stats": {
                "entities_found": len(self.placeholders),
                "entities_by_type": self._count_by_type(),
                "text_length_original": self.original_length,
                "text_length_sanitized": self.sanitized_length,
            },
        }

    def _count_by_type(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for p in self.placeholders:
            counts[p.entity_type] = counts.get(p.entity_type, 0) + 1
        return counts
