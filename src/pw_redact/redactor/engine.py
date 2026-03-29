# Copyright 2026 Protocol Wealth LLC
# Licensed under the MIT License
# https://github.com/Protocol-Wealth/pw-redact

"""PWRedactor engine — orchestrates four-layer PII redaction."""

from __future__ import annotations

import unicodedata
import uuid
from dataclasses import dataclass

from .allow_list import compile_allow_patterns, get_allow_terms
from .manifest import PlaceholderEntry, RedactionManifest
from .presidio_config import create_analyzer
from .regex_patterns import DetectedEntity, detect_regex

# Map Presidio entity type names to canonical names
_TYPE_MAP: dict[str, str] = {
    "EMAIL_ADDRESS": "EMAIL",
    "PHONE_NUMBER": "US_PHONE",
}

# Entity types to request from Presidio per document context
_CONTEXT_ENTITIES: dict[str, list[str]] = {
    "meeting_transcript": [
        "PERSON", "LOCATION", "PHONE_NUMBER", "EMAIL_ADDRESS",
        "US_SSN", "CREDIT_CARD", "NRP",
        "ACCOUNT_REF", "POLICY_NUMBER",
    ],
    "tax_return": [
        "PERSON", "LOCATION", "PHONE_NUMBER", "EMAIL_ADDRESS",
        "US_SSN", "CREDIT_CARD",
        "ACCOUNT_REF",
    ],
    "financial_notes": [
        "PERSON", "LOCATION", "PHONE_NUMBER", "EMAIL_ADDRESS",
        "US_SSN", "CREDIT_CARD",
        "CUSIP", "ACCOUNT_REF", "POLICY_NUMBER",
    ],
    "general": [
        "PERSON", "LOCATION", "PHONE_NUMBER", "EMAIL_ADDRESS",
        "US_SSN", "CREDIT_CARD",
    ],
    "mortgage": [
        "PERSON", "LOCATION", "PHONE_NUMBER", "EMAIL_ADDRESS",
        "US_SSN", "CREDIT_CARD", "NRP",
        "ACCOUNT_REF", "POLICY_NUMBER",
    ],
    "real_estate": [
        "PERSON", "LOCATION", "PHONE_NUMBER", "EMAIL_ADDRESS",
        "US_SSN", "CREDIT_CARD",
        "ACCOUNT_REF", "POLICY_NUMBER",
    ],
}


@dataclass
class RedactionResult:
    """Result of PII redaction."""

    sanitized_text: str
    manifest: RedactionManifest


class PWRedactor:
    """
    Protocol Wealth PII Redactor.

    Orchestrates four-layer redaction:
    1. Deterministic regex (high-confidence structured PII)
    2. Presidio NLP (names, addresses, contextual PII)
    3. Custom financial recognizers (CUSIP, account refs, policy numbers)
    4. Allow-list filtering (preserve financial data)
    """

    def __init__(self) -> None:
        self._analyzer = create_analyzer()
        self._allow_patterns = compile_allow_patterns()
        self._allow_terms = get_allow_terms()

    def redact(
        self,
        text: str,
        context: str = "general",
        options: dict | None = None,
    ) -> RedactionResult:
        """
        Redact PII from text.

        Args:
            text: Raw input text potentially containing PII.
            context: One of meeting_transcript, tax_return, financial_notes, general.
            options: Reserved for future use (redaction_style, preserve flags).

        Returns:
            RedactionResult with sanitized_text and manifest.
        """
        # Normalize Unicode to NFC to prevent bypass via decomposed forms
        # (e.g. NFD "e" + combining acute vs NFC "é", soft hyphens in SSNs)
        text = unicodedata.normalize("NFC", text)

        # Per-request state for placeholder consistency
        placeholder_map: dict[str, str] = {}
        type_counters: dict[str, int] = {}

        # Step 1: Regex detection (Layer 1)
        regex_entities = detect_regex(text)

        # Step 2: Presidio NLP detection (Layers 2 + 3)
        entities_to_detect = _CONTEXT_ENTITIES.get(context, _CONTEXT_ENTITIES["general"])
        presidio_results = self._analyzer.analyze(
            text=text,
            entities=entities_to_detect,
            language="en",
            allow_list=self._allow_terms,
        )
        nlp_entities = [
            DetectedEntity(
                entity_type=_TYPE_MAP.get(r.entity_type, r.entity_type),
                start=r.start,
                end=r.end,
                score=r.score,
                text=text[r.start : r.end],
            )
            for r in presidio_results
        ]

        # Step 3: Merge and deduplicate (regex preferred on ties)
        merged = _merge_entities(regex_entities, nlp_entities)

        # Step 4: Apply allow-list filter (Layer 4)
        filtered = [
            e
            for e in merged
            if not any(p.fullmatch(e.text) for p in self._allow_patterns)
        ]

        # Step 5: Generate placeholders and build manifest entries
        filtered.sort(key=lambda e: e.start)

        manifest_entries: list[PlaceholderEntry] = []
        for entity in filtered:
            if entity.text in placeholder_map:
                placeholder = placeholder_map[entity.text]
            else:
                type_counters[entity.entity_type] = (
                    type_counters.get(entity.entity_type, 0) + 1
                )
                placeholder = f"<{entity.entity_type}_{type_counters[entity.entity_type]}>"
                placeholder_map[entity.text] = placeholder

            manifest_entries.append(
                PlaceholderEntry(
                    placeholder=placeholder,
                    original=entity.text,
                    entity_type=entity.entity_type,
                    start=entity.start,
                    end=entity.end,
                )
            )

        # Step 6: Build sanitized text (replace end-to-start to preserve positions)
        sanitized = text
        for entry in reversed(manifest_entries):
            sanitized = sanitized[: entry.start] + entry.placeholder + sanitized[entry.end :]

        # Step 7: Build result
        manifest = RedactionManifest(
            redaction_id=f"red_{uuid.uuid4().hex[:8]}",
            placeholders=manifest_entries,
            original_length=len(text),
            sanitized_length=len(sanitized),
        )

        return RedactionResult(sanitized_text=sanitized, manifest=manifest)

    def detect(self, text: str, context: str = "general") -> list[DetectedEntity]:
        """Detect PII locations without redacting. For UI highlighting."""
        text = unicodedata.normalize("NFC", text)
        regex_entities = detect_regex(text)
        entities_to_detect = _CONTEXT_ENTITIES.get(context, _CONTEXT_ENTITIES["general"])
        presidio_results = self._analyzer.analyze(
            text=text,
            entities=entities_to_detect,
            language="en",
            allow_list=self._allow_terms,
        )
        nlp_entities = [
            DetectedEntity(
                entity_type=_TYPE_MAP.get(r.entity_type, r.entity_type),
                start=r.start,
                end=r.end,
                score=r.score,
                text=text[r.start : r.end],
            )
            for r in presidio_results
        ]
        merged = _merge_entities(regex_entities, nlp_entities)
        return [
            e
            for e in merged
            if not any(p.fullmatch(e.text) for p in self._allow_patterns)
        ]


def _merge_entities(
    regex_entities: list[DetectedEntity],
    nlp_entities: list[DetectedEntity],
) -> list[DetectedEntity]:
    """Merge regex and NLP entities, deduplicating overlaps.

    When two detections overlap, the higher-scoring one wins.
    Regex wins ties (lower source priority value).
    """
    # Tag with source: 0 = regex (preferred), 1 = NLP
    tagged: list[tuple[DetectedEntity, int]] = []
    for e in regex_entities:
        tagged.append((e, 0))
    for e in nlp_entities:
        tagged.append((e, 1))

    # Sort by start position, then score descending, then source (regex first)
    tagged.sort(key=lambda t: (t[0].start, -t[0].score, t[1]))

    merged: list[DetectedEntity] = []
    for entity, _source in tagged:
        if merged and entity.start < merged[-1].end:
            # Overlapping — keep the better detection
            prev = merged[-1]
            if entity.score > prev.score:
                merged[-1] = entity
            elif entity.score == prev.score and (entity.end - entity.start) > (
                prev.end - prev.start
            ):
                # Same score, prefer longer span
                merged[-1] = entity
        else:
            merged.append(entity)

    return merged
