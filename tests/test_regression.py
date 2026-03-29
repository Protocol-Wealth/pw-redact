# Copyright 2026 Protocol Wealth LLC
# Licensed under the MIT License
# https://github.com/Protocol-Wealth/pw-redact

"""Regression tests — golden-file checks that catch unintended changes to
redaction behavior. If a pattern change alters what gets redacted or preserved,
these tests fail and force you to verify the change was intentional.

Update the expected values here ONLY when you intentionally change patterns.
"""

from __future__ import annotations

from pathlib import Path

from pw_redact.redactor.engine import PWRedactor

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestTranscriptRegression:
    """Golden-file regression against sample_transcript.txt."""

    def test_entity_types_detected(self, redactor: PWRedactor):
        text = (FIXTURES_DIR / "sample_transcript.txt").read_text()
        result = redactor.redact(text, context="meeting_transcript")
        types = sorted(set(p.entity_type for p in result.manifest.placeholders))

        # These entity types MUST be detected. If one disappears, a pattern broke.
        assert "PERSON" in types, "PERSON detection regressed"
        assert "US_SSN" in types, "US_SSN detection regressed"
        assert "STREET_ADDRESS" in types or "LOCATION" in types, (
            "Address detection regressed"
        )

    def test_minimum_entity_count(self, redactor: PWRedactor):
        text = (FIXTURES_DIR / "sample_transcript.txt").read_text()
        result = redactor.redact(text, context="meeting_transcript")

        # At least 6 entities (3 names + SSN + address + location).
        # Exact count may vary with spaCy model, but never below 6.
        assert len(result.manifest.placeholders) >= 6, (
            f"Only {len(result.manifest.placeholders)} entities detected, expected >= 6"
        )

    def test_ssn_always_redacted(self, redactor: PWRedactor):
        text = (FIXTURES_DIR / "sample_transcript.txt").read_text()
        result = redactor.redact(text, context="meeting_transcript")
        assert "123-45-6789" not in result.sanitized_text

    def test_names_always_redacted(self, redactor: PWRedactor):
        text = (FIXTURES_DIR / "sample_transcript.txt").read_text()
        result = redactor.redact(text, context="meeting_transcript")
        assert "John" not in result.sanitized_text
        assert "Colleen" not in result.sanitized_text

    def test_financial_data_always_preserved(self, redactor: PWRedactor):
        """These financial values MUST survive redaction. If any disappears,
        the allow-list regressed."""
        text = (FIXTURES_DIR / "sample_transcript.txt").read_text()
        result = redactor.redact(text, context="meeting_transcript")

        must_survive = [
            ("425,000", "income amount"),
            ("95,000", "W2 income"),
            ("24,000", "rental income"),
            ("50,000", "Roth conversion amount"),
            ("32%", "tax bracket"),
            ("2032", "planning year"),
            ("6.75%", "loan rate"),
        ]
        for value, label in must_survive:
            assert value in result.sanitized_text, (
                f"Financial data '{value}' ({label}) was incorrectly redacted"
            )

    def test_placeholder_consistency(self, redactor: PWRedactor):
        """Same name must get the same placeholder everywhere."""
        text = (FIXTURES_DIR / "sample_transcript.txt").read_text()
        result = redactor.redact(text, context="meeting_transcript")

        # Find all placeholders for each original value
        originals: dict[str, set[str]] = {}
        for p in result.manifest.placeholders:
            originals.setdefault(p.original, set()).add(p.placeholder)

        for original, placeholders in originals.items():
            assert len(placeholders) == 1, (
                f"'{original}' got multiple placeholders: {placeholders}"
            )


class TestMortgageRegression:
    """Golden-file regression against sample_mortgage_notes.txt."""

    def test_ssns_redacted(self, redactor: PWRedactor):
        text = (FIXTURES_DIR / "sample_mortgage_notes.txt").read_text()
        result = redactor.redact(text, context="mortgage")
        assert "321-54-9876" not in result.sanitized_text
        assert "654-32-1098" not in result.sanitized_text

    def test_email_redacted(self, redactor: PWRedactor):
        text = (FIXTURES_DIR / "sample_mortgage_notes.txt").read_text()
        result = redactor.redact(text, context="mortgage")
        assert "michael.t@email.com" not in result.sanitized_text

    def test_mortgage_financial_preserved(self, redactor: PWRedactor):
        text = (FIXTURES_DIR / "sample_mortgage_notes.txt").read_text()
        result = redactor.redact(text, context="mortgage")

        must_survive = [
            ("$575,000", "purchase price"),
            ("$460,000", "loan amount"),
            ("$115,000", "down payment"),
            ("6.375%", "rate"),
            ("80%", "LTV"),
            ("34%", "DTI"),
        ]
        for value, label in must_survive:
            assert value in result.sanitized_text, (
                f"Mortgage data '{value}' ({label}) was incorrectly redacted"
            )

    def test_mortgage_acronyms_preserved(self, redactor: PWRedactor):
        text = (FIXTURES_DIR / "sample_mortgage_notes.txt").read_text()
        result = redactor.redact(text, context="mortgage")

        must_survive = ["LTV", "DTI", "PMI", "FRM", "RESPA", "TILA", "HOA"]
        for term in must_survive:
            assert term in result.sanitized_text, (
                f"Mortgage acronym '{term}' was incorrectly redacted"
            )


class TestCrossContextRegression:
    """Verify that core PII is always caught regardless of context."""

    def test_ssn_caught_in_all_contexts(self, redactor: PWRedactor):
        text = "Client SSN is 123-45-6789."
        contexts = [
            "general", "meeting_transcript", "tax_return",
            "financial_notes", "mortgage", "real_estate",
        ]
        for ctx in contexts:
            result = redactor.redact(text, context=ctx)
            assert "123-45-6789" not in result.sanitized_text, (
                f"SSN leaked in context '{ctx}'"
            )

    def test_email_caught_in_all_contexts(self, redactor: PWRedactor):
        text = "Contact john@example.com for details."
        contexts = [
            "general", "meeting_transcript", "tax_return",
            "financial_notes", "mortgage", "real_estate",
        ]
        for ctx in contexts:
            result = redactor.redact(text, context=ctx)
            assert "john@example.com" not in result.sanitized_text, (
                f"Email leaked in context '{ctx}'"
            )

    def test_dollar_amounts_preserved_in_all_contexts(self, redactor: PWRedactor):
        text = "Portfolio worth $1,250,000 with 7.5% return."
        contexts = [
            "general", "meeting_transcript", "tax_return",
            "financial_notes", "mortgage", "real_estate",
        ]
        for ctx in contexts:
            result = redactor.redact(text, context=ctx)
            assert "$1,250,000" in result.sanitized_text, (
                f"Dollar amount stripped in context '{ctx}'"
            )
            assert "7.5%" in result.sanitized_text, (
                f"Percentage stripped in context '{ctx}'"
            )
