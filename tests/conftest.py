# Copyright 2026 Protocol Wealth LLC
# Licensed under the Apache License, Version 2.0
# https://github.com/Protocol-Wealth/pw-redact

"""Shared test fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from pw_redact.redactor.engine import PWRedactor
from pw_redact.rehydrator.engine import PWRehydrator

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def redactor() -> PWRedactor:
    """Session-scoped PWRedactor (loads spaCy model once)."""
    return PWRedactor()


@pytest.fixture(scope="session")
def rehydrator() -> PWRehydrator:
    return PWRehydrator()


@pytest.fixture()
def sample_transcript() -> str:
    return (FIXTURES_DIR / "sample_transcript.txt").read_text()


@pytest.fixture()
def sample_tax_notes() -> str:
    return (FIXTURES_DIR / "sample_tax_notes.txt").read_text()


@pytest.fixture()
def sample_meeting_notes() -> str:
    return (FIXTURES_DIR / "sample_meeting_notes.txt").read_text()


@pytest.fixture()
def sample_mortgage_notes() -> str:
    return (FIXTURES_DIR / "sample_mortgage_notes.txt").read_text()
