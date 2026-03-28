# Copyright 2026 Protocol Wealth LLC
# Licensed under the Apache License, Version 2.0
# https://github.com/Protocol-Wealth/pw-redact

"""Pydantic request models for the API."""

from typing import Literal

from pydantic import BaseModel, Field


class RedactionOptions(BaseModel):
    preserve_amounts: bool = True
    preserve_dates: bool = True
    preserve_percentages: bool = True
    redaction_style: Literal["placeholder", "masked", "synthetic"] = "placeholder"


class RedactRequest(BaseModel):
    text: str = Field(..., max_length=1_000_000)
    context: Literal["meeting_transcript", "tax_return", "financial_notes", "general"] = "general"
    options: RedactionOptions | None = None


class RehydrateRequest(BaseModel):
    text: str = Field(..., max_length=1_000_000)
    manifest: dict


class DetectRequest(BaseModel):
    text: str = Field(..., max_length=1_000_000)
    context: Literal["meeting_transcript", "tax_return", "financial_notes", "general"] = "general"
