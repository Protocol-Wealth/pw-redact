# Copyright 2026 Protocol Wealth LLC
# Licensed under the MIT License
# https://github.com/Protocol-Wealth/pw-redact

"""Pydantic response models for the API."""

from pydantic import BaseModel


class PlaceholderEntryResponse(BaseModel):
    placeholder: str
    original: str
    entity_type: str
    start: int
    end: int


class RedactionStats(BaseModel):
    entities_found: int
    entities_by_type: dict[str, int]
    text_length_original: int
    text_length_sanitized: int


class ManifestResponse(BaseModel):
    version: str
    redaction_id: str
    placeholders: list[PlaceholderEntryResponse]
    stats: RedactionStats


class RedactResponse(BaseModel):
    sanitized_text: str
    manifest: ManifestResponse


class RehydrateResponse(BaseModel):
    rehydrated_text: str


class DetectedEntityResponse(BaseModel):
    entity_type: str
    text: str
    start: int
    end: int
    score: float


class DetectResponse(BaseModel):
    entities: list[DetectedEntityResponse]


class HealthResponse(BaseModel):
    status: str
    version: str
    models_loaded: bool
