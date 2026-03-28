# Copyright 2026 Protocol Wealth LLC
# Licensed under the Apache License, Version 2.0
# https://github.com/Protocol-Wealth/pw-redact

"""Layer 2: Presidio NLP analyzer configuration with spaCy backend."""

from __future__ import annotations

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider

from ..config import settings
from .financial_recognizers import get_financial_recognizers


def create_analyzer() -> AnalyzerEngine:
    """Initialize Presidio analyzer with spaCy NLP backend and custom recognizers."""
    nlp_config = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": settings.spacy_model}],
    }
    nlp_engine = NlpEngineProvider(nlp_configuration=nlp_config).create_engine()

    registry = RecognizerRegistry()
    registry.load_predefined_recognizers(nlp_engine=nlp_engine)

    # Add custom financial recognizers (Layer 3)
    for recognizer in get_financial_recognizers():
        registry.add_recognizer(recognizer)

    return AnalyzerEngine(nlp_engine=nlp_engine, registry=registry)
