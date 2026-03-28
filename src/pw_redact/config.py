# Copyright 2026 Protocol Wealth LLC
# Licensed under the Apache License, Version 2.0
# https://github.com/Protocol-Wealth/pw-redact

"""Application configuration via environment variables."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    pw_redact_api_key: str = "change-me-to-a-strong-random-key"
    log_level: str = "info"
    spacy_model: str = "en_core_web_lg"
    environment: str = "development"
    max_request_size_mb: int = 1

    model_config = {"env_prefix": "", "case_sensitive": False}


settings = Settings()
