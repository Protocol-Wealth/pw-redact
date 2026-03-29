# Copyright 2026 Protocol Wealth LLC
# Licensed under the MIT License
# https://github.com/Protocol-Wealth/pw-redact

"""Application configuration via environment variables."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    pw_redact_api_key: str = "change-me-to-a-strong-random-key"
    log_level: str = "info"
    spacy_model: str = "en_core_web_lg"
    environment: str = "development"
    max_request_size_mb: int = 1
    rate_limit_rpm: int = 60
    rate_limit_burst: int = 10

    model_config = {"env_prefix": "", "case_sensitive": False}


settings = Settings()
