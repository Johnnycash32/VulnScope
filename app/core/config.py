from __future__ import annotations

import logging
import secrets
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger("vulnscope.config")


class Settings(BaseSettings):
    """Application configuration loaded from environment / .env."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    database_url: str = "sqlite:///./vulnscope.db"

    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30

    environment: str = "development"
    cors_origins: list[str] = []

    redis_url: str = "redis://redis:6379/0"
    zap_api_url: str = "http://zap:8080"
    zap_api_key: str | None = None

    @property
    def is_production(self) -> bool:
        return self.environment.strip().lower() in {"prod", "production"}

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings()

    if not settings.jwt_secret:
        if settings.is_production:
            raise RuntimeError(
                "JWT_SECRET must be set when ENVIRONMENT is production. "
                "Refusing to start without a signing secret."
            )
        settings.jwt_secret = secrets.token_urlsafe(48)
        logger.warning(
            "JWT_SECRET is not set; generated an ephemeral development secret. "
            "Issued tokens will not survive a restart."
        )

    return settings