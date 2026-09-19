"""Centralized and validated runtime configuration."""

from functools import lru_cache
from typing import Literal

from pydantic import AnyHttpUrl, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded once at a process boundary."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    app_environment: Literal["development", "test", "staging", "production"]
    app_log_level: str = "INFO"
    database_url: str
    redis_url: str
    fmc_base_url: AnyHttpUrl
    scc_base_url: AnyHttpUrl
    cors_origins: list[str] = Field(default_factory=list)
    dev_auth_enabled: bool = False
    dev_auth_default_user: str = "viewer@example.test"
    scheduler_interval_seconds: int = Field(default=30, ge=5, le=3600)

    @model_validator(mode="after")
    def protect_development_auth(self) -> "Settings":
        """Prevent the local identity adapter from becoming a production bypass."""
        if self.dev_auth_enabled and self.app_environment not in {"development", "test"}:
            msg = "DEV_AUTH_ENABLED is permitted only in development or test"
            raise ValueError(msg)
        return self


@lru_cache
def get_settings() -> Settings:
    """Return process-scoped immutable-style settings."""
    # BaseSettings obtains required values from the environment; static analysis cannot see them.
    return Settings()  # pyright: ignore[reportCallIssue]
