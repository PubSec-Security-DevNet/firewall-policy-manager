"""Centralized and validated runtime configuration."""

import base64
import binascii
from functools import lru_cache
from typing import Literal

from pydantic import AnyHttpUrl, Field, SecretStr, field_validator, model_validator
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
    secret_store_master_key: SecretStr | None = Field(default=None, alias="APP_SECRET_KEY")
    secret_store_key_version: int = Field(default=1, ge=1)
    scheduler_interval_seconds: int = Field(default=30, ge=5, le=3600)
    app_public_url: str = "http://localhost:5173"
    smtp_host: str | None = None
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_from: str | None = None
    smtp_use_starttls: bool = True
    smtp_use_ssl: bool = False
    smtp_timeout_seconds: int = Field(default=15, ge=3, le=120)

    @field_validator("secret_store_master_key", mode="before")
    @classmethod
    def empty_secret_key_is_unconfigured(cls, value: object) -> object:
        """Allow the mock-only local stack to start without configuring a real-provider key."""
        return None if value == "" else value

    @model_validator(mode="after")
    def protect_development_auth(self) -> "Settings":
        """Prevent the local identity adapter from becoming a production bypass."""
        if self.dev_auth_enabled and self.app_environment not in {"development", "test"}:
            msg = "DEV_AUTH_ENABLED is permitted only in development or test"
            raise ValueError(msg)
        if self.app_environment == "production" and self.secret_store_master_key is None:
            msg = "APP_SECRET_KEY is required in production"
            raise ValueError(msg)
        if self.secret_store_master_key is not None:
            try:
                decoded = base64.b64decode(
                    self.secret_store_master_key.get_secret_value(), validate=True
                )
            except (binascii.Error, ValueError) as exc:
                msg = "APP_SECRET_KEY must be a base64-encoded 32-byte key"
                raise ValueError(msg) from exc
            if len(decoded) != 32:
                msg = "APP_SECRET_KEY must be a base64-encoded 32-byte key"
                raise ValueError(msg)
        return self


@lru_cache
def get_settings() -> Settings:
    """Return process-scoped immutable-style settings."""
    # BaseSettings obtains required values from the environment; static analysis cannot see them.
    return Settings()  # pyright: ignore[reportCallIssue]
