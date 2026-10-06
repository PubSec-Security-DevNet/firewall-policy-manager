"""Centralized and validated runtime configuration."""

import base64
import binascii
import json
from functools import lru_cache
from typing import Literal
from urllib.parse import urlparse

from pydantic import AnyHttpUrl, BaseModel, Field, SecretStr, field_validator, model_validator
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
    secret_store_provider: Literal["environment", "vault"] = "environment"  # noqa: S105
    vault_url: str | None = None
    vault_token: SecretStr | None = None
    vault_secret_path: str = "secret/data/firewall-manager"  # noqa: S105
    scheduler_interval_seconds: int = Field(default=30, ge=5, le=3600)
    audit_retention_months: int = Field(default=6, ge=1, le=120)
    app_public_url: str = "http://localhost:5173"
    administrator_email: str | None = None
    oidc_providers: str = "[]"
    auth_session_idle_minutes: int = Field(default=60, ge=5, le=1440)
    auth_session_absolute_hours: int = Field(default=12, ge=1, le=168)
    bootstrap_organization_name: str | None = None
    bootstrap_admin_email: str | None = None
    bootstrap_admin_display_name: str | None = None
    bootstrap_admin_issuer: str | None = None
    bootstrap_admin_subject: str | None = None
    smtp_host: str | None = None
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_from: str | None = None
    smtp_use_starttls: bool = True
    smtp_use_ssl: bool = False
    smtp_timeout_seconds: int = Field(default=15, ge=3, le=120)
    api_rate_limit_requests: int = Field(default=120, ge=10, le=10000)
    api_rate_limit_window_seconds: int = Field(default=60, ge=1, le=3600)

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
        if (
            self.app_environment == "production"
            and self.secret_store_master_key is None
            and self.secret_store_provider != "vault"  # noqa: S105
        ):
            msg = "APP_SECRET_KEY is required in production unless a Vault provider is configured"
            raise ValueError(msg)
        if self.secret_store_provider == "vault" and (not self.vault_url or not self.vault_token):  # noqa: S105
            raise ValueError("VAULT_URL and VAULT_TOKEN are required for Vault secret storage")
        if (
            self.app_environment in {"staging", "production"}
            and self.secret_store_provider == "vault"  # noqa: S105
            and (not self.vault_url or urlparse(self.vault_url).scheme != "https")
        ):
            raise ValueError("VAULT_URL must use HTTPS in staging and production")
        if self.app_environment in {"staging", "production"}:
            if urlparse(self.app_public_url).scheme != "https":
                raise ValueError("APP_PUBLIC_URL must use HTTPS in staging and production")
            if any(urlparse(origin).scheme != "https" for origin in self.cors_origins):
                raise ValueError("CORS_ORIGINS must use HTTPS in staging and production")
            if "*" in self.cors_origins:
                raise ValueError("CORS_ORIGINS cannot contain '*' in staging and production")
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

    def oidc_provider_configs(self) -> list["OidcProviderConfig"]:
        """Parse the deployment-owned OIDC provider catalog without exposing secrets."""
        try:
            values = json.loads(self.oidc_providers)
        except json.JSONDecodeError as exc:
            raise ValueError("OIDC_PROVIDERS must be valid JSON") from exc
        if not isinstance(values, list):
            raise ValueError("OIDC_PROVIDERS must be a JSON array")
        return [OidcProviderConfig.model_validate(value) for value in values]


class OidcProviderConfig(BaseModel):
    """Deployment configuration for one standards-based OIDC relying-party profile."""

    id: str = Field(min_length=1, max_length=80, pattern=r"^[a-z0-9-]+$")
    kind: Literal["entra", "duo", "generic"]
    display_name: str = Field(min_length=1, max_length=120)
    issuer_url: AnyHttpUrl
    client_id: str = Field(min_length=1, max_length=300)
    client_secret: SecretStr
    scopes: list[str] = Field(default_factory=lambda: ["openid", "profile", "email"])
    enabled: bool = True
    username_claim: str = "preferred_username"
    display_name_claim: str = "name"
    email_claim: str = "email"
    mapping_claim: str = "email"
    logout: bool = True

    @field_validator("scopes")
    @classmethod
    def require_openid_scope(cls, value: list[str]) -> list[str]:
        if "openid" not in value:
            raise ValueError("OIDC scopes must include openid")
        return list(dict.fromkeys(value))


@lru_cache
def get_settings() -> Settings:
    """Return process-scoped immutable-style settings."""
    # BaseSettings obtains required values from the environment; static analysis cannot see them.
    return Settings()  # pyright: ignore[reportCallIssue]
