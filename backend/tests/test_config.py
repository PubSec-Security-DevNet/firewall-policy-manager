# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Runtime configuration safety behavior."""

import base64
import os
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from firewall_manager import main
from firewall_manager.api.schemas import InitialSetupTestRequest
from firewall_manager.config import Settings
from firewall_manager.domain.models import (
    CapabilityStatus,
    ProviderCapability,
    ProviderEvidenceProfile,
    ProviderKind,
)
from firewall_manager.providers.capabilities import (
    CapabilityEvidenceMismatchError,
    default_capability_path,
    load_capabilities,
    verify_capability_evidence,
)
from firewall_manager.worker.tasks import subtract_calendar_months


def _production_values() -> dict[str, object]:
    return {
        "app_environment": "production",
        "database_url": "postgresql+psycopg://example",
        "redis_url": "redis://example",
        "fmc_base_url": "https://fmc.example.test",
        "scc_base_url": "https://scc.example.test",
        "app_public_url": "https://firewall.example.test",
        "cors_origins": ["https://console.example.test"],
        "dev_auth_enabled": False,
        "APP_SECRET_KEY": base64.b64encode(os.urandom(32)).decode(),
        "oidc_providers": '[{"id":"entra-main","kind":"entra","display_name":"Entra","issuer_url":"https://login.microsoftonline.com/example/v2.0","client_id":"client","client_secret":"secret"}]',
    }


def test_development_auth_cannot_be_enabled_in_production() -> None:
    with pytest.raises(ValidationError, match="permitted only"):
        Settings.model_validate({**_production_values(), "dev_auth_enabled": True})


def test_audit_retention_defaults_to_six_months_and_rejects_unsafe_values() -> None:
    settings = Settings.model_validate(_production_values())
    assert settings.audit_retention_months == 6
    with pytest.raises(ValidationError):
        Settings.model_validate({**_production_values(), "audit_retention_months": 0})


def test_audit_retention_subtracts_calendar_months() -> None:
    assert subtract_calendar_months(datetime(2026, 8, 31, tzinfo=UTC), 6) == datetime(
        2026, 2, 28, tzinfo=UTC
    )


def test_initial_setup_oidc_test_request_preserves_organization_name() -> None:
    request = InitialSetupTestRequest(
        organization_name="Example Organization",
        admin_email="admin@example.test",
        admin_display_name="Example Admin",
        provider_id="primary",
        provider_kind="generic",
        provider_display_name="Example OIDC",
        provider_issuer_url="https://issuer.example.test",
        provider_client_id="client-id",
        provider_client_secret="client-secret",  # noqa: S106
    )

    assert request.organization_name == "Example Organization"


def test_production_requires_a_valid_external_secret_store_key() -> None:
    without_key = _production_values()
    without_key["APP_SECRET_KEY"] = None
    with pytest.raises(ValidationError, match="APP_SECRET_KEY or APP_SECRET_KEY_FILE is required"):
        Settings.model_validate(without_key)
    with pytest.raises(ValidationError, match="base64-encoded 32-byte key"):
        Settings.model_validate({**_production_values(), "APP_SECRET_KEY": "not-a-key"})


def test_production_builds_database_and_redis_urls_from_secret_files(tmp_path) -> None:
    database_password = tmp_path / "postgres_password"
    redis_password = tmp_path / "redis_password"
    database_password.write_text("db+/password\n", encoding="utf-8")
    redis_password.write_text("redis+/password\n", encoding="utf-8")
    values = _production_values()
    values.update(
        {
            "database_url": "",
            "database_password_file": str(database_password),
            "database_host": "db",
            "database_name": "firewall_manager",
            "database_user": "firewall",
            "redis_url": "",
            "redis_password_file": str(redis_password),
            "redis_host": "redis",
        }
    )

    settings = Settings.model_validate(values)

    assert settings.database_url == (
        "postgresql+psycopg://firewall:db%2B%2Fpassword@db:5432/firewall_manager"
    )
    assert settings.redis_url == "redis://:redis%2B%2Fpassword@redis:6379/0"


def test_production_loads_master_key_from_secret_file(tmp_path) -> None:
    encoded_key = base64.b64encode(os.urandom(32)).decode()
    master_key = tmp_path / "app_secret_key"
    master_key.write_text(f"{encoded_key}\n", encoding="utf-8")
    values = _production_values()
    values["APP_SECRET_KEY"] = None
    values["APP_SECRET_KEY_FILE"] = str(master_key)

    settings = Settings.model_validate(values)

    assert settings.secret_store_master_key is not None
    assert settings.secret_store_master_key.get_secret_value() == encoded_key


def test_oidc_bootstrap_catalog_can_be_loaded_from_a_secret_file(tmp_path) -> None:
    catalog = tmp_path / "oidc.json"
    catalog.write_text(str(_production_values()["oidc_providers"]), encoding="utf-8")

    settings = Settings.model_validate(
        {**_production_values(), "oidc_providers": "[]", "oidc_providers_file": str(catalog)}
    )

    assert settings.oidc_provider_configs()[0].id == "entra-main"


def test_development_identity_endpoint_is_not_registered_when_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings.model_validate(_production_values())
    monkeypatch.setattr(main, "get_settings", lambda: settings)
    application = main.create_app()
    assert "/api/v1/dev/users" not in {
        path
        for route in application.routes
        if isinstance(path := getattr(route, "path", None), str)
    }
    assert "/docs" not in {getattr(route, "path", None) for route in application.routes}
    assert "/openapi.json" not in {getattr(route, "path", None) for route in application.routes}


def test_provider_capability_document_separates_mock_and_real_evidence() -> None:
    document = load_capabilities(default_capability_path())
    assert set(document.statuses) == set(CapabilityStatus)
    assert set(document.capabilities) == set(ProviderCapability)
    for provider in ProviderKind:
        mock = document.for_provider(provider, ProviderEvidenceProfile.MOCK)
        real = document.for_provider(provider, ProviderEvidenceProfile.REAL)
        assert mock["access_rule_read"] is CapabilityStatus.READ_ONLY
        assert mock["access_rule_create"] is CapabilityStatus.SUPPORTED
        assert mock["rule_ordering"] is CapabilityStatus.SUPPORTED
        assert mock["application_object_create"] is CapabilityStatus.PARTIAL
        assert real["access_rule_read"] is CapabilityStatus.NOT_STARTED
        assert real["access_rule_create"] is CapabilityStatus.SUPPORTED
        assert real["pending_change_inspection"] is CapabilityStatus.SUPPORTED
        assert real["application_object_create"] is CapabilityStatus.NOT_STARTED
        assert CapabilityStatus.SUPPORTED in real.values()


@pytest.mark.parametrize("provider", list(ProviderKind))
def test_mock_capability_evidence_cannot_promote_a_real_manager(provider: ProviderKind) -> None:
    document = load_capabilities(default_capability_path())
    mock = document.for_provider(provider, ProviderEvidenceProfile.MOCK)
    with pytest.raises(CapabilityEvidenceMismatchError):
        verify_capability_evidence(
            document,
            provider,
            is_mock=False,
            reported_profile=ProviderEvidenceProfile.MOCK,
            reported_capabilities=mock,
        )
