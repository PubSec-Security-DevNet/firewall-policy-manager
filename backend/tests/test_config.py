"""Runtime configuration safety behavior."""

import base64
import os

import pytest
from pydantic import ValidationError

from firewall_manager import main
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


def _production_values() -> dict[str, object]:
    return {
        "app_environment": "production",
        "database_url": "postgresql+psycopg://example",
        "redis_url": "redis://example",
        "fmc_base_url": "https://fmc.example.test",
        "scc_base_url": "https://scc.example.test",
        "dev_auth_enabled": False,
        "APP_SECRET_KEY": base64.b64encode(os.urandom(32)).decode(),
    }


def test_development_auth_cannot_be_enabled_in_production() -> None:
    with pytest.raises(ValidationError, match="permitted only"):
        Settings.model_validate({**_production_values(), "dev_auth_enabled": True})


def test_production_requires_a_valid_external_secret_store_key() -> None:
    without_key = _production_values()
    without_key.pop("APP_SECRET_KEY")
    with pytest.raises(ValidationError, match="APP_SECRET_KEY is required"):
        Settings.model_validate(without_key)
    with pytest.raises(ValidationError, match="base64-encoded 32-byte key"):
        Settings.model_validate({**_production_values(), "APP_SECRET_KEY": "not-a-key"})


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
        assert real["access_rule_create"] is CapabilityStatus.NOT_STARTED
        assert CapabilityStatus.SUPPORTED not in real.values()


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
