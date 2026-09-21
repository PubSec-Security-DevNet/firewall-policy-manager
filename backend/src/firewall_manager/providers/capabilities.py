"""Validated loader for the provider capability evidence file."""

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from firewall_manager.domain.models import (
    CapabilityStatus,
    ProviderCapability,
    ProviderEvidenceProfile,
    ProviderKind,
)

VALIDATION_WRITE_CAPABILITIES = frozenset(
    {
        ProviderCapability.ACCESS_RULE_CREATE.value,
        ProviderCapability.ACCESS_RULE_UPDATE.value,
        ProviderCapability.ACCESS_RULE_DELETE.value,
        ProviderCapability.RULE_ORDERING.value,
        ProviderCapability.RULE_CATEGORY_MUTATION.value,
        ProviderCapability.NETWORK_OBJECT_CREATE.value,
        ProviderCapability.NETWORK_OBJECT_MUTATION.value,
        ProviderCapability.PORT_SERVICE_OBJECT_CREATE.value,
        ProviderCapability.PORT_SERVICE_OBJECT_MUTATION.value,
        ProviderCapability.URL_OBJECT_CREATE.value,
        ProviderCapability.URL_OBJECT_MUTATION.value,
    }
)
VALIDATION_REQUIRED_CAPABILITIES = VALIDATION_WRITE_CAPABILITIES | {
    ProviderCapability.PENDING_CHANGE_INSPECTION.value
}


def effective_write_capabilities(
    capabilities: dict[str, str], *, validation_writes_enabled: bool
) -> dict[str, str]:
    """Expose implemented PARTIAL capabilities only inside an explicit validation write gate."""
    if not validation_writes_enabled:
        return dict(capabilities)
    return {
        name: (
            CapabilityStatus.SUPPORTED.value
            if name in VALIDATION_REQUIRED_CAPABILITIES and status == CapabilityStatus.PARTIAL.value
            else status
        )
        for name, status in capabilities.items()
    }


class ProviderKindCapabilityValues(BaseModel):
    """Capability status for both first-class provider families."""

    model_config = ConfigDict(extra="forbid")

    fmc: CapabilityStatus
    scc: CapabilityStatus


class ProviderCapabilityValues(BaseModel):
    """Independent mock and real-provider compatibility evidence."""

    model_config = ConfigDict(extra="forbid")

    mock: ProviderKindCapabilityValues
    real: ProviderKindCapabilityValues


class CapabilityDocument(BaseModel):
    """Validated capability document."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(ge=1)
    statuses: list[CapabilityStatus]
    capabilities: dict[ProviderCapability, ProviderCapabilityValues]

    def for_provider(
        self, provider: ProviderKind, profile: ProviderEvidenceProfile
    ) -> dict[str, CapabilityStatus]:
        """Return all declared statuses for one provider and evidence profile."""
        return {
            capability.value: getattr(getattr(values, profile.value), provider.value)
            for capability, values in self.capabilities.items()
        }


class CapabilityEvidenceMismatchError(ValueError):
    """Reported capabilities do not match the manager's governed evidence profile."""


def verify_capability_evidence(
    document: CapabilityDocument,
    provider: ProviderKind,
    *,
    is_mock: bool,
    reported_profile: ProviderEvidenceProfile,
    reported_capabilities: dict[str, CapabilityStatus],
) -> dict[str, CapabilityStatus]:
    """Return governed evidence or reject mock/real profile substitution and drift."""
    expected_profile = ProviderEvidenceProfile.MOCK if is_mock else ProviderEvidenceProfile.REAL
    expected = document.for_provider(provider, expected_profile)
    if reported_profile is not expected_profile or reported_capabilities != expected:
        raise CapabilityEvidenceMismatchError
    return expected


def load_capabilities(path: Path) -> CapabilityDocument:
    """Load and validate the JSON-form YAML 1.2 capability document."""
    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    return CapabilityDocument.model_validate(payload)


def default_capability_path() -> Path:
    """Locate the repository capability source in source and container layouts."""
    candidates = (
        Path("/app/config/provider-capabilities.yaml"),
        Path(__file__).resolve().parents[4] / "config" / "provider-capabilities.yaml",
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    msg = "config/provider-capabilities.yaml was not found"
    raise FileNotFoundError(msg)
