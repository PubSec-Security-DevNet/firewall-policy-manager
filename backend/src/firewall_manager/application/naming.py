"""Centralized normalized object equivalence and provider-safe naming."""

import re
from dataclasses import asdict, dataclass
from ipaddress import ip_address, ip_network
from uuid import UUID

from firewall_manager.domain.models import FirewallObjectType, NamingResolutionKind, ProviderKind

_SAFE_COMPONENT = re.compile(r"[^A-Za-z0-9_.-]+")
_PORT = re.compile(r"^(tcp|udp)/(\d{1,5})(?:-(\d{1,5}))?$", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class ObjectCandidate:
    """Minimal provider inventory used for naming/equivalence decisions."""

    object_id: UUID
    name: str
    object_type: str
    normalized_value: str | None


@dataclass(frozen=True, slots=True)
class NamingResolution:
    """Safe result returned to REST, UI, audit, and execution."""

    kind: NamingResolutionKind
    requested_name: str
    provider_name: str | None
    normalized_value: str | None
    existing_object_id: UUID | None = None
    reason: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class ProviderObjectNamingService:
    """Resolve object names once, outside UI and provider-specific adapters."""

    def normalize_value(self, object_type: str, value: str) -> str:
        kind = FirewallObjectType(object_type)
        stripped = value.strip()
        if kind is FirewallObjectType.NETWORK:
            return (
                str(ip_network(stripped, strict=False))
                if "/" in stripped
                else str(ip_address(stripped))
            )
        if kind is FirewallObjectType.PORT_SERVICE:
            match = _PORT.fullmatch(stripped)
            if match is None:
                msg = "port service must use protocol/port or protocol/start-end"
                raise ValueError(msg)
            start = int(match.group(2))
            end = int(match.group(3) or start)
            if not 1 <= start <= end <= 65535:
                msg = "port range must be between 1 and 65535"
                raise ValueError(msg)
            suffix = str(start) if start == end else f"{start}-{end}"
            return f"{match.group(1).lower()}/{suffix}"
        if kind is FirewallObjectType.URL:
            return stripped.rstrip("/").casefold()
        if kind in {FirewallObjectType.APPLICATION, FirewallObjectType.APPLICATION_FILTER}:
            return " ".join(stripped.casefold().split())
        msg = "object type does not support delegated creation"
        raise ValueError(msg)

    def provider_name(
        self, provider: ProviderKind, group_slug: str, requested_name: str
    ) -> str | None:
        """Apply conservative restrictions common to the supported mock provider families."""
        component = _SAFE_COMPONENT.sub("-", requested_name.strip()).strip("-._")
        if not component:
            return None
        maximum = 64 if provider is ProviderKind.FMC else 80
        name = f"{group_slug}__{component}"
        return name if len(name) <= maximum else None

    def category_name(self, provider: ProviderKind, group_slug: str) -> str | None:
        """Return the stable provider-visible rule category for one immutable Group slug."""
        maximum = 64 if provider is ProviderKind.FMC else 80
        name = f"{group_slug}__RULES"
        return name if len(name) <= maximum else None

    def resolve(  # noqa: PLR0913 -- all resolution inputs are security-relevant
        self,
        *,
        provider: ProviderKind,
        group_slug: str,
        requested_name: str,
        object_type: str,
        value: str,
        candidates: list[ObjectCandidate],
    ) -> NamingResolution:
        """Distinguish reuse, new creation, and name/content conflicts deterministically."""
        try:
            normalized = self.normalize_value(object_type, value)
        except (ValueError, TypeError):
            return NamingResolution(
                NamingResolutionKind.SEMANTIC_CONFLICT,
                requested_name,
                None,
                None,
                reason="INVALID_NORMALIZED_VALUE",
            )
        provider_name = self.provider_name(provider, group_slug, requested_name)
        if provider_name is None:
            return NamingResolution(
                NamingResolutionKind.UNSUPPORTED_PROVIDER_BEHAVIOR,
                requested_name,
                None,
                normalized,
                reason="PROVIDER_NAME_RESTRICTION",
            )
        same_name = next((item for item in candidates if item.name == provider_name), None)
        if same_name is not None:
            if same_name.object_type == object_type and same_name.normalized_value == normalized:
                return NamingResolution(
                    NamingResolutionKind.EXACT_REUSE,
                    requested_name,
                    provider_name,
                    normalized,
                    same_name.object_id,
                )
            return NamingResolution(
                NamingResolutionKind.NAMING_CONFLICT,
                requested_name,
                provider_name,
                normalized,
                same_name.object_id,
                "SAME_NAME_DIFFERENT_CONTENT",
            )
        equivalent = next(
            (
                item
                for item in candidates
                if item.object_type == object_type and item.normalized_value == normalized
            ),
            None,
        )
        if equivalent is not None:
            return NamingResolution(
                NamingResolutionKind.EQUIVALENT_REUSE,
                requested_name,
                equivalent.name,
                normalized,
                equivalent.object_id,
            )
        return NamingResolution(
            NamingResolutionKind.NEW_OBJECT_REQUIRED,
            requested_name,
            provider_name,
            normalized,
        )
