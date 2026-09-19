"""Provider-neutral domain types shared across application services."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from ipaddress import ip_address, ip_network
from typing import TypeVar
from uuid import UUID


class ProviderKind(StrEnum):
    """Supported provider families."""

    FMC = "fmc"
    SCC = "scc"


class ProviderEvidenceProfile(StrEnum):
    """Capability evidence boundary; mock evidence never promotes real providers."""

    MOCK = "mock"
    REAL = "real"


class CapabilityStatus(StrEnum):
    """Evidence state for a provider capability."""

    NOT_STARTED = "NOT_STARTED"
    READ_ONLY = "READ_ONLY"
    PARTIAL = "PARTIAL"
    SUPPORTED = "SUPPORTED"
    UNSUPPORTED = "UNSUPPORTED"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"


class ProviderCapability(StrEnum):
    """Capabilities consumed by provider-independent application code."""

    AUTHENTICATION_SESSION = "authentication_session"
    MANAGER_TENANT_DISCOVERY = "manager_tenant_discovery"
    DEVICE_DISCOVERY = "device_discovery"
    ACCESS_POLICY_DISCOVERY = "access_policy_discovery"
    RULE_CATEGORY_READ = "rule_category_read"
    RULE_CATEGORY_MUTATION = "rule_category_mutation"
    ACCESS_RULE_READ = "access_rule_read"
    ACCESS_RULE_CREATE = "access_rule_create"
    ACCESS_RULE_UPDATE = "access_rule_update"
    ACCESS_RULE_DELETE = "access_rule_delete"
    RULE_ORDERING = "rule_ordering"
    NETWORK_OBJECT_READ = "network_object_read"
    NETWORK_OBJECT_MUTATION = "network_object_mutation"
    NETWORK_GROUPS = "network_groups"
    PORT_OBJECTS_GROUPS = "port_objects_groups"
    SECURITY_ZONE_READ = "security_zone_read"
    SECURITY_ZONE_MUTATION = "security_zone_mutation"
    NETWORK_OBJECT_CREATE = "network_object_create"
    PORT_SERVICE_OBJECT_CREATE = "port_service_object_create"
    URL_OBJECT_CREATE = "url_object_create"
    APPLICATION_OBJECT_CREATE = "application_object_create"
    PENDING_CHANGE_INSPECTION = "pending_change_inspection"
    DEPLOYMENT_START = "deployment_start"
    DEPLOYMENT_STATUS = "deployment_status"
    ROLLBACK = "rollback"
    POLICY_LOCKING = "policy_locking"
    CHANGELOG_HISTORY = "changelog_history"


class FirewallObjectType(StrEnum):
    """Normalized object classes used for discovery and future equivalence checks."""

    NETWORK = "NETWORK"
    NETWORK_GROUP = "NETWORK_GROUP"
    PORT_SERVICE = "PORT_SERVICE"
    URL = "URL"
    APPLICATION = "APPLICATION"
    APPLICATION_FILTER = "APPLICATION_FILTER"


class RuleObjectElement(StrEnum):
    """Rule element in which a provider object is referenced."""

    SOURCE_NETWORK = "SOURCE_NETWORK"
    DESTINATION_NETWORK = "DESTINATION_NETWORK"
    PORT_SERVICE = "PORT_SERVICE"
    APPLICATION = "APPLICATION"
    URL = "URL"


class ZoneElement(StrEnum):
    """Direction in which a security zone is used by a rule."""

    SOURCE = "SOURCE"
    DESTINATION = "DESTINATION"


class ResourceState(StrEnum):
    """Application management/reconciliation state for discovered resources."""

    OBSERVED = "OBSERVED"
    UNMANAGED = "UNMANAGED"
    PENDING_ADOPTION = "PENDING_ADOPTION"
    MANAGED = "MANAGED"
    DRIFTED = "DRIFTED"
    MISSING = "MISSING"
    CONFLICT = "CONFLICT"


class SyncStatus(StrEnum):
    """Durable synchronization outcome."""

    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    INCOMPLETE = "INCOMPLETE"
    FAILED = "FAILED"


class Action(StrEnum):
    """Canonical authorization actions from ``config/permissions.yaml``."""

    READ = "read"
    USE = "use"
    CREATE = "create"
    MODIFY = "modify"
    DELETE = "delete"
    REORDER = "reorder"
    SUBMIT = "submit"
    APPROVE = "approve"
    REJECT = "reject"
    DEPLOY = "deploy"
    RECONCILE = "reconcile"
    MANAGE_GRANTS = "manage_grants"


class PolicyCapability(StrEnum):
    """Delegated capabilities independently granted for one Access Policy."""

    VIEW = "view"
    CREATE_RULE = "create_rule"
    MODIFY_RULE = "modify_rule"
    DELETE_RULE = "delete_rule"
    REORDER_RULE = "reorder_rule"
    SUBMIT = "submit"
    APPROVE = "approve"
    DEPLOY = "deploy"


class AuthorizationReason(StrEnum):
    """Stable, non-enumerating authorization decision reasons."""

    ALLOWED = "ALLOWED"
    NOT_AUTHENTICATED = "NOT_AUTHENTICATED"
    USER_DISABLED = "USER_DISABLED"
    ACTIVE_GROUP_REQUIRED = "ACTIVE_GROUP_REQUIRED"
    GROUP_DISABLED = "GROUP_DISABLED"
    NOT_GROUP_MEMBER = "NOT_GROUP_MEMBER"
    POLICY_NOT_DELEGATED = "POLICY_NOT_DELEGATED"
    ACTION_NOT_GRANTED = "ACTION_NOT_GRANTED"
    RESOURCE_OUT_OF_SCOPE = "RESOURCE_OUT_OF_SCOPE"
    RESOURCE_NOT_USABLE = "RESOURCE_NOT_USABLE"
    IP_RANGE_NOT_GRANTED = "IP_RANGE_NOT_GRANTED"
    PROVIDER_CAPABILITY_UNAVAILABLE = "PROVIDER_CAPABILITY_UNAVAILABLE"
    EQUIVALENT_OBJECT_EXISTS = "EQUIVALENT_OBJECT_EXISTS"
    NOT_OWNER = "NOT_OWNER"
    STALE_AUTHORIZATION_CONTEXT = "STALE_AUTHORIZATION_CONTEXT"


class AuthorizationResourceType(StrEnum):
    """Resources understood by the interface-independent authorization engine."""

    ADMINISTRATION = "administration"
    POLICY = "policy"
    RULE = "rule"
    OBJECT = "object"
    ZONE = "zone"
    IP_NETWORK = "ip_network"
    OBJECT_TYPE = "object_type"
    CATEGORY = "category"


class ChangeSetState(StrEnum):
    """Milestone 3 draft and mock-execution lifecycle states."""

    DRAFT = "DRAFT"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    READY = "READY"
    EXECUTING = "EXECUTING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    PARTIALLY_SUCCEEDED = "PARTIALLY_SUCCEEDED"
    CONFLICT = "CONFLICT"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"
    CANCELLED = "CANCELLED"


class ChangeOperationKind(StrEnum):
    """Provider-neutral operations represented by one ordered ChangeSet."""

    CREATE_RULE = "CREATE_RULE"
    MODIFY_RULE = "MODIFY_RULE"
    DELETE_RULE = "DELETE_RULE"
    MOVE_RULE = "MOVE_RULE"
    CREATE_OBJECT = "CREATE_OBJECT"


class OperationStatus(StrEnum):
    """Independent operation result; provider transactions are not assumed atomic."""

    DRAFT = "DRAFT"
    INVALID = "INVALID"
    READY = "READY"
    EXECUTING = "EXECUTING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CONFLICT = "CONFLICT"
    AMBIGUOUS = "AMBIGUOUS"
    NOT_ATTEMPTED = "NOT_ATTEMPTED"


class ProviderTransactionState(StrEnum):
    """Per-provider execution state for logical multi-provider ChangeSets."""

    PENDING = "PENDING"
    EXECUTING = "EXECUTING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    PARTIALLY_SUCCEEDED = "PARTIALLY_SUCCEEDED"
    CONFLICT = "CONFLICT"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"


class NamingResolutionKind(StrEnum):
    """Stable centralized object naming/equivalence outcomes."""

    EXACT_REUSE = "EXACT_REUSE"
    EQUIVALENT_REUSE = "EQUIVALENT_REUSE"
    NEW_OBJECT_REQUIRED = "NEW_OBJECT_REQUIRED"
    NAMING_CONFLICT = "NAMING_CONFLICT"
    SEMANTIC_CONFLICT = "SEMANTIC_CONFLICT"
    UNSUPPORTED_PROVIDER_BEHAVIOR = "UNSUPPORTED_PROVIDER_BEHAVIOR"


@dataclass(frozen=True, slots=True)
class Principal:
    """Authenticated application principal."""

    user_id: UUID
    organization_id: UUID
    email: str
    role: str
    issuer: str = ""
    subject: str = ""


@dataclass(frozen=True, slots=True)
class DelegatedPolicyContext:
    """Explicit scope required for future delegated policy authorization."""

    principal: Principal
    active_group_id: UUID
    access_policy_id: UUID


@dataclass(frozen=True, slots=True)
class AuthorizationResource:
    """Typed resource input for a single authorization preflight."""

    resource_type: AuthorizationResourceType
    resource_id: UUID | None = None
    element: str | None = None
    value: str | None = None


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    """Structured decision safe for audit, tests, REST, and future MCP use."""

    allowed: bool
    reason: AuthorizationReason
    action: Action
    principal_id: UUID
    organization_id: UUID
    active_group_id: UUID | None
    access_policy_id: UUID | None
    resource_type: AuthorizationResourceType
    resource_id: UUID | None = None
    authorization_revision: int = 0


@dataclass(frozen=True, slots=True)
class ProviderInfo:
    """Provider identity and explicit capability evidence."""

    provider: ProviderKind
    display_name: str
    provider_version: str
    capabilities: dict[str, CapabilityStatus]
    evidence_profile: ProviderEvidenceProfile = ProviderEvidenceProfile.REAL
    writable: bool = False


@dataclass(frozen=True, slots=True)
class ProviderInventory:
    """Bounded, normalized provider discovery summary."""

    provider: ProviderKind
    display_name: str
    provider_version: str
    policy_count: int
    object_count: int
    writable: bool


@dataclass(frozen=True, slots=True)
class NativeResource:
    """Provider identity attributes that never serve as application identity."""

    native_id: str
    name: str
    native_version: str | None
    fingerprint: str
    native_metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class DiscoveredDomain(NativeResource):
    """Normalized FMC domain or SCC tenant."""


@dataclass(frozen=True, slots=True)
class DiscoveredDevice(NativeResource):
    """Normalized managed firewall device."""

    domain_native_id: str = ""
    model: str | None = None


@dataclass(frozen=True, slots=True)
class DiscoveredPolicy(NativeResource):
    """Normalized access policy."""

    domain_native_id: str = ""


@dataclass(frozen=True, slots=True)
class DiscoveredCategory(NativeResource):
    """Normalized rule category or provider ordering section."""

    policy_native_id: str = ""
    position: int = 0


@dataclass(frozen=True, slots=True)
class DiscoveredZone(NativeResource):
    """Normalized provider security zone."""

    domain_native_id: str = ""
    zone_type: str = "SECURITY"


@dataclass(frozen=True, slots=True)
class DiscoveredObjectReference:
    """Provider object reference with its independently authorized rule element."""

    object_native_id: str
    element: RuleObjectElement

    def __post_init__(self) -> None:
        object.__setattr__(self, "element", RuleObjectElement(self.element))


@dataclass(frozen=True, slots=True)
class DiscoveredZoneReference:
    """Provider zone reference with source/destination direction."""

    zone_native_id: str
    element: ZoneElement

    def __post_init__(self) -> None:
        object.__setattr__(self, "element", ZoneElement(self.element))


@dataclass(frozen=True, slots=True)
class DiscoveredRule(NativeResource):
    """Normalized access rule without SDK-native types."""

    policy_native_id: str = ""
    category_native_id: str | None = None
    action: str = ""
    position: int = 0
    object_references: tuple[DiscoveredObjectReference, ...] = ()
    zone_references: tuple[DiscoveredZoneReference, ...] = ()


@dataclass(frozen=True, slots=True)
class DiscoveredObject(NativeResource):
    """Normalized firewall object."""

    domain_native_id: str = ""
    object_type: FirewallObjectType = FirewallObjectType.NETWORK
    normalized_value: str | None = None
    sharing_mode: str = "private"
    referenced_object_native_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object_type = FirewallObjectType(self.object_type)
        object.__setattr__(self, "object_type", object_type)
        if object_type is FirewallObjectType.NETWORK and self.normalized_value:
            value = self.normalized_value
            normalized = (
                str(ip_network(value, strict=False)) if "/" in value else str(ip_address(value))
            )
            object.__setattr__(self, "normalized_value", normalized)


T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class ProviderPage[T]:
    """A bounded provider page with an opaque continuation cursor."""

    items: tuple[T, ...]
    next_cursor: str | None


@dataclass(frozen=True, slots=True)
class PageRequest:
    """Validated provider pagination request."""

    limit: int = 100
    cursor: str | None = None

    def __post_init__(self) -> None:
        if not 1 <= self.limit <= 100:
            msg = "provider page limit must be between 1 and 100"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class SyncResult:
    """Application synchronization result."""

    run_id: UUID
    status: SyncStatus
    resources_seen: int
    started_at: datetime
    completed_at: datetime | None
