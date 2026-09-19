"""Deterministic stateful mock implementing read and transaction contracts."""

# ruff: noqa: PLR0912, PLR0913, PLR0917 -- provider commands keep explicit normalized fields.

from dataclasses import replace
from enum import StrEnum
from typing import TypeVar, cast
from uuid import NAMESPACE_URL, UUID, uuid5

from firewall_manager.application.errors import (
    ProviderPaginationError,
    ProviderUnavailableError,
)
from firewall_manager.domain.models import (
    CapabilityStatus,
    ChangeOperationKind,
    DiscoveredCategory,
    DiscoveredDevice,
    DiscoveredDomain,
    DiscoveredObject,
    DiscoveredObjectReference,
    DiscoveredPolicy,
    DiscoveredRule,
    DiscoveredZone,
    DiscoveredZoneReference,
    FirewallObjectType,
    OperationStatus,
    PageRequest,
    ProviderEvidenceProfile,
    ProviderInfo,
    ProviderInventory,
    ProviderKind,
    ProviderPage,
    ProviderTransactionState,
    RuleObjectElement,
    ZoneElement,
)
from firewall_manager.providers.capabilities import default_capability_path, load_capabilities
from firewall_manager.providers.transactions import ProviderExecutionResult

T = TypeVar("T")


class MockScenario(StrEnum):
    """Read-path faults/state transitions available to contract and sync tests."""

    NORMAL = "normal"
    UNAVAILABLE = "unavailable"
    FAIL_SECOND_PAGE = "fail_second_page"


class DeterministicMockProvider:
    """Representative FMC/SCC data with deterministic read and transaction controls."""

    def __init__(self, kind: ProviderKind, scenario: MockScenario = MockScenario.NORMAL) -> None:
        self.kind = kind
        self.scenario = scenario
        self._capabilities = load_capabilities(default_capability_path()).for_provider(
            kind, ProviderEvidenceProfile.MOCK
        )
        prefix = kind.value
        domain = f"{prefix}-domain-main"
        policy = f"{prefix}-policy-edge"
        self._domains = [
            DiscoveredDomain(f"{prefix}-domain-main", "Primary scope", "1", f"{prefix}-d-1"),
            DiscoveredDomain(f"{prefix}-domain-lab", "Lab scope", "1", f"{prefix}-d-2"),
        ]
        self._devices = [
            DiscoveredDevice(
                f"{prefix}-device-1",
                f"{prefix.upper()} edge firewall",
                "7.6",
                f"{prefix}-device-fp-1",
                domain_native_id=domain,
                model="Secure Firewall 3100",
            )
        ]
        self._policies = [
            DiscoveredPolicy(
                policy,
                f"{prefix.upper()} Edge Policy",
                "3",
                f"{prefix}-policy-fp-3",
                domain_native_id=domain,
            )
        ]
        finance_category = f"{prefix}-category-finance"
        engineering_category = f"{prefix}-category-engineering"
        admin_category = f"{prefix}-category-admin"
        self._categories = [
            DiscoveredCategory(
                finance_category,
                "FINANCE__RULES",
                "2",
                f"{prefix}-category-finance-fp-2",
                policy_native_id=policy,
                position=10,
            ),
            DiscoveredCategory(
                engineering_category,
                "ENGINEERING__RULES",
                "1",
                f"{prefix}-category-engineering-fp-1",
                policy_native_id=policy,
                position=20,
            ),
            DiscoveredCategory(
                admin_category,
                "ADMIN__RULES",
                "1",
                f"{prefix}-category-admin-fp-1",
                policy_native_id=policy,
                position=30,
            ),
        ]
        inside_zone = f"{prefix}-zone-inside"
        outside_zone = f"{prefix}-zone-outside"
        self._zones = [
            DiscoveredZone(
                f"{prefix}-zone-finance",
                "Inside-Finance",
                "1",
                f"{prefix}-zone-finance-fp-1",
                domain_native_id=domain,
            ),
            DiscoveredZone(
                f"{prefix}-zone-engineering",
                "Inside-Engineering",
                "1",
                f"{prefix}-zone-engineering-fp-1",
                domain_native_id=domain,
            ),
            DiscoveredZone(
                inside_zone,
                "Inside",
                "3",
                f"{prefix}-zone-inside-fp-3",
                domain_native_id=domain,
            ),
            DiscoveredZone(
                outside_zone,
                "Outside",
                "2",
                f"{prefix}-zone-outside-fp-2",
                domain_native_id=domain,
            ),
        ]
        shared_object = f"{prefix}-object-dns"
        private_object = f"{prefix}-object-app"
        service_object = f"{prefix}-object-https"
        application_object = f"{prefix}-object-web-app"
        self._rules = [
            DiscoveredRule(
                f"{prefix}-rule-web",
                "Allow application web",
                "4",
                f"{prefix}-rule-fp-4",
                policy_native_id=policy,
                category_native_id=finance_category,
                action="ALLOW",
                position=10,
                object_references=(
                    DiscoveredObjectReference(private_object, RuleObjectElement.SOURCE_NETWORK),
                    DiscoveredObjectReference(shared_object, RuleObjectElement.DESTINATION_NETWORK),
                    DiscoveredObjectReference(service_object, RuleObjectElement.PORT_SERVICE),
                    DiscoveredObjectReference(application_object, RuleObjectElement.APPLICATION),
                ),
                zone_references=(
                    DiscoveredZoneReference(inside_zone, ZoneElement.SOURCE),
                    DiscoveredZoneReference(outside_zone, ZoneElement.DESTINATION),
                ),
            ),
            DiscoveredRule(
                f"{prefix}-rule-default",
                "Default deny",
                "1",
                f"{prefix}-rule-fp-1",
                policy_native_id=policy,
                category_native_id=engineering_category,
                action="BLOCK",
                position=20,
                object_references=(
                    DiscoveredObjectReference(shared_object, RuleObjectElement.DESTINATION_NETWORK),
                ),
            ),
        ]
        self._objects = [
            DiscoveredObject(
                f"{prefix}-object-finance-servers",
                "FINANCE__APP-SUBNET",
                "1",
                f"{prefix}-finance-servers-fp-1",
                domain_native_id=domain,
                object_type=FirewallObjectType.NETWORK,
                normalized_value="10.20.10.0/24",
            ),
            DiscoveredObject(
                f"{prefix}-object-engineering-servers",
                "ENGINEERING__BUILD-SERVERS",
                "1",
                f"{prefix}-engineering-servers-fp-1",
                domain_native_id=domain,
                object_type=FirewallObjectType.NETWORK,
                normalized_value="172.16.10.0/24",
            ),
            DiscoveredObject(
                f"{prefix}-object-finance-equivalent",
                "legacy-finance-network",
                "1",
                f"{prefix}-finance-equivalent-fp-1",
                domain_native_id=domain,
                object_type=FirewallObjectType.NETWORK,
                normalized_value="10.20.10.0/24",
            ),
            DiscoveredObject(
                f"{prefix}-object-finance-name-conflict",
                "FINANCE__conflict",
                "1",
                f"{prefix}-finance-conflict-fp-1",
                domain_native_id=domain,
                object_type=FirewallObjectType.NETWORK,
                normalized_value="10.20.99.0/24",
            ),
            DiscoveredObject(
                private_object,
                "application-subnet",
                "5",
                f"{prefix}-object-fp-5",
                domain_native_id=domain,
                object_type=FirewallObjectType.NETWORK,
                normalized_value=("10.20.0.0/24" if kind is ProviderKind.FMC else "10.30.0.0/24"),
            ),
            DiscoveredObject(
                shared_object,
                "shared-dns",
                "2",
                f"{prefix}-dns-fp-2",
                domain_native_id=domain,
                object_type=FirewallObjectType.NETWORK,
                normalized_value="192.0.2.53",
                sharing_mode="shared_use",
            ),
            DiscoveredObject(
                f"{prefix}-object-group",
                "application-and-dns",
                "1",
                f"{prefix}-group-fp-1",
                domain_native_id=domain,
                object_type=FirewallObjectType.NETWORK_GROUP,
                referenced_object_native_ids=(private_object, shared_object),
            ),
            DiscoveredObject(
                service_object,
                "HTTPS",
                "1",
                f"{prefix}-service-fp-1",
                domain_native_id=domain,
                object_type=FirewallObjectType.PORT_SERVICE,
                normalized_value="tcp/443",
                sharing_mode="shared_use",
            ),
            DiscoveredObject(
                f"{prefix}-object-finance-service",
                "FINANCE__API-SERVICE",
                "1",
                f"{prefix}-finance-service-fp-1",
                domain_native_id=domain,
                object_type=FirewallObjectType.PORT_SERVICE,
                normalized_value="tcp/9443",
            ),
            DiscoveredObject(
                f"{prefix}-object-url",
                "Corporate portal URL",
                "1",
                f"{prefix}-url-fp-1",
                domain_native_id=domain,
                object_type=FirewallObjectType.URL,
                normalized_value="portal.example.test",
            ),
            DiscoveredObject(
                f"{prefix}-object-finance-url",
                "FINANCE__PORTAL",
                "1",
                f"{prefix}-finance-url-fp-1",
                domain_native_id=domain,
                object_type=FirewallObjectType.URL,
                normalized_value="finance.example.test",
            ),
            DiscoveredObject(
                application_object,
                "Web browsing",
                "1",
                f"{prefix}-application-fp-1",
                domain_native_id=domain,
                object_type=FirewallObjectType.APPLICATION,
                normalized_value="web-browsing",
                sharing_mode="shared_use",
            ),
            DiscoveredObject(
                f"{prefix}-object-app-filter",
                "Business applications",
                "1",
                f"{prefix}-application-filter-fp-1",
                domain_native_id=domain,
                object_type=FirewallObjectType.APPLICATION_FILTER,
                normalized_value="category=business",
            ),
        ]
        self._transactions: dict[str, ProviderExecutionResult] = {}

    def set_scenario(self, scenario: MockScenario) -> None:
        """Select a deterministic read failure without adding provider writes."""
        self.scenario = scenario

    def simulate_rule_drift(self) -> None:
        """Change one native version/fingerprint for reconciliation tests."""
        current = self._rules[0]
        self._rules[0] = replace(current, native_version="5", fingerprint=f"{self.kind}-drift-5")

    def simulate_new_object(self) -> None:
        domain = self._domains[0].native_id
        self._objects.append(
            DiscoveredObject(
                f"{self.kind}-object-new",
                "newly-discovered-host",
                "1",
                f"{self.kind}-new-fp-1",
                domain_native_id=domain,
                object_type=FirewallObjectType.NETWORK,
                normalized_value="198.51.100.10",
            )
        )

    def simulate_deleted_rule(self) -> None:
        self._rules = self._rules[1:]

    def _check_available(self) -> None:
        if self.scenario is MockScenario.UNAVAILABLE:
            raise ProviderUnavailableError

    def _page(self, items: list[T], page: PageRequest) -> ProviderPage[T]:
        self._check_available()
        try:
            offset = int(page.cursor or "0")
        except ValueError as exc:
            raise ProviderPaginationError from exc
        if self.scenario is MockScenario.FAIL_SECOND_PAGE and offset > 0:
            raise ProviderPaginationError
        selected = tuple(items[offset : offset + page.limit])
        next_offset = offset + len(selected)
        cursor = str(next_offset) if next_offset < len(items) else None
        return ProviderPage(selected, cursor)

    async def information(self) -> ProviderInfo:
        self._check_available()
        return ProviderInfo(
            provider=self.kind,
            display_name=f"Local {self.kind.upper()} Mock",
            provider_version=f"mock-{self.kind}-1.0",
            capabilities=self._capabilities,
            evidence_profile=ProviderEvidenceProfile.MOCK,
            writable=True,
        )

    async def discover(self) -> ProviderInventory:
        info = await self.information()
        return ProviderInventory(
            info.provider,
            info.display_name,
            info.provider_version,
            len(self._policies),
            len(self._objects),
            True,
        )

    async def domains(self, page: PageRequest) -> ProviderPage[DiscoveredDomain]:
        return self._page(self._domains, page)

    async def devices(
        self, domain_native_id: str, page: PageRequest
    ) -> ProviderPage[DiscoveredDevice]:
        return self._page(
            [x for x in self._devices if x.domain_native_id == domain_native_id], page
        )

    async def policies(
        self, domain_native_id: str, page: PageRequest
    ) -> ProviderPage[DiscoveredPolicy]:
        return self._page(
            [x for x in self._policies if x.domain_native_id == domain_native_id], page
        )

    async def categories(
        self, policy_native_id: str, page: PageRequest
    ) -> ProviderPage[DiscoveredCategory]:
        return self._page(
            [x for x in self._categories if x.policy_native_id == policy_native_id], page
        )

    async def rules(self, policy_native_id: str, page: PageRequest) -> ProviderPage[DiscoveredRule]:
        return self._page([x for x in self._rules if x.policy_native_id == policy_native_id], page)

    async def objects(
        self, domain_native_id: str, page: PageRequest
    ) -> ProviderPage[DiscoveredObject]:
        return self._page(
            [x for x in self._objects if x.domain_native_id == domain_native_id], page
        )

    async def zones(self, domain_native_id: str, page: PageRequest) -> ProviderPage[DiscoveredZone]:
        return self._page([x for x in self._zones if x.domain_native_id == domain_native_id], page)

    async def execute_transaction(
        self,
        change_set_id: UUID,
        manager_id: UUID,
        operations: list[dict[str, object]],
    ) -> ProviderExecutionResult:
        """Apply one idempotent mock transaction and retain exact operation outcomes."""
        self._check_available()
        transaction_id = str(uuid5(NAMESPACE_URL, f"mock:{change_set_id}:{manager_id}"))
        existing = self._transactions.get(transaction_id)
        if existing is not None:
            return existing
        results: list[dict[str, object]] = []
        mutation_seen = False
        ambiguous = False
        baseline_versions = {
            item.native_id: item.native_version
            for item in [*self._policies, *self._categories, *self._rules, *self._objects]
        }
        for index, operation in enumerate(operations):
            operation_id = str(operation.get("id", ""))
            if ambiguous:
                results.append(
                    self._result(
                        operation_id,
                        OperationStatus.NOT_ATTEMPTED,
                        False,
                        failure={"code": "PRIOR_RESULT_AMBIGUOUS"},
                    )
                )
                continue
            payload = self._operation_payload(operation)
            behavior = str(payload.get("mock_behavior", "success"))
            if behavior == "timeout_before_mutation":
                results.append(
                    self._result(
                        operation_id,
                        OperationStatus.FAILED,
                        False,
                        failure={"code": "TIMEOUT_BEFORE_MUTATION", "retry_safe": True},
                    )
                )
                continue
            if behavior in {"provider_failure", "rate_limit", "partial_failure"}:
                code = {
                    "provider_failure": "PROVIDER_API_FAILURE",
                    "rate_limit": "PROVIDER_RATE_LIMITED",
                    "partial_failure": "PROVIDER_PARTIAL_FAILURE",
                }[behavior]
                results.append(
                    self._result(
                        operation_id,
                        OperationStatus.FAILED,
                        False,
                        failure={"code": code, "retry_safe": behavior != "partial_failure"},
                    )
                )
                continue
            try:
                provider_resource_id, mutated = self._apply_operation(
                    transaction_id, index, operation, payload, baseline_versions
                )
            except ValueError as exc:
                results.append(
                    self._result(
                        operation_id,
                        OperationStatus.CONFLICT,
                        False,
                        failure={"code": str(exc), "retry_safe": False},
                    )
                )
                continue
            mutation_seen = mutation_seen or mutated
            if behavior == "timeout_after_mutation":
                ambiguous = True
                results.append(
                    self._result(
                        operation_id,
                        OperationStatus.AMBIGUOUS,
                        "unknown",
                        provider_resource_id=provider_resource_id,
                        provider_resource=self._provider_resource(provider_resource_id),
                        failure={
                            "code": "TIMEOUT_AFTER_MUTATION",
                            "retry_safe": False,
                            "reconciliation_required": True,
                        },
                    )
                )
            else:
                results.append(
                    self._result(
                        operation_id,
                        OperationStatus.SUCCEEDED,
                        mutated,
                        provider_resource_id=provider_resource_id,
                        provider_resource=self._provider_resource(provider_resource_id),
                    )
                )
        statuses = {str(item["status"]) for item in results}
        if OperationStatus.AMBIGUOUS.value in statuses:
            state = ProviderTransactionState.RECONCILIATION_REQUIRED
        elif OperationStatus.CONFLICT.value in statuses and not mutation_seen:
            state = ProviderTransactionState.CONFLICT
        elif statuses == {OperationStatus.SUCCEEDED.value}:
            state = ProviderTransactionState.SUCCEEDED
        elif OperationStatus.SUCCEEDED.value in statuses or mutation_seen:
            state = ProviderTransactionState.PARTIALLY_SUCCEEDED
        else:
            state = ProviderTransactionState.FAILED
        failures = [item for item in results if item["status"] != OperationStatus.SUCCEEDED.value]
        outcome = ProviderExecutionResult(
            state=state,
            operation_results=results,
            failure_info={"operation_failures": failures} if failures else {},
            reconciliation_required=ambiguous,
            external_operation_id=transaction_id,
        )
        self._transactions[transaction_id] = outcome
        return outcome

    def transaction_result(self, external_operation_id: str) -> ProviderExecutionResult | None:
        """Return the retained result used to reconcile ambiguous mock outcomes."""
        return self._transactions.get(external_operation_id)

    def _apply_operation(
        self,
        transaction_id: str,
        index: int,
        operation: dict[str, object],
        payload: dict[str, object],
        baseline_versions: dict[str, str | None],
    ) -> tuple[str, bool]:
        kind = ChangeOperationKind(str(operation["kind"]))
        required = {
            ChangeOperationKind.CREATE_RULE: "access_rule_create",
            ChangeOperationKind.MODIFY_RULE: "access_rule_update",
            ChangeOperationKind.DELETE_RULE: "access_rule_delete",
            ChangeOperationKind.MOVE_RULE: "rule_ordering",
            ChangeOperationKind.ENSURE_RULE_CATEGORY: "rule_category_mutation",
        }.get(kind)
        if kind in {
            ChangeOperationKind.CREATE_OBJECT,
            ChangeOperationKind.MODIFY_OBJECT,
            ChangeOperationKind.DELETE_OBJECT,
        }:
            object_type = FirewallObjectType(str(payload["object_type"]))
            required = {
                FirewallObjectType.NETWORK: "network_object_create",
                FirewallObjectType.PORT_SERVICE: "port_service_object_create",
                FirewallObjectType.URL: "url_object_create",
                FirewallObjectType.APPLICATION: "application_object_create",
                FirewallObjectType.APPLICATION_FILTER: "application_object_create",
            }[object_type]
            if kind is not ChangeOperationKind.CREATE_OBJECT:
                required = {
                    FirewallObjectType.NETWORK: "network_object_mutation",
                    FirewallObjectType.PORT_SERVICE: "port_service_object_mutation",
                    FirewallObjectType.URL: "url_object_mutation",
                    FirewallObjectType.APPLICATION: "application_object_mutation",
                    FirewallObjectType.APPLICATION_FILTER: "application_object_mutation",
                }[object_type]
        if required is None or self._capabilities.get(required) is not CapabilityStatus.SUPPORTED:
            raise ValueError("PROVIDER_CAPABILITY_UNAVAILABLE")
        if (
            kind is ChangeOperationKind.CREATE_RULE
            and payload.get("position") is not None
            and self._capabilities.get("rule_ordering") is not CapabilityStatus.SUPPORTED
        ):
            raise ValueError("PROVIDER_CAPABILITY_UNAVAILABLE")
        policy = self._policy(str(payload["policy_native_id"]))
        expected_policy_version = payload.get("expected_policy_version")
        if expected_policy_version is not None and str(expected_policy_version) != str(
            baseline_versions.get(policy.native_id)
        ):
            raise ValueError("STALE_PROVIDER_REVISION")
        resource_id = str(
            uuid5(NAMESPACE_URL, f"{self.kind}:{transaction_id}:{index}:{operation['id']}")
        )
        if kind is ChangeOperationKind.ENSURE_RULE_CATEGORY:
            return self._ensure_category(policy, payload, resource_id, baseline_versions)
        if kind is ChangeOperationKind.CREATE_OBJECT:
            return self._create_object(policy, payload, resource_id)
        if kind in {ChangeOperationKind.MODIFY_OBJECT, ChangeOperationKind.DELETE_OBJECT}:
            return self._mutate_object(kind, policy, payload, baseline_versions)
        if kind is ChangeOperationKind.CREATE_RULE:
            return self._create_rule(policy, payload, resource_id)
        rule = self._rule(str(payload["rule_native_id"]), policy.native_id)
        expected_rule_version = payload.get("expected_rule_version")
        if expected_rule_version is not None and str(expected_rule_version) != str(
            baseline_versions.get(rule.native_id)
        ):
            raise ValueError("STALE_PROVIDER_REVISION")
        if kind is ChangeOperationKind.DELETE_RULE:
            self._rules.remove(rule)
            self._bump_policy(policy)
            return rule.native_id, True
        category = self._category(str(payload["category_native_id"]), policy.native_id)
        if kind is ChangeOperationKind.MOVE_RULE:
            position = self._validated_position(category, int(str(payload["position"])))
            updated = replace(
                rule,
                category_native_id=category.native_id,
                position=position,
                native_version=str(int(rule.native_version or "0") + 1),
                fingerprint=f"{self.kind}-rule-{rule.native_id}-{position}",
            )
        else:
            updated = self._rule_from_payload(rule.native_id, policy, category, payload, rule)
        self._rules[self._rules.index(rule)] = updated
        self._bump_policy(policy)
        return rule.native_id, True

    def _create_rule(
        self, policy: DiscoveredPolicy, payload: dict[str, object], resource_id: str
    ) -> tuple[str, bool]:
        category = self._category(str(payload["category_native_id"]), policy.native_id)
        position = self._validated_position(
            category, int(str(payload.get("position", category.position)))
        )
        self._rules.append(
            self._rule_from_payload(resource_id, policy, category, payload, None, position)
        )
        self._bump_policy(policy)
        return resource_id, True

    def _rule_from_payload(
        self,
        native_id: str,
        policy: DiscoveredPolicy,
        category: DiscoveredCategory,
        payload: dict[str, object],
        existing: DiscoveredRule | None,
        position: int | None = None,
    ) -> DiscoveredRule:
        object_references: list[DiscoveredObjectReference] = []
        for key, element in (
            ("source_object_native_ids", RuleObjectElement.SOURCE_NETWORK),
            ("destination_object_native_ids", RuleObjectElement.DESTINATION_NETWORK),
            ("port_object_native_ids", RuleObjectElement.PORT_SERVICE),
            ("application_object_native_ids", RuleObjectElement.APPLICATION),
            ("url_object_native_ids", RuleObjectElement.URL),
        ):
            values = payload.get(key, [])
            if isinstance(values, list):
                object_references.extend(
                    DiscoveredObjectReference(str(value), element)
                    for value in cast("list[object]", values)
                )
        zone_references: list[DiscoveredZoneReference] = []
        for key, element in (
            ("source_zone_native_ids", ZoneElement.SOURCE),
            ("destination_zone_native_ids", ZoneElement.DESTINATION),
        ):
            values = payload.get(key, [])
            if isinstance(values, list):
                zone_references.extend(
                    DiscoveredZoneReference(str(value), element)
                    for value in cast("list[object]", values)
                )
        version = str(int(existing.native_version or "0") + 1) if existing else "1"
        return DiscoveredRule(
            native_id=native_id,
            name=str(payload.get("name", existing.name if existing else "delegated rule")),
            native_version=version,
            fingerprint=f"{self.kind}-rule-{native_id}-{version}",
            policy_native_id=policy.native_id,
            category_native_id=category.native_id,
            action=str(payload.get("action", existing.action if existing else "ALLOW")),
            position=position
            if position is not None
            else int(
                str(payload.get("position", existing.position if existing else category.position))
            ),
            object_references=tuple(object_references)
            if object_references
            else (existing.object_references if existing else ()),
            zone_references=tuple(zone_references)
            if zone_references
            else (existing.zone_references if existing else ()),
        )

    def _create_object(
        self, policy: DiscoveredPolicy, payload: dict[str, object], resource_id: str
    ) -> tuple[str, bool]:
        resolution = payload.get("resolution")
        if isinstance(resolution, dict) and resolution.get("kind") in {
            "EXACT_REUSE",
            "EQUIVALENT_REUSE",
        }:
            existing_native_id = resolution.get("existing_object_native_id")
            if not isinstance(existing_native_id, str):
                raise ValueError("PROVIDER_OBJECT_REUSE_TARGET_MISSING")
            return existing_native_id, False
        object_type = FirewallObjectType(str(payload["object_type"]))
        name = str(payload["provider_name"])
        normalized_value = str(payload["normalized_value"])
        if any(item.name == name for item in self._objects):
            raise ValueError("PROVIDER_OBJECT_NAME_CONFLICT")
        if any(
            item.object_type is object_type and item.normalized_value == normalized_value
            for item in self._objects
        ):
            raise ValueError("PROVIDER_EQUIVALENT_OBJECT_CONFLICT")
        self._objects.append(
            DiscoveredObject(
                native_id=resource_id,
                name=name,
                native_version="1",
                fingerprint=f"{self.kind}-object-{resource_id}-1",
                domain_native_id=policy.domain_native_id,
                object_type=object_type,
                normalized_value=normalized_value,
            )
        )
        self._bump_policy(policy)
        return resource_id, True

    def _mutate_object(
        self,
        kind: ChangeOperationKind,
        policy: DiscoveredPolicy,
        payload: dict[str, object],
        baseline_versions: dict[str, str | None],
    ) -> tuple[str, bool]:
        item = self._object(str(payload["object_native_id"]), policy.domain_native_id)
        expected_version = payload.get("expected_object_version")
        if expected_version is not None and str(expected_version) != str(
            baseline_versions.get(item.native_id)
        ):
            raise ValueError("STALE_PROVIDER_REVISION")
        if payload.get("expected_provider_name") != item.name:
            raise ValueError("PROVIDER_OWNERSHIP_NAME_CONFLICT")
        if kind is ChangeOperationKind.DELETE_OBJECT:
            referenced_by_rule = any(
                reference.object_native_id == item.native_id
                for rule in self._rules
                for reference in rule.object_references
            )
            referenced_by_object = any(
                item.native_id in candidate.referenced_object_native_ids
                for candidate in self._objects
            )
            if referenced_by_rule or referenced_by_object:
                raise ValueError("PROVIDER_OBJECT_IN_USE")
            self._objects.remove(item)
            self._bump_policy(policy)
            return item.native_id, True
        normalized_value = str(payload["normalized_value"])
        if any(
            candidate.native_id != item.native_id
            and candidate.object_type is item.object_type
            and candidate.normalized_value == normalized_value
            for candidate in self._objects
        ):
            raise ValueError("PROVIDER_EQUIVALENT_OBJECT_CONFLICT")
        version = str(int(item.native_version or "0") + 1)
        updated = replace(
            item,
            native_version=version,
            fingerprint=f"{self.kind}-object-{item.native_id}-{version}",
            normalized_value=normalized_value,
        )
        self._objects[self._objects.index(item)] = updated
        self._bump_policy(policy)
        return item.native_id, True

    def _ensure_category(
        self,
        policy: DiscoveredPolicy,
        payload: dict[str, object],
        resource_id: str,
        baseline_versions: dict[str, str | None],
    ) -> tuple[str, bool]:
        provider_name = str(payload["provider_name"])
        native_id = payload.get("category_native_id")
        if native_id is not None:
            category = self._category(str(native_id), policy.native_id)
            expected_version = payload.get("expected_category_version")
            if expected_version is not None and str(expected_version) != str(
                baseline_versions.get(category.native_id)
            ):
                raise ValueError("STALE_PROVIDER_REVISION")
            if category.name != provider_name:
                raise ValueError("PROVIDER_CATEGORY_MAPPING_CONFLICT")
            return category.native_id, False
        if any(
            item.policy_native_id == policy.native_id and item.name == provider_name
            for item in self._categories
        ):
            raise ValueError("PROVIDER_CATEGORY_NAME_CONFLICT")
        position = (
            max(
                (
                    item.position
                    for item in self._categories
                    if item.policy_native_id == policy.native_id
                ),
                default=0,
            )
            + 10
        )
        self._categories.append(
            DiscoveredCategory(
                native_id=resource_id,
                name=provider_name,
                native_version="1",
                fingerprint=f"{self.kind}-category-{resource_id}-1",
                policy_native_id=policy.native_id,
                position=position,
            )
        )
        self._bump_policy(policy)
        return resource_id, True

    def _validated_position(self, category: DiscoveredCategory, position: int) -> int:
        ordered = sorted(self._categories, key=lambda item: item.position)
        index = ordered.index(category)
        next_position = ordered[index + 1].position if index + 1 < len(ordered) else 2**31
        if not category.position <= position < next_position:
            raise ValueError("RULE_ORDERING_BOUNDARY_VIOLATION")
        return position

    def _bump_policy(self, policy: DiscoveredPolicy) -> None:
        version = str(int(policy.native_version or "0") + 1)
        self._policies[self._policies.index(policy)] = replace(
            policy,
            native_version=version,
            fingerprint=f"{self.kind}-policy-{policy.native_id}-{version}",
        )

    def _policy(self, native_id: str) -> DiscoveredPolicy:
        try:
            return next(item for item in self._policies if item.native_id == native_id)
        except StopIteration as exc:
            raise ValueError("PROVIDER_POLICY_NOT_FOUND") from exc

    def _category(self, native_id: str, policy_native_id: str) -> DiscoveredCategory:
        try:
            return next(
                item
                for item in self._categories
                if item.native_id == native_id and item.policy_native_id == policy_native_id
            )
        except StopIteration as exc:
            raise ValueError("PROVIDER_CATEGORY_NOT_FOUND") from exc

    def _rule(self, native_id: str, policy_native_id: str) -> DiscoveredRule:
        try:
            return next(
                item
                for item in self._rules
                if item.native_id == native_id and item.policy_native_id == policy_native_id
            )
        except StopIteration as exc:
            raise ValueError("PROVIDER_RULE_NOT_FOUND") from exc

    def _object(self, native_id: str, domain_native_id: str) -> DiscoveredObject:
        try:
            return next(
                item
                for item in self._objects
                if item.native_id == native_id and item.domain_native_id == domain_native_id
            )
        except StopIteration as exc:
            raise ValueError("PROVIDER_OBJECT_NOT_FOUND") from exc

    def _provider_resource(self, native_id: str) -> dict[str, object]:
        for item in [*self._objects, *self._categories, *self._rules]:
            if item.native_id != native_id:
                continue
            result: dict[str, object] = {
                "native_id": item.native_id,
                "name": item.name,
                "native_version": item.native_version,
                "fingerprint": item.fingerprint,
            }
            if isinstance(item, DiscoveredObject):
                result.update(
                    {
                        "object_type": item.object_type.value,
                        "normalized_value": item.normalized_value,
                    }
                )
            elif isinstance(item, DiscoveredCategory):
                result["position"] = item.position
            return result
        return {}

    @staticmethod
    def _operation_payload(operation: dict[str, object]) -> dict[str, object]:
        value = operation.get("provider_payload", operation.get("payload", {}))
        if not isinstance(value, dict):
            raise ValueError("INVALID_PROVIDER_OPERATION")
        return cast("dict[str, object]", value)

    @staticmethod
    def _result(
        operation_id: str,
        status: OperationStatus,
        mutated: bool | str,
        *,
        provider_resource_id: str | None = None,
        provider_resource: dict[str, object] | None = None,
        failure: dict[str, object] | None = None,
    ) -> dict[str, object]:
        result: dict[str, object] = {
            "operation_id": operation_id,
            "status": status.value,
            "mutated": mutated,
        }
        if provider_resource_id is not None:
            result["provider_resource_id"] = provider_resource_id
        if provider_resource:
            result["provider_resource"] = provider_resource
        if failure:
            result["failure"] = failure
        return result
