"""REST contract and safe error-envelope tests."""

from uuid import UUID

from fastapi.testclient import TestClient

from firewall_manager.api.dependencies import (
    get_administration_repository,
    get_authorization_repository,
    get_overview_repository,
    get_principal,
)
from firewall_manager.api.routes import get_provider_readers
from firewall_manager.domain.models import (
    AuthorizationDecision,
    Principal,
    ProviderInventory,
    ProviderKind,
)
from firewall_manager.main import app


class FakeRepository:
    def __init__(self) -> None:
        self.requested_organization_ids: list[UUID] = []

    def principal_by_email(self, email: str) -> Principal | None:
        return None

    def organization_name(self, organization_id: UUID) -> str | None:
        return "Example Organization"

    def counts(self, organization_id: UUID) -> dict[str, int]:
        return {"managers": 2, "policies": 1, "rules": 1, "objects": 2, "change_sets": 2}

    def list_managers(
        self, organization_id: UUID, offset: int, limit: int
    ) -> tuple[list[dict[str, object]], int]:
        self.requested_organization_ids.append(organization_id)
        rows: list[dict[str, object]] = [
            {
                "id": UUID("40000000-0000-0000-0000-000000000001"),
                "provider": "fmc",
                "display_name": "Mock FMC",
                "read_only": True,
                "provider_version": "mock-1",
                "revision": 1,
            },
            {
                "id": UUID("40000000-0000-0000-0000-000000000002"),
                "provider": "scc",
                "display_name": "Mock SCC",
                "read_only": True,
                "provider_version": "mock-1",
                "revision": 1,
            },
        ]
        return rows[offset : offset + limit], len(rows)

    def list_policies(
        self, organization_id: UUID, manager_id: UUID | None, offset: int, limit: int
    ) -> tuple[list[dict[str, object]], int]:
        self.requested_organization_ids.append(organization_id)
        return [], 0

    def list_rules(
        self, organization_id: UUID, policy_id: UUID | None, offset: int, limit: int
    ) -> tuple[list[dict[str, object]], int]:
        self.requested_organization_ids.append(organization_id)
        return [], 0

    def list_objects(
        self, organization_id: UUID, manager_id: UUID | None, offset: int, limit: int
    ) -> tuple[list[dict[str, object]], int]:
        self.requested_organization_ids.append(organization_id)
        return [], 0

    def provider_status(self, organization_id: UUID) -> list[dict[str, object]]:
        self.requested_organization_ids.append(organization_id)
        return []


class FakeProvider:
    kind = ProviderKind.FMC

    async def discover(self) -> ProviderInventory:
        return ProviderInventory(self.kind, "Mock FMC", "mock-1", 1, 2, False)


def viewer() -> Principal:
    return Principal(
        UUID("30000000-0000-0000-0000-000000000001"),
        UUID("10000000-0000-0000-0000-000000000001"),
        "viewer@example.test",
        "viewer",
    )


def fake_repository() -> FakeRepository:
    return FakeRepository()


class FakeAuthorizationApiRepository:
    finance = UUID("20000000-0000-0000-0000-000000000001")
    engineering = UUID("20000000-0000-0000-0000-000000000002")
    policy = UUID("50000000-0000-0000-0000-000000000001")
    manager = UUID("40000000-0000-0000-0000-000000000001")

    def user_state(self, user_id: UUID, organization_id: UUID) -> tuple[bool, int] | None:
        return True, 1

    def membership_state(
        self, user_id: UUID, group_id: UUID, organization_id: UUID
    ) -> tuple[bool, int] | None:
        return (True, 1) if group_id in {self.finance, self.engineering} else None

    def policy_state(self, policy_id: UUID, organization_id: UUID) -> tuple[UUID, str, int] | None:
        return (self.manager, "OBSERVED", 1) if policy_id == self.policy else None

    def policy_capabilities(
        self, user_id: UUID, group_id: UUID, policy_id: UUID, organization_id: UUID
    ) -> tuple[set[str], int, bool]:
        return (
            ({"view"}, 1, True)
            if group_id in {self.finance, self.engineering}
            else (set(), 0, False)
        )

    def object_grant_state(self, *args: object) -> None:
        return None

    def zone_grant_state(self, *args: object) -> None:
        return None

    def ip_range_grants(self, *args: object) -> tuple[list[str], int]:
        return [], 0

    def object_create_grant_state(self, *args: object) -> None:
        return None

    def equivalent_object_id(self, *args: object) -> None:
        return None

    def rule_owner_state(self, *args: object) -> None:
        return None

    def category_mapping_state(
        self, group_id: UUID, policy_id: UUID, category_id: UUID, organization_id: UUID
    ) -> tuple[UUID, str, int] | None:
        return None

    def record_authorization_decision(
        self, decision: AuthorizationDecision, *, interface: str, correlation_id: str | None
    ) -> None:
        pass

    def active_groups_for_user(
        self, user_id: UUID, organization_id: UUID
    ) -> list[dict[str, object]]:
        return [
            {"id": self.finance, "name": "Finance", "provider_slug": "FINANCE", "revision": 1},
            {
                "id": self.engineering,
                "name": "Engineering",
                "provider_slug": "ENGINEERING",
                "revision": 1,
            },
        ]

    def delegated_context_view(
        self, user_id: UUID, group_id: UUID, policy_id: UUID, organization_id: UUID
    ) -> dict[str, object] | None:
        group_name = "FINANCE" if group_id == self.finance else "ENGINEERING"
        return {
            "policy": {
                "id": self.policy,
                "manager_id": self.manager,
                "name": "Corporate-ACP",
                "management_state": "OBSERVED",
                "revision": 1,
            },
            "capabilities": ["view"],
            "rules": [],
            "objects": [
                {
                    "id": UUID(
                        f"60000000-0000-0000-0000-00000000000{1 if group_name == 'FINANCE' else 2}"
                    ),
                    "name": f"{group_name}-SERVERS",
                    "object_type": "NETWORK",
                }
            ],
            "zones": [],
            "categories": [],
            "ip_ranges": ["10.20.0.0/16" if group_name == "FINANCE" else "172.16.0.0/12"],
            "object_create": [],
        }

    def delegated_policies(
        self, user_id: UUID, group_id: UUID, organization_id: UUID
    ) -> list[dict[str, object]]:
        return [
            {
                "id": self.policy,
                "manager_id": self.manager,
                "name": "Corporate-ACP",
                "management_state": "OBSERVED",
                "revision": 1,
            }
        ]


class FakeAdministrationRepository:
    def __init__(self) -> None:
        self.revocations: list[tuple[UUID, UUID, str, UUID, int]] = []

    def authorization_snapshot(self, organization_id: UUID) -> dict[str, object]:
        return {
            "users": [],
            "groups": [],
            "policies": [],
            "objects": [],
            "zones": [],
            "categories": [],
            "memberships": [],
            "policy_delegations": [],
            "direct_user_policy_grants": [],
            "object_use_grants": [],
            "zone_grants": [],
            "ip_range_grants": [],
            "object_create_grants": [],
            "category_mappings": [],
        }

    def revoke_authorization_resource(
        self,
        organization_id: UUID,
        actor_user_id: UUID,
        resource: str,
        resource_id: UUID,
        expected_revision: int,
    ) -> None:
        self.revocations.append(
            (organization_id, actor_user_id, resource, resource_id, expected_revision)
        )


def test_live_endpoint_and_correlation_id() -> None:
    response = TestClient(app).get("/api/v1/health/live", headers={"X-Correlation-ID": "test-id"})
    assert response.status_code == 200
    assert response.headers["X-Correlation-ID"] == "test-id"


def test_overview_uses_application_service_contract() -> None:
    app.dependency_overrides[get_principal] = viewer
    app.dependency_overrides[get_overview_repository] = fake_repository
    app.dependency_overrides[get_provider_readers] = lambda: (FakeProvider(),)
    try:
        response = TestClient(app).get("/api/v1/overview")
    finally:
        app.dependency_overrides.pop(get_principal)
        app.dependency_overrides.pop(get_overview_repository)
        app.dependency_overrides[get_provider_readers] = lambda: (FakeProvider(),)
    assert response.status_code == 200
    assert response.json()["providers"][0]["writable"] is False


def test_unknown_identity_has_safe_error_envelope() -> None:
    app.dependency_overrides[get_overview_repository] = fake_repository
    try:
        response = TestClient(app).get(
            "/api/v1/session",
            headers={"X-Correlation-ID": "denied-id", "X-Dev-User": "missing@example.test"},
        )
    finally:
        app.dependency_overrides.pop(get_overview_repository)
    assert response.status_code == 401
    assert response.json() == {
        "error": {
            "code": "NOT_AUTHENTICATED",
            "message": "Authentication is required.",
            "details": {},
            "correlation_id": "denied-id",
        }
    }


def test_inventory_pagination_is_bounded_and_organization_scoped() -> None:
    repository = FakeRepository()
    repository.requested_organization_ids = []
    app.dependency_overrides[get_principal] = viewer
    app.dependency_overrides[get_overview_repository] = lambda: repository
    try:
        first = TestClient(app).get("/api/v1/firewall-managers?limit=1")
        second = TestClient(app).get(
            "/api/v1/firewall-managers",
            params={"limit": 1, "cursor": first.json()["next_cursor"]},
        )
    finally:
        app.dependency_overrides.pop(get_principal)
        app.dependency_overrides.pop(get_overview_repository)
    assert [first.json()["items"][0]["provider"], second.json()["items"][0]["provider"]] == [
        "fmc",
        "scc",
    ]
    assert first.json()["total"] == 2
    assert set(repository.requested_organization_ids) == {viewer().organization_id}


def test_invalid_pagination_uses_canonical_error_envelope_and_correlation_id() -> None:
    app.dependency_overrides[get_principal] = viewer
    app.dependency_overrides[get_overview_repository] = fake_repository
    try:
        response = TestClient(app).get(
            "/api/v1/firewall-managers?limit=101", headers={"X-Correlation-ID": "bad-page"}
        )
    finally:
        app.dependency_overrides.pop(get_principal)
        app.dependency_overrides.pop(get_overview_repository)
    assert response.status_code == 422
    assert response.json()["error"] == {
        "code": "INVALID_REQUEST",
        "message": "The request parameters are invalid.",
        "details": {},
        "correlation_id": "bad-page",
    }


def test_invalid_cursor_and_unknown_route_use_canonical_error_envelopes() -> None:
    app.dependency_overrides[get_principal] = viewer
    app.dependency_overrides[get_overview_repository] = fake_repository
    try:
        cursor_response = TestClient(app).get(
            "/api/v1/firewall-managers?cursor=not-base64!",
            headers={"X-Correlation-ID": "bad-cursor"},
        )
        missing_response = TestClient(app).get(
            "/api/v1/does-not-exist", headers={"X-Correlation-ID": "missing-route"}
        )
    finally:
        app.dependency_overrides.pop(get_principal)
        app.dependency_overrides.pop(get_overview_repository)
    assert cursor_response.status_code == 422
    assert cursor_response.json()["error"]["code"] == "INVALID_PAGINATION"
    assert cursor_response.json()["error"]["correlation_id"] == "bad-cursor"
    assert missing_response.status_code == 404
    assert missing_response.json()["error"]["code"] == "NOT_FOUND"


def test_delegated_context_is_server_scoped_to_exact_active_group() -> None:
    repository = FakeAuthorizationApiRepository()
    app.dependency_overrides[get_principal] = viewer
    app.dependency_overrides[get_authorization_repository] = lambda: repository
    try:
        finance = TestClient(app).get(
            "/api/v1/delegated/context",
            params={"active_group_id": repository.finance, "policy_id": repository.policy},
        )
        engineering = TestClient(app).get(
            "/api/v1/delegated/context",
            params={"active_group_id": repository.engineering, "policy_id": repository.policy},
        )
        tampered = TestClient(app).get(
            "/api/v1/delegated/context",
            params={
                "active_group_id": UUID("20000000-0000-0000-0000-000000000099"),
                "policy_id": repository.policy,
            },
        )
    finally:
        app.dependency_overrides.pop(get_principal)
        app.dependency_overrides.pop(get_authorization_repository)
    assert finance.status_code == 200
    assert finance.json()["objects"][0]["name"] == "FINANCE-SERVERS"
    assert engineering.json()["objects"][0]["name"] == "ENGINEERING-SERVERS"
    assert tampered.status_code == 403
    assert tampered.json()["error"]["code"] == "RESOURCE_OUT_OF_SCOPE"


def test_normal_user_cannot_administer_grants_but_enabled_admin_can() -> None:
    authorization = FakeAuthorizationApiRepository()
    administration = FakeAdministrationRepository()
    app.dependency_overrides[get_authorization_repository] = lambda: authorization
    app.dependency_overrides[get_administration_repository] = lambda: administration
    client = TestClient(app)
    try:
        app.dependency_overrides[get_principal] = viewer
        denied = client.get("/api/v1/admin/authorization")
        app.dependency_overrides[get_principal] = lambda: Principal(
            viewer().user_id,
            viewer().organization_id,
            "admin@example.test",
            "admin",
        )
        allowed = client.get("/api/v1/admin/authorization")
    finally:
        app.dependency_overrides.pop(get_principal)
        app.dependency_overrides.pop(get_authorization_repository)
        app.dependency_overrides.pop(get_administration_repository)
    assert denied.status_code == 403
    assert allowed.status_code == 200


def test_grant_revocation_is_admin_only_and_revision_checked_at_contract() -> None:
    authorization = FakeAuthorizationApiRepository()
    administration = FakeAdministrationRepository()
    grant_id = UUID("90000000-0000-0000-0000-000000000001")
    app.dependency_overrides[get_authorization_repository] = lambda: authorization
    app.dependency_overrides[get_administration_repository] = lambda: administration
    client = TestClient(app)
    try:
        app.dependency_overrides[get_principal] = viewer
        denied = client.delete(
            f"/api/v1/admin/object-use-grants/{grant_id}", params={"expected_revision": 3}
        )
        app.dependency_overrides[get_principal] = lambda: Principal(
            viewer().user_id,
            viewer().organization_id,
            "admin@example.test",
            "admin",
        )
        allowed = client.delete(
            f"/api/v1/admin/object-use-grants/{grant_id}", params={"expected_revision": 3}
        )
    finally:
        app.dependency_overrides.pop(get_principal)
        app.dependency_overrides.pop(get_authorization_repository)
        app.dependency_overrides.pop(get_administration_repository)
    assert denied.status_code == 403
    assert allowed.status_code == 204
    assert administration.revocations == [
        (
            viewer().organization_id,
            viewer().user_id,
            "object-use-grants",
            grant_id,
            3,
        )
    ]
