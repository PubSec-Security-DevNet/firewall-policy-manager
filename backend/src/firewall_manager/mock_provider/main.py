"""HTTP façade over the deterministic normalized FMC/SCC mock provider."""

from dataclasses import asdict
from typing import Annotated, Literal
from uuid import UUID

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict

from firewall_manager.application.errors import ProviderPaginationError
from firewall_manager.domain.models import PageRequest, ProviderKind
from firewall_manager.providers.mock import DeterministicMockProvider


class MockSettings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    provider_kind: Literal["fmc", "scc"]


class DiscoveryResponse(BaseModel):
    provider: Literal["fmc", "scc"]
    display_name: str
    provider_version: str
    policy_count: int
    object_count: int
    evidence_profile: Literal["mock", "real"]
    writable: Literal[True] = True


class TransactionRequest(BaseModel):
    """Provider-neutral mock transaction envelope."""

    change_set_id: UUID
    manager_id: UUID
    operations: list[dict[str, object]]


settings = MockSettings()  # pyright: ignore[reportCallIssue]
provider = DeterministicMockProvider(ProviderKind(settings.provider_kind))
app = FastAPI(title=f"Mock {settings.provider_kind.upper()} provider", version="1.0.0")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "provider": settings.provider_kind}


@app.get("/api/v1/info")
async def information() -> dict[str, object]:
    info = await provider.information()
    return {
        "provider": info.provider,
        "display_name": info.display_name,
        "provider_version": info.provider_version,
        "capabilities": info.capabilities,
        "evidence_profile": info.evidence_profile,
        "writable": info.writable,
    }


@app.get("/api/v1/discovery")
async def discovery() -> DiscoveryResponse:
    inventory = await provider.discover()
    return DiscoveryResponse(**asdict(inventory))


@app.post("/api/v1/transactions")
async def execute_transaction(body: TransactionRequest) -> dict[str, object]:
    outcome = await provider.execute_transaction(
        body.change_set_id, body.manager_id, body.operations
    )
    return outcome.to_dict()


@app.get("/api/v1/transactions/{external_operation_id}")
async def reconcile_transaction(external_operation_id: str) -> dict[str, object]:
    outcome = provider.transaction_result(external_operation_id)
    if outcome is None:
        raise HTTPException(status_code=404, detail="transaction not found")
    return outcome.to_dict()


@app.get("/api/v1/resources/{resource}")
async def resources(  # noqa: PLR0913, PLR0917 -- provider fixture query dimensions
    resource: Literal[
        "domains",
        "devices",
        "policies",
        "categories",
        "intrusion_policies",
        "variable_sets",
        "rules",
        "objects",
        "zones",
        "file_policies",
    ],
    parent: str | None = None,
    cursor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
    applications_only: bool = False,
    include_applications: bool = True,
) -> dict[str, object]:
    page_request = PageRequest(limit=limit, cursor=cursor)
    try:
        if resource == "domains":
            page = await provider.domains(page_request)
        elif parent is None:
            raise HTTPException(status_code=422, detail="parent is required")
        elif resource == "devices":
            page = await provider.devices(parent, page_request)
        elif resource == "policies":
            page = await provider.policies(parent, page_request)
        elif resource == "categories":
            page = await provider.categories(parent, page_request)
        elif resource == "intrusion_policies":
            page = await provider.intrusion_policies(parent, page_request)
        elif resource == "variable_sets":
            page = await provider.variable_sets(parent, page_request)
        elif resource == "file_policies":
            page = await provider.file_policies(parent, page_request)
        elif resource == "rules":
            page = await provider.rules(parent, page_request)
        elif resource == "zones":
            page = await provider.zones(parent, page_request)
        else:
            page = await provider.objects(
                parent,
                page_request,
                applications_only=applications_only,
                include_applications=include_applications,
            )
    except ProviderPaginationError as exc:
        raise HTTPException(status_code=424, detail="page unavailable") from exc
    return {"items": [asdict(item) for item in page.items], "next_cursor": page.next_cursor}
