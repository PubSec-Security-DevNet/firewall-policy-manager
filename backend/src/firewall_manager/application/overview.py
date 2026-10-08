# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Read-only system overview use case shared by delivery interfaces."""

import asyncio
from dataclasses import asdict

from firewall_manager.application.authorization import require_action
from firewall_manager.application.errors import ResourceOutOfScopeError
from firewall_manager.application.ports import OverviewRepository, ProviderReader
from firewall_manager.domain.models import Action, Principal, ProviderEvidenceProfile


class OverviewService:
    """Build a bounded overview after server-side authorization."""

    def __init__(
        self, repository: OverviewRepository, providers: tuple[ProviderReader, ...]
    ) -> None:
        self._repository = repository
        self._providers = providers

    async def get(self, principal: Principal) -> dict[str, object]:
        """Return normalized local and provider inventory for the principal's organization."""
        require_action(principal, Action.READ)
        organization = self._repository.organization_name(principal.organization_id)
        if organization is None:
            raise ResourceOutOfScopeError
        if principal.role != "admin":
            # No explicit Group+Policy context: use the delegated context endpoint.
            return {
                "organization": organization,
                "counts": dict.fromkeys(
                    ("managers", "policies", "rules", "objects", "change_sets"), 0
                ),
                "providers": [],
            }
        normalized_summaries = getattr(self._repository, "provider_summaries", None)
        if normalized_summaries is not None:
            providers = normalized_summaries(principal.organization_id)
        else:
            providers = [
                {
                    key: value
                    for key, value in asdict(inventory).items()
                    if key != "evidence_profile"
                }
                for inventory in await asyncio.gather(
                    *(provider.discover() for provider in self._providers)
                )
                if inventory.evidence_profile is not ProviderEvidenceProfile.MOCK
            ]
        return {
            "organization": organization,
            "counts": self._repository.counts(principal.organization_id),
            "providers": providers,
        }
