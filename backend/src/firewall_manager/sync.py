# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Canonical local command for synchronizing all configured mock managers."""

import asyncio

from sqlalchemy import select

from firewall_manager.application.synchronization import SynchronizationService
from firewall_manager.config import get_settings
from firewall_manager.domain.models import ProviderKind
from firewall_manager.persistence.database import new_session
from firewall_manager.persistence.models import FirewallManager
from firewall_manager.persistence.repositories import SqlSyncRepository
from firewall_manager.providers.fmc import FmcProviderReader
from firewall_manager.providers.scc import SccProviderReader
from firewall_manager.seed import seed_authorization_scenarios


async def synchronize_all() -> None:
    """Run a complete read-only sync for each seeded manager."""
    settings = get_settings()
    with new_session() as session:
        managers = list(
            session.scalars(
                select(FirewallManager)
                .where(FirewallManager.is_mock.is_(True))
                .order_by(FirewallManager.id)
            )
        )
        repository = SqlSyncRepository(session)
        for manager in managers:
            provider = (
                FmcProviderReader(str(settings.fmc_base_url))
                if ProviderKind(manager.provider) is ProviderKind.FMC
                else SccProviderReader(str(settings.scc_base_url))
            )
            result = await SynchronizationService(repository, page_size=2).synchronize(
                manager.id, provider
            )
            if result.status.value != "COMPLETED":
                msg = f"sync failed for manager {manager.id}: {result.status}"
                raise RuntimeError(msg)
        seed_authorization_scenarios(session)


if __name__ == "__main__":
    asyncio.run(synchronize_all())
