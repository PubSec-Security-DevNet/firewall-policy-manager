# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Remove all OIDC providers from one organization for access recovery."""

import argparse
import sys
from uuid import UUID

from sqlalchemy import delete, select

from firewall_manager.persistence.database import new_session
from firewall_manager.persistence.models import (
    ExternalIdentity,
    OidcProvider,
    Organization,
    SecretRecord,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--organization-id", type=UUID)
    target.add_argument("--organization-name")
    parser.add_argument("--list-organizations", action="store_true")
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="confirm deletion of provider configuration and encrypted OIDC secrets",
    )
    args = parser.parse_args()

    with new_session() as session, session.begin():
        if args.list_organizations:
            for organization in session.scalars(select(Organization).order_by(Organization.name)):
                sys.stdout.write(f"{organization.id}\t{organization.name}\n")
            return
        organization = _organization(session, args.organization_id, args.organization_name)
        if organization is None:
            raise SystemExit("Organization was not found or selection was ambiguous.")
        providers = list(
            session.scalars(
                select(OidcProvider).where(OidcProvider.organization_id == organization.id)
            )
        )
        if not args.confirm:
            raise SystemExit(
                f"Refusing to remove {len(providers)} OIDC provider(s) from "
                f"{organization.name!r}. Re-run with --confirm."
            )
        provider_ids = [provider.provider_id for provider in providers]
        secret_ids = [provider.secret_reference for provider in providers]
        if provider_ids:
            session.execute(
                delete(ExternalIdentity).where(ExternalIdentity.provider_id.in_(provider_ids))
            )
            session.execute(
                delete(OidcProvider).where(OidcProvider.organization_id == organization.id)
            )
            session.execute(delete(SecretRecord).where(SecretRecord.id.in_(secret_ids)))
        sys.stdout.write(
            f"Removed {len(providers)} OIDC provider(s) from {organization.name}. "
            "Users and organization data were preserved.\n"
        )


def _organization(
    session, organization_id: UUID | None, organization_name: str | None
) -> Organization | None:
    if organization_id is not None:
        return session.get(Organization, organization_id)
    if organization_name is not None:
        return session.scalar(select(Organization).where(Organization.name == organization_name))
    organizations = list(session.scalars(select(Organization).order_by(Organization.name)))
    return organizations[0] if len(organizations) == 1 else None


if __name__ == "__main__":
    main()
