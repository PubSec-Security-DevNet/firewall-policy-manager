# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Enable a short-lived operator-controlled OIDC recovery setup window."""

import argparse
import sys
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select

from firewall_manager.application.setup import create_recovery_code, hash_recovery_code
from firewall_manager.config import get_settings
from firewall_manager.persistence.database import new_session
from firewall_manager.persistence.models import OidcProvider, Organization, SetupRecovery


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--organization-id", type=UUID)
    target.add_argument("--organization-name")
    parser.add_argument(
        "--list-organizations",
        action="store_true",
        help="list organizations and exit",
    )
    parser.add_argument("--expires-minutes", type=int, default=30)
    args = parser.parse_args()
    if not 1 <= args.expires_minutes <= 1440:
        raise SystemExit("--expires-minutes must be between 1 and 1440")

    code = create_recovery_code()
    expires_at = datetime.now(UTC) + timedelta(minutes=args.expires_minutes)
    with new_session() as session, session.begin():
        if args.list_organizations:
            for organization in session.scalars(select(Organization).order_by(Organization.name)):
                sys.stdout.write(f"{organization.id}\t{organization.name}\n")
            return
        if args.organization_id is not None:
            organization = session.get(Organization, args.organization_id)
        elif args.organization_name is not None:
            organization = session.scalar(
                select(Organization).where(Organization.name == args.organization_name)
            )
        else:
            organizations = list(session.scalars(select(Organization).order_by(Organization.name)))
            if len(organizations) != 1:
                raise SystemExit(
                    "Recovery requires an organization selection because the database contains "
                    f"{len(organizations)} organizations. Run with --list-organizations."
                )
            organization = organizations[0]
        if organization is None:
            raise SystemExit("Recovery refused: organization was not found.")
        if (
            session.scalar(
                select(OidcProvider.id)
                .where(OidcProvider.organization_id == organization.id)
                .limit(1)
            )
            is not None
        ):
            raise SystemExit("Recovery refused: the organization already has an OIDC provider.")
        row = session.get(SetupRecovery, 1)
        if row is None:
            row = SetupRecovery(
                id=1,
                organization_id=organization.id,
                code_hash=hash_recovery_code(code),
                expires_at=expires_at,
            )
            session.add(row)
        else:
            row.organization_id = organization.id
            row.code_hash = hash_recovery_code(code)
            row.expires_at = expires_at
            row.used_at = None

    url = f"{get_settings().app_public_url.rstrip('/')}/?setup_recovery={code}"
    sys.stdout.write(f"Recovery setup URL (expires {expires_at.isoformat()}):\n{url}\n")


if __name__ == "__main__":
    main()
