"""One-time, deployment-controlled production administrator bootstrap."""

import sys
from typing import cast

from sqlalchemy import select

from firewall_manager.config import get_settings
from firewall_manager.persistence.database import new_session
from firewall_manager.persistence.models import ExternalIdentity, Organization, User


def main() -> None:
    settings = get_settings()
    required = (
        settings.bootstrap_organization_name,
        settings.bootstrap_admin_email,
        settings.bootstrap_admin_display_name,
        settings.bootstrap_admin_issuer,
        settings.bootstrap_admin_subject,
    )
    if any(value is None or not value.strip() for value in required):
        raise SystemExit(
            "Set BOOTSTRAP_ORGANIZATION_NAME, BOOTSTRAP_ADMIN_EMAIL, "
            "BOOTSTRAP_ADMIN_DISPLAY_NAME, BOOTSTRAP_ADMIN_ISSUER, and "
            "BOOTSTRAP_ADMIN_SUBJECT for one-time bootstrap."
        )
    organization_name = cast(str, settings.bootstrap_organization_name).strip()
    admin_email = cast(str, settings.bootstrap_admin_email).strip()
    admin_display_name = cast(str, settings.bootstrap_admin_display_name).strip()
    admin_issuer = cast(str, settings.bootstrap_admin_issuer).strip()
    admin_subject = cast(str, settings.bootstrap_admin_subject).strip()
    with new_session() as session, session.begin():
        if session.scalar(select(User.id)) is not None:
            raise SystemExit("Bootstrap refused: an application User already exists.")
        organization = Organization(name=organization_name)
        session.add(organization)
        session.flush()
        user = User(
            organization_id=organization.id,
            identity_issuer=admin_issuer,
            identity_subject=admin_subject,
            email=admin_email,
            display_name=admin_display_name,
            role="admin",
            is_active=True,
            revision=1,
        )
        session.add(user)
        session.flush()
        session.add(
            ExternalIdentity(
                organization_id=organization.id,
                user_id=user.id,
                provider_id="bootstrap",
                issuer=user.identity_issuer,
                subject=user.identity_subject,
                email_claim=user.email,
                display_name_claim=user.display_name,
            )
        )
    sys.stdout.write(
        "Bootstrap administrator created. Remove the bootstrap variables before starting the "
        "application.\n"
    )


if __name__ == "__main__":
    main()
