"""One-time first-run and operator-authorized OIDC setup."""

import hashlib
import secrets
from datetime import UTC, datetime
from uuid import uuid4

from pydantic import ValidationError
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from firewall_manager.application.errors import InvalidInputError, ResourceOutOfScopeError
from firewall_manager.application.ports import SecretStore
from firewall_manager.config import OidcProviderConfig
from firewall_manager.persistence.models import (
    ExternalIdentity,
    OidcProvider,
    Organization,
    SetupRecovery,
    User,
)


class InitialSetupService:
    """Create the first application identity only in a genuinely empty database."""

    def __init__(self, session: Session, secrets: SecretStore) -> None:
        self._session, self._secrets = session, secrets

    def available(self) -> bool:
        return not any(
            self._session.scalar(select(model.id).limit(1))
            for model in (Organization, User, OidcProvider)
        )

    def recovery_available(self, code: str | None) -> bool:
        row = self._recovery(code)
        return row is not None and row.expires_at > datetime.now(UTC)

    def create(self, values: dict[str, object]) -> dict[str, str]:  # noqa: PLR0912, PLR0915
        self._session.execute(text("SELECT pg_advisory_xact_lock(:lock_key)"), {"lock_key": 914273})
        recovery_code = values.pop("recovery_code", None)
        recovery = None
        if not self.available():
            recovery = self._recovery(recovery_code)
            if recovery is None or recovery.expires_at <= datetime.now(UTC):
                raise ResourceOutOfScopeError
        try:
            organization_name = _required(values, "organization_name") if recovery is None else ""
            admin_email = _required(values, "admin_email")
            admin_display_name = _required(values, "admin_display_name")
            admin_issuer = _required(values, "admin_issuer")
            provider_values = {
                "id": _required(values, "provider_id"),
                "kind": _required(values, "provider_kind"),
                "display_name": _required(values, "provider_display_name"),
                "issuer_url": _required(values, "provider_issuer_url"),
                "client_id": _required(values, "provider_client_id"),
                "client_secret": _required(values, "provider_client_secret"),
            }
            config = OidcProviderConfig.model_validate(provider_values)
            if admin_issuer != str(config.issuer_url):
                raise ValueError("administrator issuer must match the OIDC provider issuer")
        except ValidationError as exc:
            fields = sorted({str(item["loc"][0]) for item in exc.errors() if item["loc"]})
            raise InvalidInputError(details={"fields": fields}) from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise InvalidInputError(details={"reason": str(exc)}) from exc

        if recovery is None:
            organization = Organization(name=organization_name)
            self._session.add(organization)
            self._session.flush()
        else:
            organization = self._session.get(Organization, recovery.organization_id)
            if organization is None:
                raise ResourceOutOfScopeError
            if (
                self._session.scalar(
                    select(OidcProvider.id)
                    .where(OidcProvider.organization_id == organization.id)
                    .limit(1)
                )
                is not None
            ):
                raise ResourceOutOfScopeError
        identity_subject = str(values.get("admin_subject") or f"pending:{uuid4()}")
        user = self._session.scalar(
            select(User).where(
                User.organization_id == organization.id,
                func.lower(User.email) == admin_email.casefold(),
            )
        )
        if user is None:
            user = User(
                organization_id=organization.id,
                identity_issuer=admin_issuer,
                identity_subject=identity_subject,
                email=admin_email,
                display_name=admin_display_name,
                role="admin",
                is_active=True,
                revision=1,
            )
            self._session.add(user)
        else:
            user.identity_issuer = admin_issuer
            user.identity_subject = identity_subject
            user.display_name = admin_display_name
            user.role = "admin"
            user.is_active = True
            user.revision += 1
        self._session.flush()
        if not identity_subject.startswith("pending:"):
            identity = self._session.scalar(
                select(ExternalIdentity).where(
                    ExternalIdentity.issuer == admin_issuer,
                    ExternalIdentity.subject == identity_subject,
                )
            )
            if identity is None:
                self._session.add(
                    ExternalIdentity(
                        organization_id=organization.id,
                        user_id=user.id,
                        provider_id=config.id,
                        issuer=admin_issuer,
                        subject=identity_subject,
                        email_claim=admin_email,
                        display_name_claim=admin_display_name,
                    )
                )
            elif identity.user_id != user.id:
                raise InvalidInputError(
                    details={"reason": "the tested OIDC identity belongs to another user"}
                )
        secret_id = self._secrets.create(
            organization.id,
            "oidc-client-secret",
            {"client_secret": config.client_secret.get_secret_value()},
        )
        self._session.add(
            OidcProvider(
                organization_id=organization.id,
                provider_id=config.id,
                kind=config.kind,
                display_name=config.display_name,
                issuer_url=str(config.issuer_url),
                client_id=config.client_id,
                scopes=config.scopes,
                username_claim=config.username_claim,
                display_name_claim=config.display_name_claim,
                email_claim=config.email_claim,
                mapping_claim=config.mapping_claim,
                enabled=True,
                logout=True,
                secret_reference=secret_id,
                revision=1,
            )
        )
        if recovery is not None:
            recovery.used_at = datetime.now(UTC)
        return {"organization_name": organization.name, "provider_id": config.id}

    def _recovery(self, code: str | None) -> SetupRecovery | None:
        if not code:
            return None
        row = self._session.get(SetupRecovery, 1)
        if row is None or row.used_at is not None:
            return None
        if secrets.compare_digest(row.code_hash, hash_recovery_code(code)):
            return row
        return None


def hash_recovery_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def create_recovery_code() -> str:
    return secrets.token_urlsafe(32)


def _required(values: dict[str, object], key: str) -> str:
    value = values[key]
    if not isinstance(value, str) or not value.strip():
        raise ValueError(key)
    return value.strip()
