# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Administrator-managed OIDC configuration with write-only secret rotation."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from firewall_manager.application.authorization import AuthorizationService
from firewall_manager.application.errors import (
    InvalidInputError,
    ResourceOutOfScopeError,
    StaleWriteError,
)
from firewall_manager.application.ports import AuthorizationRepository, SecretStore
from firewall_manager.config import OidcProviderConfig
from firewall_manager.domain.models import Principal
from firewall_manager.persistence.models import AuditEvent, ExternalIdentity, OidcProvider, User


class OidcAdministrationService:
    def __init__(
        self, session: Session, authorization: AuthorizationRepository, secrets: SecretStore
    ) -> None:
        self._session, self._authorization, self._secrets = session, authorization, secrets

    def _admin(self, principal: Principal) -> None:
        if (
            not AuthorizationService(self._authorization)
            .authorize_administration(principal)
            .allowed
        ):
            raise ResourceOutOfScopeError

    def _audit(self, principal: Principal, action: str, row: OidcProvider) -> None:
        self._session.add(
            AuditEvent(
                organization_id=principal.organization_id,
                actor_user_id=principal.audit_user_id,
                action=action,
                resource_type="oidc_provider",
                resource_id=row.id,
                decision="ALLOW",
                reason_code="OIDC_ADMINISTRATION",
                interface="rest",
                details={"provider_id": row.provider_id, "provider_kind": row.kind},
            )
        )

    def list(self, principal: Principal) -> list[dict[str, object]]:
        self._admin(principal)
        return [
            self._safe(row)
            for row in self._session.scalars(
                select(OidcProvider)
                .where(OidcProvider.organization_id == principal.organization_id)
                .order_by(OidcProvider.display_name)
            )
        ]

    def list_identities(self, principal: Principal, user_id: UUID) -> list[ExternalIdentity]:
        self._admin(principal)
        if (
            self._session.scalar(
                select(User.id).where(
                    User.id == user_id, User.organization_id == principal.organization_id
                )
            )
            is None
        ):
            raise ResourceOutOfScopeError
        return list(
            self._session.scalars(
                select(ExternalIdentity)
                .where(
                    ExternalIdentity.user_id == user_id,
                    ExternalIdentity.organization_id == principal.organization_id,
                )
                .order_by(ExternalIdentity.created_at)
            )
        )

    def add_identity(
        self, principal: Principal, user_id: UUID, values: dict[str, object]
    ) -> ExternalIdentity:
        self._admin(principal)
        if (
            self._session.scalar(
                select(User.id).where(
                    User.id == user_id, User.organization_id == principal.organization_id
                )
            )
            is None
        ):
            raise ResourceOutOfScopeError
        issuer, subject = values["issuer"], values["subject"]
        if (
            self._session.scalar(
                select(ExternalIdentity.id).where(
                    ExternalIdentity.issuer == issuer, ExternalIdentity.subject == subject
                )
            )
            is not None
        ):
            raise InvalidInputError
        row = ExternalIdentity(
            organization_id=principal.organization_id,
            user_id=user_id,
            provider_id=str(values["provider_id"]),
            issuer=str(issuer),
            subject=str(subject),
            email_claim=values.get("email_claim"),
            display_name_claim=values.get("display_name_claim"),
        )
        self._session.add(row)
        self._session.flush()
        self._session.add(
            AuditEvent(
                organization_id=principal.organization_id,
                actor_user_id=principal.audit_user_id,
                action="external_identity_added",
                resource_type="external_identity",
                resource_id=row.id,
                decision="ALLOW",
                reason_code="OIDC_ADMINISTRATION",
                interface="rest",
                details={"provider_id": row.provider_id, "issuer": row.issuer},
            )
        )
        return row

    def remove_identity(self, principal: Principal, user_id: UUID, identity_id: UUID) -> None:
        self._admin(principal)
        row = self._session.scalar(
            select(ExternalIdentity).where(
                ExternalIdentity.id == identity_id,
                ExternalIdentity.user_id == user_id,
                ExternalIdentity.organization_id == principal.organization_id,
            )
        )
        if row is None:
            raise ResourceOutOfScopeError
        self._session.delete(row)
        self._session.add(
            AuditEvent(
                organization_id=principal.organization_id,
                actor_user_id=principal.audit_user_id,
                action="external_identity_removed",
                resource_type="external_identity",
                resource_id=identity_id,
                decision="ALLOW",
                reason_code="OIDC_ADMINISTRATION",
                interface="rest",
                details={"provider_id": row.provider_id, "issuer": row.issuer},
            )
        )

    def create(
        self, principal: Principal, values: dict[str, object], secret: str
    ) -> dict[str, object]:
        self._admin(principal)
        config = self._validate(values, secret)
        if self._session.scalar(
            select(OidcProvider).where(OidcProvider.provider_id == config["provider_id"])
        ):
            raise InvalidInputError
        secret_id = self._secrets.create(
            principal.organization_id, "oidc-client-secret", {"client_secret": secret}
        )
        row = OidcProvider(
            organization_id=principal.organization_id, secret_reference=secret_id, **config
        )
        self._session.add(row)
        self._session.flush()
        self._audit(principal, "oidc_provider_created", row)
        return self._safe(row)

    def rotate(
        self, principal: Principal, provider_id: UUID, expected_revision: int, secret: str
    ) -> dict[str, object]:
        self._admin(principal)
        row = self._row(principal, provider_id)
        if row.revision != expected_revision:
            raise StaleWriteError
        self._secrets.replace(
            principal.organization_id,
            row.secret_reference,
            "oidc-client-secret",
            {"client_secret": secret},
        )
        row.revision += 1
        self._audit(principal, "oidc_client_secret_rotated", row)
        return self._safe(row)

    def update(
        self, principal: Principal, provider_id: UUID, values: dict[str, object]
    ) -> dict[str, object]:
        self._admin(principal)
        row = self._row(principal, provider_id)
        if int(values.get("expected_revision", 0)) != row.revision:
            raise StaleWriteError
        allowed = {
            "display_name",
            "issuer_url",
            "client_id",
            "scopes",
            "enabled",
            "logout",
            "username_claim",
            "display_name_claim",
            "email_claim",
            "mapping_claim",
        }
        candidate = {
            "id": row.provider_id,
            "kind": row.kind,
            "display_name": values.get("display_name", row.display_name),
            "issuer_url": values.get("issuer_url", row.issuer_url),
            "client_id": values.get("client_id", row.client_id),
            "scopes": values.get("scopes", row.scopes),
            "username_claim": values.get("username_claim", row.username_claim),
            "display_name_claim": values.get("display_name_claim", row.display_name_claim),
            "email_claim": values.get("email_claim", row.email_claim),
            "mapping_claim": values.get("mapping_claim", row.mapping_claim),
            "enabled": values.get("enabled", row.enabled),
            "logout": values.get("logout", row.logout),
            "client_secret": "redacted-validation-placeholder",
        }
        try:
            OidcProviderConfig.model_validate(candidate)
        except ValueError as exc:
            raise InvalidInputError from exc
        for key in allowed:
            if key in values:
                setattr(row, key, values[key])
        row.revision += 1
        self._audit(principal, "oidc_provider_updated", row)
        return self._safe(row)

    def secret(self, principal: Principal, row: OidcProvider) -> dict[str, str]:
        return self._secrets.retrieve(
            principal.organization_id, row.secret_reference, "oidc-client-secret"
        )

    def _row(self, principal: Principal, provider_id: UUID) -> OidcProvider:
        row = self._session.scalar(
            select(OidcProvider).where(
                OidcProvider.id == provider_id,
                OidcProvider.organization_id == principal.organization_id,
            )
        )
        if row is None:
            raise ResourceOutOfScopeError
        return row

    @staticmethod
    def _validate(values: dict[str, object], secret: str) -> dict[str, object]:
        try:
            config = OidcProviderConfig.model_validate({**values, "client_secret": secret})
        except ValueError as exc:
            raise InvalidInputError from exc
        return {
            "provider_id": config.id,
            "kind": config.kind,
            "display_name": config.display_name,
            "issuer_url": str(config.issuer_url),
            "client_id": config.client_id,
            "scopes": config.scopes,
            "username_claim": config.username_claim,
            "display_name_claim": config.display_name_claim,
            "email_claim": config.email_claim,
            "mapping_claim": config.mapping_claim,
            "enabled": config.enabled,
            "logout": config.logout,
        }

    @staticmethod
    def _safe(row: OidcProvider) -> dict[str, object]:
        return {
            "id": row.id,
            "provider_id": row.provider_id,
            "kind": row.kind,
            "display_name": row.display_name,
            "issuer_url": row.issuer_url,
            "client_id": row.client_id,
            "scopes": row.scopes,
            "enabled": row.enabled,
            "logout": row.logout,
            "username_claim": row.username_claim,
            "display_name_claim": row.display_name_claim,
            "email_claim": row.email_claim,
            "mapping_claim": row.mapping_claim,
            "secret_configured": True,
            "revision": row.revision,
            "updated_at": row.updated_at,
        }
