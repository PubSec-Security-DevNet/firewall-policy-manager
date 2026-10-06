"""Administrator-managed SMTP configuration and encrypted credential handling."""

import ssl

from sqlalchemy import select
from sqlalchemy.orm import Session

from firewall_manager.application.authorization import AuthorizationService
from firewall_manager.application.errors import (
    InvalidInputError,
    ResourceOutOfScopeError,
    StaleWriteError,
)
from firewall_manager.application.ports import AuthorizationRepository, SecretStore
from firewall_manager.domain.models import Principal
from firewall_manager.persistence.models import AuditEvent, SmtpSettings


class SmtpAdministrationService:
    """Manage one organization SMTP profile without returning its password."""

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

    def get(self, principal: Principal, fallback: dict[str, object]) -> dict[str, object]:
        self._admin(principal)
        row = self._session.scalar(
            select(SmtpSettings).where(SmtpSettings.organization_id == principal.organization_id)
        )
        return (
            self._safe(row)
            if row
            else {**fallback, "configured": bool(fallback.get("host")), "revision": 0}
        )

    def upsert(  # noqa: PLR0912 -- explicit validation for independent SMTP settings
        self, principal: Principal, values: dict[str, object]
    ) -> dict[str, object]:
        self._admin(principal)
        row = self._session.scalar(
            select(SmtpSettings).where(SmtpSettings.organization_id == principal.organization_id)
        )
        try:
            host = str(values["host"]).strip()
            from_address = str(values["from_address"]).strip()
            port = int(values["port"])
            encryption = str(values["encryption"])
            auth_required = bool(values["authentication_required"])
            username = str(values.get("username") or "").strip() or None
            password = values.get("password")
            custom_ca = values.get("custom_ca_certificate")
            if custom_ca is not None:
                custom_ca = str(custom_ca).strip() or None
                if custom_ca:
                    ssl.create_default_context(cadata=custom_ca)
            expected_revision = int(values.get("expected_revision", 0))
            if (
                not host
                or not from_address
                or not 1 <= port <= 65535
                or encryption not in {"NONE", "STARTTLS", "SSL_TLS"}
            ):
                raise ValueError
            if auth_required and (
                not username
                or (
                    not isinstance(password, str)
                    and (row is None or row.password_reference is None)
                )
                or (
                    isinstance(password, str)
                    and not password
                    and (row is None or row.password_reference is None)
                )
            ):
                raise ValueError
            if not auth_required:
                username, password = None, None
        except (KeyError, TypeError, ValueError, ssl.SSLError) as exc:
            raise InvalidInputError from exc
        if row and expected_revision != row.revision:
            raise StaleWriteError
        if row is None:
            row = SmtpSettings(
                organization_id=principal.organization_id,
                host=host,
                port=port,
                from_address=from_address,
                encryption=encryption,
                authentication_required=auth_required,
                username=username,
                custom_ca_certificate=custom_ca,
            )
            self._session.add(row)
            self._session.flush()
        else:
            row.host, row.port, row.from_address = host, port, from_address
            row.encryption, row.authentication_required, row.username = (
                encryption,
                auth_required,
                username,
            )
            if "custom_ca_certificate" in values:
                row.custom_ca_certificate = custom_ca
            row.revision += 1
        if isinstance(password, str):
            if row.password_reference:
                self._secrets.replace(
                    principal.organization_id,
                    row.password_reference,
                    "smtp-password",
                    {"password": password},
                )
            else:
                row.password_reference = self._secrets.create(
                    principal.organization_id, "smtp-password", {"password": password}
                )
        elif not auth_required:
            row.password_reference = None
        self._session.add(
            AuditEvent(
                organization_id=principal.organization_id,
                actor_user_id=principal.audit_user_id,
                action="smtp_settings_updated",
                resource_type="smtp_settings",
                resource_id=row.id,
                decision="CHANGE",
                reason_code="SMTP_ADMINISTRATION",
                interface="rest",
                details={"encryption": encryption, "authentication_required": auth_required},
            )
        )
        return self._safe(row)

    @staticmethod
    def _safe(row: SmtpSettings) -> dict[str, object]:
        return {
            "id": row.id,
            "host": row.host,
            "port": row.port,
            "from_address": row.from_address,
            "encryption": row.encryption,
            "authentication_required": row.authentication_required,
            "username": row.username,
            "custom_ca_configured": row.custom_ca_certificate is not None,
            "password_configured": row.password_reference is not None,
            "configured": True,
            "revision": row.revision,
            "updated_at": row.updated_at,
        }
