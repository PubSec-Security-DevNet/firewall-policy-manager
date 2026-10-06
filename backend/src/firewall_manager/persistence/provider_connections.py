"""SQL persistence for isolated, unlimited provider connections."""

import re
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from firewall_manager.application.errors import (
    InvalidChangeSetStateError,
    InvalidInputError,
    ResourceOutOfScopeError,
    StaleWriteError,
)
from firewall_manager.persistence.models import (
    AuditEvent,
    FirewallManager,
    ProviderCapabilityEvidence,
    ProviderConnection,
    ProviderConnectionScope,
)
from firewall_manager.providers.capabilities import (
    VALIDATION_REQUIRED_CAPABILITIES,
    VALIDATION_WRITE_CAPABILITIES,
)


def _provider_api_family(version: str | None) -> str | None:
    """Return the stable major.minor API family from a provider build string."""
    if not version:
        return None
    components = re.findall(r"\d+", version)
    return ".".join(components[:2]) if len(components) >= 2 else None


class SqlProviderConnectionRepository:
    """Organization-scoped connection state with revision and append-oriented audit."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def list_connections(
        self, organization_id: UUID, offset: int, limit: int
    ) -> tuple[list[dict[str, object]], int]:
        total = int(
            self._session.scalar(
                select(func.count())
                .select_from(ProviderConnection)
                .where(ProviderConnection.organization_id == organization_id)
            )
            or 0
        )
        rows = list(
            self._session.scalars(
                select(ProviderConnection)
                .where(ProviderConnection.organization_id == organization_id)
                .order_by(ProviderConnection.display_name, ProviderConnection.id)
                .offset(offset)
                .limit(limit)
            )
        )
        return [self._safe_dict(row) for row in rows], total

    def connection_context(
        self, organization_id: UUID, connection_id: UUID
    ) -> dict[str, object] | None:
        row = self._row(organization_id, connection_id)
        if row is None:
            return None
        manager = self._session.scalar(
            select(FirewallManager).where(
                FirewallManager.organization_id == organization_id,
                FirewallManager.provider_connection_id == connection_id,
            )
        )
        return {
            **self._safe_dict(row),
            "credential_reference": row.credential_reference,
            "manager_id": manager.id if manager else None,
            "capabilities": dict(manager.capabilities) if manager else {},
        }

    def create_connection(  # noqa: PLR0913, PLR0917 -- complete actor and secret context
        self,
        organization_id: UUID,
        actor_user_id: UUID,
        connection_id: UUID,
        credential_reference: UUID,
        values: dict[str, object],
        capabilities: dict[str, str],
    ) -> dict[str, object]:
        now = datetime.now(UTC)
        row = ProviderConnection(
            id=connection_id,
            organization_id=organization_id,
            provider_type=str(values["provider_type"]),
            display_name=str(values["display_name"]),
            lifecycle="DISABLED",
            connection_mode=str(values["connection_mode"]),
            evidence_profile="real",
            base_endpoint=str(values["base_endpoint"])
            if values.get("base_endpoint") is not None
            else None,
            region=str(values["region"]) if values.get("region") is not None else None,
            tls_mode=str(values.get("tls_mode", "SYSTEM")),
            credential_reference=credential_reference,
            credential_type=str(values["credential_type"]),
            credential_username=str(values["credential_username"])
            if values.get("credential_username") is not None
            else None,
            credential_updated_at=now,
            connection_status="NEVER_TESTED",
            sync_interval_minutes=int(str(values.get("sync_interval_minutes", 60))),
            applications_sync_interval_minutes=int(
                str(values.get("applications_sync_interval_minutes", 1440))
            ),
            deployment_interval_minutes=int(str(values.get("deployment_interval_minutes", 15))),
            revision=1,
        )
        manager = FirewallManager(
            organization_id=organization_id,
            provider_connection_id=connection_id,
            provider=row.provider_type,
            native_id=f"connection:{connection_id}",
            display_name=row.display_name,
            base_url=row.base_endpoint or "",
            read_only=True,
            is_mock=False,
            capabilities=capabilities,
            revision=1,
        )
        # These mappers intentionally have no ORM relationship: application services resolve the
        # connection/manager boundary explicitly. Flush the FK parent first because SQLAlchemy
        # cannot infer mapper insertion order from a relationship in this model. PostgreSQL would
        # otherwise be allowed to insert the manager before its provider connection.
        self._session.add(row)
        self._flush()
        self._session.add(manager)
        self._flush()
        self._audit(organization_id, actor_user_id, connection_id, "connection_created", "SUCCESS")
        return self._safe_dict(row)

    def update_connection(
        self,
        organization_id: UUID,
        actor_user_id: UUID,
        connection_id: UUID,
        expected_revision: int,
        values: dict[str, object],
    ) -> dict[str, object]:
        row = self._require_row(organization_id, connection_id)
        self._require_not_retired(row)
        self._require_revision(row, expected_revision)
        routing_changed = any(
            key in values and getattr(row, key) != values[key]
            for key in ("base_endpoint", "region", "tls_mode")
        )
        for key in (
            "display_name",
            "base_endpoint",
            "region",
            "tls_mode",
            "sync_interval_minutes",
            "applications_sync_interval_minutes",
            "deployment_schedule_enabled",
            "deployment_interval_minutes",
        ):
            if key in values:
                setattr(row, key, values[key])
        if routing_changed:
            row.lifecycle = "DISABLED"
            self._disable_writes(row)
            row.connection_status = "NEVER_TESTED"
            row.provider_version = None
            row.last_error_code = None
            row.last_error_message = None
            row.next_sync_at = None
        if "deployment_interval_minutes" in values:
            row.deployment_next_at = None
        row.revision += 1
        manager = self._manager(organization_id, connection_id)
        manager.display_name = row.display_name
        manager.base_url = row.base_endpoint or ""
        if routing_changed:
            self._reset_manager_validation(manager)
        manager.revision += 1
        self._flush()
        self._audit(
            organization_id,
            actor_user_id,
            connection_id,
            "connection_configuration_changed",
            "SUCCESS",
        )
        return self._safe_dict(row)

    def record_credential_rotation(
        self,
        organization_id: UUID,
        actor_user_id: UUID,
        connection_id: UUID,
        expected_revision: int,
        username: str | None,
    ) -> dict[str, object]:
        row = self._require_row(organization_id, connection_id)
        self._require_not_retired(row)
        self._require_revision(row, expected_revision)
        row.credential_username = username
        row.credential_updated_at = datetime.now(UTC)
        row.connection_status = "NEVER_TESTED"
        row.lifecycle = "DISABLED"
        self._disable_writes(row)
        row.next_sync_at = None
        row.provider_version = None
        row.certificate_info = {}
        row.revision += 1
        manager = self._manager(organization_id, connection_id)
        self._reset_manager_validation(manager)
        manager.revision += 1
        self._flush()
        self._audit(organization_id, actor_user_id, connection_id, "credential_replaced", "SUCCESS")
        return self._safe_dict(row)

    def record_connection_test(  # noqa: PLR0913, PLR0917 -- complete evidence context
        self,
        organization_id: UUID,
        actor_user_id: UUID,
        connection_id: UUID,
        result: dict[str, object],
        capabilities: dict[str, str],
        scopes: list[dict[str, str]],
    ) -> dict[str, object]:
        row = self._require_row(organization_id, connection_id)
        self._require_not_retired(row)
        writes_were_enabled = row.write_enabled
        previous_version = row.provider_version
        previous_write_enabled_at = row.write_enabled_at
        previous_write_enabled_by_user_id = row.write_enabled_by_user_id
        self._disable_writes(row)
        now = datetime.now(UTC)
        status = str(result["status"])
        row.connection_status = status
        row.last_connection_test = now
        row.last_error_code = str(result["error_code"]) if result.get("error_code") else None
        row.last_error_message = str(result["safe_message"]) if result.get("safe_message") else None
        row.last_error_correlation_id = (
            str(result["correlation_id"]) if result.get("correlation_id") else None
        )
        if status == "CONNECTED":
            row.last_successful_connection = now
            row.provider_version = str(result["provider_version"])
            certificate_info = result.get("certificate_info", {})
            if not isinstance(certificate_info, dict):
                raise InvalidInputError
            row.certificate_info = {
                str(key): str(value)
                for key, value in cast("dict[object, object]", certificate_info).items()
            }
            row.last_error_code = None
            row.last_error_message = None
            row.last_error_correlation_id = None
            self._replace_scopes(row, scopes, now)
            tested_capabilities = self._replace_evidence(
                row, capabilities, now, previous_version=previous_version
            )
            manager = self._manager(organization_id, connection_id)
            manager.provider_version = row.provider_version
            manager.capabilities = {
                **capabilities,
                **dict.fromkeys(tested_capabilities, "SUPPORTED"),
            }
            restore_writes = writes_were_enabled and row.lifecycle == "ACTIVE"
            if restore_writes:
                row.write_enabled = True
                row.write_enabled_at = previous_write_enabled_at
                row.write_enabled_by_user_id = previous_write_enabled_by_user_id
            manager.read_only = not restore_writes
            manager.revision += 1
        else:
            row.lifecycle = "DISABLED"
            self._disable_writes(row)
            row.next_sync_at = None
            row.provider_version = None
            row.certificate_info = {}
            manager = self._manager(organization_id, connection_id)
            self._reset_manager_validation(manager)
            manager.revision += 1
        row.revision += 1
        self._flush()
        self._audit(
            organization_id,
            actor_user_id,
            connection_id,
            "connection_tested",
            "SUCCESS" if status == "CONNECTED" else "FAILED",
            {
                "connection_status": status,
                **({"error_code": row.last_error_code} if row.last_error_code else {}),
            },
        )
        if writes_were_enabled and not row.write_enabled:
            self._audit(
                organization_id,
                actor_user_id,
                connection_id,
                "provider_writes_disabled_for_revalidation",
                "SUCCESS",
            )
        return self._safe_dict(row)

    def set_lifecycle(
        self,
        organization_id: UUID,
        actor_user_id: UUID,
        connection_id: UUID,
        expected_revision: int,
        lifecycle: str,
    ) -> dict[str, object]:
        row = self._require_row(organization_id, connection_id)
        writes_were_enabled = row.write_enabled
        self._require_revision(row, expected_revision)
        if lifecycle == "ACTIVE" and row.connection_status != "CONNECTED":
            raise InvalidChangeSetStateError
        if row.lifecycle == "RETIRED" and lifecycle != "RETIRED":
            raise InvalidChangeSetStateError
        row.lifecycle = lifecycle
        now = datetime.now(UTC)
        if lifecycle == "ACTIVE":
            row.next_sync_at = now
            row.applications_next_sync_at = now
            action = "connection_enabled"
        elif lifecycle == "RETIRED":
            row.retired_at = now
            row.next_sync_at = None
            row.applications_next_sync_at = None
            self._disable_writes(row)
            action = "connection_retired"
        else:
            row.next_sync_at = None
            row.applications_next_sync_at = None
            self._disable_writes(row)
            action = "connection_disabled"
        if lifecycle != "ACTIVE":
            manager = self._manager(organization_id, connection_id)
            manager.read_only = True
            manager.revision += 1
        row.revision += 1
        self._flush()
        self._audit(organization_id, actor_user_id, connection_id, action, "SUCCESS")
        if writes_were_enabled and not row.write_enabled:
            self._audit(
                organization_id,
                actor_user_id,
                connection_id,
                "provider_writes_disabled",
                "SUCCESS",
                {"reason": "connection_lifecycle_changed"},
            )
        return self._safe_dict(row)

    def set_write_enabled(  # noqa: PLR0913, PLR0917 -- explicit actor and gate context
        self,
        organization_id: UUID,
        actor_user_id: UUID,
        connection_id: UUID,
        expected_revision: int,
        enabled: bool,
        allow_unvalidated_non_production: bool,
    ) -> dict[str, object]:
        """Set the independent production write gate; compatibility evidence is advisory."""
        del allow_unvalidated_non_production  # Retained for backward-compatible API clients.
        row = self._require_row(organization_id, connection_id)
        self._require_not_retired(row)
        self._require_revision(row, expected_revision)
        manager = self._manager(organization_id, connection_id)
        if enabled:
            if (
                row.lifecycle != "ACTIVE"
                or row.connection_status != "CONNECTED"
                or not row.provider_version
            ):
                raise InvalidChangeSetStateError(
                    details={"code": "PROVIDER_CONNECTION_NOT_VALIDATED"}
                )
            row.write_enabled = True
            row.write_enabled_at = datetime.now(UTC)
            row.write_enabled_by_user_id = actor_user_id
            manager.read_only = False
            action = "provider_writes_enabled"
        else:
            self._disable_writes(row)
            manager.read_only = True
            action = "provider_writes_disabled"
        row.revision += 1
        manager.revision += 1
        self._flush()
        self._audit(
            organization_id,
            actor_user_id,
            connection_id,
            action,
            "SUCCESS",
            {
                "write_enabled": enabled,
                "compatibility_evidence_is_advisory": True,
            },
        )
        return self._safe_dict(row)

    def request_sync(
        self, organization_id: UUID, actor_user_id: UUID, connection_id: UUID, mode: str = "FULL"
    ) -> None:
        row = self._require_row(organization_id, connection_id)
        if row.lifecycle != "ACTIVE":
            raise InvalidChangeSetStateError
        now = datetime.now(UTC)
        if mode == "APPLICATIONS":
            row.applications_sync_status = "QUEUED"
            row.applications_last_sync = now
        else:
            row.sync_status = "QUEUED"
            row.last_sync = now
        row.last_error_code = None
        row.last_error_message = None
        row.last_error_correlation_id = None
        self._flush()
        self._audit(
            organization_id, actor_user_id, connection_id, "manual_sync_requested", "QUEUED"
        )
        # Publish happens after this method returns. Commit the queue claim and its audit first so
        # a fast worker can never observe pre-request state.
        self._session.commit()

    def due_connection_jobs(self, now: datetime, limit: int = 100) -> list[tuple[UUID, str]]:
        full = list(
            self._session.scalars(
                select(ProviderConnection.id)
                .where(
                    ProviderConnection.lifecycle == "ACTIVE",
                    ProviderConnection.next_sync_at.is_not(None),
                    ProviderConnection.next_sync_at <= now,
                    or_(
                        ProviderConnection.sync_status.is_(None),
                        ProviderConnection.sync_status.notin_(("QUEUED", "RUNNING")),
                    ),
                )
                .order_by(ProviderConnection.next_sync_at, ProviderConnection.id)
                .limit(limit)
            )
        )
        apps = list(
            self._session.scalars(
                select(ProviderConnection.id)
                .where(
                    ProviderConnection.lifecycle == "ACTIVE",
                    ProviderConnection.applications_next_sync_at.is_not(None),
                    ProviderConnection.applications_next_sync_at <= now,
                    or_(
                        ProviderConnection.applications_sync_status.is_(None),
                        ProviderConnection.applications_sync_status.notin_(("QUEUED", "RUNNING")),
                    ),
                )
                .order_by(ProviderConnection.applications_next_sync_at, ProviderConnection.id)
                .limit(limit)
            )
        )
        return [(connection_id, "NON_APPLICATIONS") for connection_id in full] + [
            (connection_id, "APPLICATIONS") for connection_id in apps
        ]

    def due_connection_ids(self, now: datetime, limit: int = 100) -> list[UUID]:
        return list(
            self._session.scalars(
                select(ProviderConnection.id)
                .where(
                    ProviderConnection.lifecycle == "ACTIVE",
                    ProviderConnection.next_sync_at.is_not(None),
                    ProviderConnection.next_sync_at <= now,
                    or_(
                        ProviderConnection.sync_status.is_(None),
                        ProviderConnection.sync_status.notin_(("QUEUED", "RUNNING")),
                    ),
                )
                .order_by(ProviderConnection.next_sync_at, ProviderConnection.id)
                .limit(limit)
            )
        )

    def queue_due_connections(self, now: datetime, limit: int = 100) -> list[UUID]:
        """Claim a bounded due batch for the single scheduler/worker queue architecture."""
        ids = self.due_connection_ids(now, limit)
        if ids:
            rows = list(
                self._session.scalars(
                    select(ProviderConnection).where(ProviderConnection.id.in_(ids))
                )
            )
            for row in rows:
                row.sync_status = "QUEUED"
                row.last_sync = now
            self._session.commit()
        return ids

    def queue_due_sync_jobs(self, now: datetime, limit: int = 100) -> list[tuple[UUID, str]]:
        jobs = self.due_connection_jobs(now, limit)
        for connection_id, mode in jobs:
            row = self._session.get(ProviderConnection, connection_id)
            if row is None:
                continue
            if mode == "APPLICATIONS":
                row.applications_sync_status = "QUEUED"
                row.applications_last_sync = now
            else:
                row.sync_status = "QUEUED"
                row.last_sync = now
        if jobs:
            self._session.commit()
        return jobs

    def mark_sync_running(self, connection_id: UUID, mode: str = "FULL") -> tuple[UUID, UUID]:
        row = self._session.get(ProviderConnection, connection_id)
        if row is None or row.lifecycle != "ACTIVE":
            raise InvalidChangeSetStateError
        now = datetime.now(UTC)
        if mode == "APPLICATIONS":
            row.applications_sync_status = "RUNNING"
            row.applications_last_sync = now
        else:
            row.sync_status = "RUNNING"
            row.last_sync = now
            row.last_error_code = None
            row.last_error_message = None
            row.last_error_correlation_id = None
        manager = self._manager(row.organization_id, connection_id)
        self._session.commit()
        return row.organization_id, manager.id

    def mark_sync_finished(
        self, connection_id: UUID, status: str, error_code: str | None, mode: str = "FULL"
    ) -> None:
        row = self._session.get(ProviderConnection, connection_id)
        if row is None:
            raise ResourceOutOfScopeError
        now = datetime.now(UTC)
        if mode == "APPLICATIONS":
            row.applications_sync_status = status
            if status == "COMPLETED":
                row.applications_last_successful_sync = now
            row.applications_next_sync_at = (
                now + timedelta(minutes=row.applications_sync_interval_minutes)
                if row.lifecycle == "ACTIVE"
                else None
            )
        else:
            row.sync_status = status
            row.last_sync = now
            row.last_error_code = error_code
            if status == "COMPLETED":
                row.last_successful_sync = now
                row.last_error_code = None
            row.next_sync_at = (
                now + timedelta(minutes=row.sync_interval_minutes)
                if row.lifecycle == "ACTIVE"
                else None
            )
        self._session.commit()

    def _safe_dict(self, row: ProviderConnection) -> dict[str, object]:
        scopes = list(
            self._session.scalars(
                select(ProviderConnectionScope)
                .where(ProviderConnectionScope.connection_id == row.id)
                .order_by(ProviderConnectionScope.scope_type, ProviderConnectionScope.name)
            )
        )
        evidence = list(
            self._session.scalars(
                select(ProviderCapabilityEvidence)
                .where(ProviderCapabilityEvidence.connection_id == row.id)
                .order_by(ProviderCapabilityEvidence.capability)
            )
        )
        provider_evidence = list(
            self._session.scalars(
                select(ProviderCapabilityEvidence)
                .join(
                    ProviderConnection,
                    ProviderConnection.id == ProviderCapabilityEvidence.connection_id,
                )
                .where(ProviderConnection.provider_type == row.provider_type)
            )
        )
        current_api_family = _provider_api_family(row.provider_version)
        tested_by_family: dict[str, set[str]] = {}
        for item in provider_evidence:
            family = _provider_api_family(item.provider_version)
            if (
                family is not None
                and item.status == "SUPPORTED"
                and item.evidence_level == "TESTED"
            ):
                tested_by_family.setdefault(family, set()).add(item.capability)
        current_family_capabilities = tested_by_family.get(current_api_family or "", set())
        version_family_tested = bool(
            current_api_family
            and current_family_capabilities.intersection(VALIDATION_WRITE_CAPABILITIES)
            and "pending_change_inspection" in current_family_capabilities
        )
        compatibility_warning = (
            None
            if version_family_tested or current_api_family is None
            else (
                f"{row.provider_type.upper()} {current_api_family}.x has not been write-tested "
                "with this application version. Production writes are allowed, but provider "
                "behavior should be monitored closely."
            )
        )
        return {
            "id": row.id,
            "provider_type": row.provider_type,
            "display_name": row.display_name,
            "lifecycle": row.lifecycle,
            "enabled": row.lifecycle == "ACTIVE",
            "connection_mode": row.connection_mode,
            "evidence_profile": row.evidence_profile,
            "base_endpoint": row.base_endpoint,
            "region": row.region,
            "tls_mode": row.tls_mode,
            "credential_present": True,
            "credential_type": row.credential_type,
            "credential_username": row.credential_username,
            "credential_updated_at": row.credential_updated_at,
            "provider_version": row.provider_version,
            "connection_status": row.connection_status,
            "sync_status": row.sync_status,
            "last_connection_test": row.last_connection_test,
            "last_successful_connection": row.last_successful_connection,
            "last_sync": row.last_sync,
            "last_successful_sync": row.last_successful_sync,
            "last_error_code": row.last_error_code,
            "last_error_message": row.last_error_message,
            "last_error_correlation_id": row.last_error_correlation_id,
            "certificate_info": dict(row.certificate_info),
            "sync_interval_minutes": row.sync_interval_minutes,
            "applications_sync_interval_minutes": row.applications_sync_interval_minutes,
            "deployment_interval_minutes": row.deployment_interval_minutes,
            "applications_sync_status": row.applications_sync_status,
            "applications_last_sync": row.applications_last_sync,
            "applications_last_successful_sync": row.applications_last_successful_sync,
            "applications_next_sync_at": row.applications_next_sync_at,
            "deployment_schedule_enabled": row.deployment_schedule_enabled,
            "deployment_paused": row.deployment_paused,
            "deployment_pause_reason": row.deployment_pause_reason,
            "deployment_paused_at": row.deployment_paused_at,
            "deployment_pause_until": row.deployment_pause_until,
            "deployment_paused_by_user_id": row.deployment_paused_by_user_id,
            "deployment_status": row.deployment_status,
            "deployment_next_at": row.deployment_next_at,
            "deployment_last_started_at": row.deployment_last_started_at,
            "deployment_last_completed_at": row.deployment_last_completed_at,
            "write_enabled": row.write_enabled,
            "write_validation_mode": False,
            "version_family_tested": version_family_tested,
            "compatibility_warning": compatibility_warning,
            "write_enabled_at": row.write_enabled_at,
            "write_enabled_by_user_id": row.write_enabled_by_user_id,
            "scopes": [
                {
                    "id": scope.id,
                    "native_id": scope.native_id,
                    "name": scope.name,
                    "scope_type": scope.scope_type,
                    "last_seen_at": scope.last_seen_at,
                }
                for scope in scopes
            ],
            "capability_evidence": [
                {
                    "capability": item.capability,
                    "status": item.status,
                    "evidence_level": item.evidence_level,
                    "provider_version": item.provider_version,
                    "tested_at": item.tested_at,
                }
                for item in evidence
            ],
            "created_at": row.created_at,
            "updated_at": row.updated_at,
            "revision": row.revision,
        }

    def _replace_scopes(
        self, row: ProviderConnection, scopes: list[dict[str, str]], now: datetime
    ) -> None:
        existing = {
            item.native_id: item
            for item in self._session.scalars(
                select(ProviderConnectionScope).where(
                    ProviderConnectionScope.connection_id == row.id
                )
            )
        }
        for value in scopes:
            native_id = value["native_id"]
            scope = existing.get(native_id)
            if scope is None:
                scope = ProviderConnectionScope(
                    organization_id=row.organization_id,
                    connection_id=row.id,
                    native_id=native_id,
                )
                self._session.add(scope)
            scope.name = value["name"]
            scope.scope_type = value["scope_type"]
            scope.last_seen_at = now
        current_native_ids = {value["native_id"] for value in scopes}
        for native_id, scope in existing.items():
            if native_id not in current_native_ids:
                self._session.delete(scope)

    def _replace_evidence(
        self,
        row: ProviderConnection,
        capabilities: dict[str, str],
        now: datetime,
        *,
        previous_version: str | None,
    ) -> set[str]:
        if row.provider_version is None:
            return set()
        compatible_previous: dict[str, ProviderCapabilityEvidence] = {}
        previous_api_family = _provider_api_family(previous_version)
        if (
            previous_version
            and previous_version != row.provider_version
            and previous_api_family is not None
            and previous_api_family == _provider_api_family(row.provider_version)
        ):
            compatible_previous = {
                item.capability: item
                for item in self._session.scalars(
                    select(ProviderCapabilityEvidence).where(
                        ProviderCapabilityEvidence.connection_id == row.id,
                        ProviderCapabilityEvidence.provider_version == previous_version,
                        ProviderCapabilityEvidence.status == "SUPPORTED",
                        ProviderCapabilityEvidence.evidence_level == "TESTED",
                    )
                )
            }
        tested: set[str] = set()
        for capability, status in capabilities.items():
            evidence = self._session.scalar(
                select(ProviderCapabilityEvidence).where(
                    ProviderCapabilityEvidence.connection_id == row.id,
                    ProviderCapabilityEvidence.provider_version == row.provider_version,
                    ProviderCapabilityEvidence.capability == capability,
                )
            )
            if evidence is None:
                evidence = ProviderCapabilityEvidence(
                    organization_id=row.organization_id,
                    connection_id=row.id,
                    provider_version=row.provider_version,
                    capability=capability,
                )
                self._session.add(evidence)
            elif evidence.status == "SUPPORTED" and evidence.evidence_level == "TESTED":
                # A read-only connection probe must not erase live write evidence
                # already proven against this exact provider version.
                tested.add(capability)
                continue
            previous = compatible_previous.get(capability)
            if (
                previous is not None
                and capability in VALIDATION_REQUIRED_CAPABILITIES
                and status in {"PARTIAL", "SUPPORTED"}
            ):
                evidence.status = "SUPPORTED"
                evidence.evidence_level = "TESTED"
                evidence.evidence_summary = (
                    f"Carried forward from compatible API family version {previous_version}."
                )
                evidence.tested_at = now
                tested.add(capability)
                continue
            evidence.status = status
            evidence.evidence_level = "TESTED" if status == "READ_ONLY" else "NOT_STARTED"
            evidence.evidence_summary = (
                "Read-only connection validation succeeded through the normalized provider path."
                if status == "READ_ONLY"
                else "No live compatibility evidence has been recorded."
            )
            evidence.tested_at = now if status == "READ_ONLY" else None
            if evidence.status == "SUPPORTED" and evidence.evidence_level == "TESTED":
                tested.add(capability)
        return tested

    def _audit(  # noqa: PLR0913, PLR0917 -- complete append-only evidence context
        self,
        organization_id: UUID,
        actor_user_id: UUID,
        connection_id: UUID,
        action: str,
        outcome: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        connection = self._session.get(ProviderConnection, connection_id)
        details = {
            "provider": connection.provider_type if connection is not None else "unknown",
            **(metadata or {}),
        }
        self._session.add(
            AuditEvent(
                organization_id=organization_id,
                actor_user_id=actor_user_id,
                action="manage_providers",
                resource_type="provider_connection",
                resource_id=connection_id,
                decision=outcome,
                reason_code=action,
                interface="rest",
                details=details,
            )
        )

    def _row(self, organization_id: UUID, connection_id: UUID) -> ProviderConnection | None:
        return self._session.scalar(
            select(ProviderConnection).where(
                ProviderConnection.id == connection_id,
                ProviderConnection.organization_id == organization_id,
            )
        )

    def _require_row(self, organization_id: UUID, connection_id: UUID) -> ProviderConnection:
        row = self._row(organization_id, connection_id)
        if row is None:
            raise ResourceOutOfScopeError
        return row

    def _manager(self, organization_id: UUID, connection_id: UUID) -> FirewallManager:
        manager = self._session.scalar(
            select(FirewallManager).where(
                FirewallManager.organization_id == organization_id,
                FirewallManager.provider_connection_id == connection_id,
            )
        )
        if manager is None:
            raise ResourceOutOfScopeError
        return manager

    @staticmethod
    def _reset_manager_validation(manager: FirewallManager) -> None:
        manager.provider_version = None
        manager.capabilities = dict.fromkeys(manager.capabilities, "NOT_STARTED")
        manager.read_only = True

    @staticmethod
    def _disable_writes(row: ProviderConnection) -> None:
        row.write_enabled = False
        row.write_enabled_at = None
        row.write_enabled_by_user_id = None

    @staticmethod
    def _require_revision(row: ProviderConnection, expected_revision: int) -> None:
        if row.revision != expected_revision:
            raise StaleWriteError

    @staticmethod
    def _require_not_retired(row: ProviderConnection) -> None:
        if row.lifecycle == "RETIRED":
            raise InvalidChangeSetStateError

    def _flush(self) -> None:
        try:
            self._session.flush()
        except IntegrityError as exc:
            self._session.rollback()
            raise InvalidInputError from exc
