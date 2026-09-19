"""Restricted-secret encryption, isolation, tamper detection, and logging regressions."""

import base64
import io
import logging
import os
from typing import cast
from uuid import uuid4

import pytest
from sqlalchemy import Table, create_engine, select
from sqlalchemy.orm import Session

from firewall_manager.application.errors import ResourceOutOfScopeError, SecretStoreUnavailableError
from firewall_manager.persistence.models import Base, Organization, SecretRecord
from firewall_manager.persistence.secrets import EncryptedDatabaseSecretStore
from firewall_manager.security.redaction import SecretRedactionFilter


def _session() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(
        engine,
        tables=[
            cast(Table, Organization.__table__),
            cast(Table, SecretRecord.__table__),
        ],
    )
    return Session(engine)


def _key() -> str:
    return base64.b64encode(os.urandom(32)).decode()


def test_encrypted_database_secret_store_is_organization_and_purpose_bound() -> None:
    session = _session()
    organization_id = uuid4()
    other_organization_id = uuid4()
    session.add_all(
        (
            Organization(id=organization_id, name="Primary"),
            Organization(id=other_organization_id, name="Other"),
        )
    )
    session.flush()
    store = EncryptedDatabaseSecretStore(session, _key(), 7)
    secret_id = store.create(
        organization_id,
        "provider-connection:one",
        {"username": "api-user", "password": "fmc-password"},
    )

    row = session.scalar(select(SecretRecord).where(SecretRecord.id == secret_id))
    assert row is not None
    assert b"fmc-password" not in row.ciphertext
    assert row.key_version == 7
    assert store.retrieve(organization_id, secret_id, "provider-connection:one") == {
        "username": "api-user",
        "password": "fmc-password",
    }
    with pytest.raises(ResourceOutOfScopeError):
        store.retrieve(other_organization_id, secret_id, "provider-connection:one")
    with pytest.raises(ResourceOutOfScopeError):
        store.retrieve(organization_id, secret_id, "provider-connection:two")


def test_secret_ciphertext_tampering_fails_authenticated_decryption() -> None:
    session = _session()
    organization_id = uuid4()
    session.add(Organization(id=organization_id, name="Primary"))
    session.flush()
    store = EncryptedDatabaseSecretStore(session, _key(), 1)
    secret_id = store.create(
        organization_id, "provider-connection:one", {"token": "scc-bearer-token"}
    )
    row = session.get(SecretRecord, secret_id)
    assert row is not None
    row.ciphertext = bytes([row.ciphertext[0] ^ 1]) + row.ciphertext[1:]
    session.flush()

    with pytest.raises(SecretStoreUnavailableError):
        store.retrieve(organization_id, secret_id, "provider-connection:one")


def test_logging_filter_redacts_provider_secrets_and_authorization_headers() -> None:
    output = io.StringIO()
    handler = logging.StreamHandler(output)
    handler.addFilter(SecretRedactionFilter())
    logger = logging.getLogger("redaction-regression")
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.INFO)

    secrets = (
        "fmc-password",
        "fmc-access-token",
        "fmc-refresh-token",
        "scc-bearer-token",
        "basic-credential",
    )
    logger.info(
        "password=%s X-auth-access-token=%s X-auth-refresh-token=%s Authorization=Bearer %s",
        *secrets[:4],
        extra={"authorization": f"Basic {secrets[4]}"},
    )
    rendered = output.getvalue()
    for secret in secrets:
        assert secret not in rendered
    assert rendered.count("[REDACTED]") >= 4
