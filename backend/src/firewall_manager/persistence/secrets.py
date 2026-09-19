"""Authenticated encrypted database SecretStore for local/container deployments."""

import base64
import binascii
import json
import os
from datetime import UTC, datetime
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select
from sqlalchemy.orm import Session

from firewall_manager.application.errors import (
    ResourceOutOfScopeError,
    SecretStoreUnavailableError,
)
from firewall_manager.persistence.models import SecretRecord


class EncryptedDatabaseSecretStore:
    """Store AES-256-GCM ciphertext while keeping the root key outside PostgreSQL.

    Associated data binds ciphertext to its organization, immutable secret identifier,
    purpose, and key version. A database copy without the external key cannot decrypt secrets;
    the key alone has no ciphertext or organization metadata.
    """

    def __init__(self, session: Session, encoded_master_key: str | None, key_version: int) -> None:
        self._session = session
        self._key_version = key_version
        try:
            self._key = (
                base64.b64decode(encoded_master_key, validate=True) if encoded_master_key else None
            )
        except (binascii.Error, ValueError) as exc:
            raise SecretStoreUnavailableError from exc
        if self._key is not None and len(self._key) != 32:
            raise SecretStoreUnavailableError

    def create(self, organization_id: UUID, purpose: str, value: dict[str, str]) -> UUID:
        secret_id = uuid4()
        nonce, ciphertext = self._encrypt(organization_id, secret_id, purpose, value)
        self._session.add(
            SecretRecord(
                id=secret_id,
                organization_id=organization_id,
                purpose=purpose,
                ciphertext=ciphertext,
                nonce=nonce,
                key_version=self._key_version,
                rotated_at=datetime.now(UTC),
            )
        )
        self._session.flush()
        return secret_id

    def retrieve(self, organization_id: UUID, secret_id: UUID, purpose: str) -> dict[str, str]:
        row = self._session.scalar(
            select(SecretRecord).where(
                SecretRecord.id == secret_id,
                SecretRecord.organization_id == organization_id,
                SecretRecord.purpose == purpose,
            )
        )
        if row is None or self._key is None:
            if self._key is None:
                raise SecretStoreUnavailableError
            raise ResourceOutOfScopeError
        aad = self._aad(organization_id, secret_id, purpose, row.key_version)
        try:
            plaintext = AESGCM(self._key).decrypt(row.nonce, row.ciphertext, aad)
            payload = json.loads(plaintext)
        except (InvalidTag, UnicodeDecodeError, json.JSONDecodeError, TypeError) as exc:
            raise SecretStoreUnavailableError from exc
        if not isinstance(payload, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in payload.items()
        ):
            raise SecretStoreUnavailableError
        return payload

    def replace(
        self, organization_id: UUID, secret_id: UUID, purpose: str, value: dict[str, str]
    ) -> None:
        row = self._session.scalar(
            select(SecretRecord).where(
                SecretRecord.id == secret_id,
                SecretRecord.organization_id == organization_id,
                SecretRecord.purpose == purpose,
            )
        )
        if row is None:
            raise ResourceOutOfScopeError
        nonce, ciphertext = self._encrypt(organization_id, secret_id, purpose, value)
        row.nonce = nonce
        row.ciphertext = ciphertext
        row.key_version = self._key_version
        row.rotated_at = datetime.now(UTC)
        self._session.flush()

    def _encrypt(
        self, organization_id: UUID, secret_id: UUID, purpose: str, value: dict[str, str]
    ) -> tuple[bytes, bytes]:
        if self._key is None:
            raise SecretStoreUnavailableError
        nonce = os.urandom(12)
        plaintext = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        aad = self._aad(organization_id, secret_id, purpose, self._key_version)
        return nonce, AESGCM(self._key).encrypt(nonce, plaintext, aad)

    @staticmethod
    def _aad(organization_id: UUID, secret_id: UUID, purpose: str, key_version: int) -> bytes:
        return f"{organization_id}:{secret_id}:{purpose}:v{key_version}".encode()
