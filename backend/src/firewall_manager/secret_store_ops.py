# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Operator checks and authenticated key rotation for database-backed secrets."""

import base64
import binascii
import json
import os
import sys
from datetime import UTC, datetime

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select

from firewall_manager.config import get_settings
from firewall_manager.persistence.database import new_session
from firewall_manager.persistence.models import SecretRecord
from firewall_manager.security.secret_provider import master_key


def _key(value: str | None) -> bytes:
    if not value:
        raise ValueError("a base64-encoded 32-byte key is required")
    try:
        result = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("secret key is not valid base64") from exc
    if len(result) != 32:
        raise ValueError("secret key must decode to 32 bytes")
    return result


def _aad(row: SecretRecord, version: int) -> bytes:
    return f"{row.organization_id}:{row.id}:{row.purpose}:v{version}".encode()


def _decrypt(row: SecretRecord, key: bytes) -> dict[str, str]:
    try:
        payload = json.loads(
            AESGCM(key).decrypt(row.nonce, row.ciphertext, _aad(row, row.key_version))
        )
    except (InvalidTag, UnicodeDecodeError, json.JSONDecodeError, TypeError) as exc:
        raise ValueError(f"secret validation failed for record {row.id}") from exc
    if not isinstance(payload, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in payload.items()
    ):
        raise ValueError(f"secret payload is invalid for record {row.id}")
    return payload


def check() -> int:
    key = _key(master_key(get_settings()))
    with new_session() as session:
        rows = list(session.scalars(select(SecretRecord)))
        for row in rows:
            _decrypt(row, key)
    return len(rows)


def rotate() -> int:
    old = _key(os.environ.get("OLD_APP_SECRET_KEY"))
    new = _key(os.environ.get("NEW_APP_SECRET_KEY"))
    version = int(os.environ.get("NEW_SECRET_STORE_KEY_VERSION", "0"))
    if version < 1:
        raise ValueError("NEW_SECRET_STORE_KEY_VERSION must be a positive integer")
    if old == new:
        raise ValueError("old and new secret keys must differ")
    with new_session() as session:
        rows = list(session.scalars(select(SecretRecord)))
        for row in rows:
            payload = _decrypt(row, old)
            nonce = os.urandom(12)
            plaintext = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            row.nonce = nonce
            row.ciphertext = AESGCM(new).encrypt(nonce, plaintext, _aad(row, version))
            row.key_version = version
            row.rotated_at = datetime.now(UTC)
        session.commit()
    return len(rows)


def main() -> None:
    command = sys.argv[1] if len(sys.argv) == 2 else ""
    count = check() if command == "check" else rotate() if command == "rotate" else 0
    if command not in {"check", "rotate"}:
        raise SystemExit("usage: python -m firewall_manager.secret_store_ops check|rotate")
    sys.stderr.write(f"Secret store {command} completed for {count} records.\n")


if __name__ == "__main__":
    main()
