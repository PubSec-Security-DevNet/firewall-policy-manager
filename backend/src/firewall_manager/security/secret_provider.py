# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Runtime master-key providers for deployment-owned secret injection."""

import base64
from pathlib import Path

import httpx

from firewall_manager.application.errors import SecretStoreUnavailableError
from firewall_manager.config import Settings


def _vault_key(settings: Settings) -> str:
    try:
        if settings.vault_url is None:
            raise ValueError("Vault URL is missing")
        verify: bool | str = settings.vault_ca_cert or True
        token = settings.vault_token.get_secret_value() if settings.vault_token else None
        if token is None:
            if not settings.vault_role_id_file or not settings.vault_secret_id_file:
                raise ValueError("Vault AppRole credentials are incomplete")
            login = httpx.post(
                f"{settings.vault_url.rstrip('/')}/v1/auth/approle/login",
                json={
                    "role_id": Path(settings.vault_role_id_file)
                    .read_text(encoding="utf-8")
                    .strip(),
                    "secret_id": Path(settings.vault_secret_id_file)
                    .read_text(encoding="utf-8")
                    .strip(),
                },
                timeout=5,
                follow_redirects=False,
                verify=verify,
            )
            login.raise_for_status()
            token_value = login.json().get("auth", {}).get("client_token")
            if not isinstance(token_value, str) or not token_value:
                raise ValueError("Vault AppRole response did not contain a client token")
            token = token_value
        response = httpx.get(
            f"{settings.vault_url.rstrip('/')}/v1/{settings.vault_secret_path.lstrip('/')}",
            headers={"X-Vault-Token": token},
            timeout=5,
            follow_redirects=False,
            verify=verify,
        )
        response.raise_for_status()
        payload = response.json()
        value = payload.get("data", {}).get("data", {}).get("APP_SECRET_KEY")
        if not isinstance(value, str):
            value = payload.get("data", {}).get("APP_SECRET_KEY")
        if not isinstance(value, str):
            raise ValueError("Vault response did not contain APP_SECRET_KEY")
        value = value.strip()
        if len(base64.b64decode(value, validate=True)) != 32:
            raise ValueError("Vault APP_SECRET_KEY must decode to 32 bytes")
        return value
    except (OSError, httpx.HTTPError, ValueError, TypeError, KeyError) as exc:
        raise SecretStoreUnavailableError from exc


def master_key(settings: Settings) -> str | None:
    """Resolve the encryption key without logging or persisting it."""
    if settings.secret_store_master_key is not None:
        return settings.secret_store_master_key.get_secret_value()
    if (
        settings.secret_store_provider == "vault"  # noqa: S105
        and settings.vault_url
        and (settings.vault_token or settings.vault_role_id_file)
    ):
        return _vault_key(settings)
    return None
