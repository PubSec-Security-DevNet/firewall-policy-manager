"""Runtime master-key providers for deployment-owned secret injection."""

import base64

import httpx

from firewall_manager.application.errors import SecretStoreUnavailableError
from firewall_manager.config import Settings


def _vault_key(url: str, token: str, path: str) -> str:
    try:
        response = httpx.get(
            f"{url.rstrip('/')}/v1/{path.lstrip('/')}",
            headers={"X-Vault-Token": token},
            timeout=5,
            follow_redirects=False,
        )
        response.raise_for_status()
        payload = response.json()
        value = payload.get("data", {}).get("data", {}).get("APP_SECRET_KEY")
        if not isinstance(value, str):
            value = payload.get("data", {}).get("APP_SECRET_KEY")
        if not isinstance(value, str):
            raise ValueError("Vault response did not contain APP_SECRET_KEY")
        if len(base64.b64decode(value, validate=True)) != 32:
            raise ValueError("Vault APP_SECRET_KEY must decode to 32 bytes")
        return value
    except (httpx.HTTPError, ValueError, TypeError, KeyError) as exc:
        raise SecretStoreUnavailableError from exc


def master_key(settings: Settings) -> str | None:
    """Resolve the encryption key without logging or persisting it."""
    if settings.secret_store_master_key is not None:
        return settings.secret_store_master_key.get_secret_value()
    if (
        settings.secret_store_provider == "vault"  # noqa: S105
        and settings.vault_url
        and settings.vault_token
    ):
        return _vault_key(
            settings.vault_url,
            settings.vault_token.get_secret_value(),
            settings.vault_secret_path,
        )
    return None
