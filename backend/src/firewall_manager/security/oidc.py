"""Small server-side OIDC relying-party implementation.

The application owns the session and user authorization. Providers only authenticate the
external identity. Provider endpoints are discovered from deployment configuration and are never
accepted from browser input.
"""

import base64
import hashlib
import hmac
import json
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import httpx
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hashes import SHA256
from fastapi import Response
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from firewall_manager.application.errors import NotAuthenticatedError, ProviderConfigurationError
from firewall_manager.config import OidcProviderConfig, Settings
from firewall_manager.persistence.database import SessionFactory
from firewall_manager.persistence.models import (
    AuditEvent,
    AuthenticationEvent,
    AuthSession,
    ExternalIdentity,
    OidcProvider,
    User,
)
from firewall_manager.persistence.secrets import EncryptedDatabaseSecretStore
from firewall_manager.security.secret_provider import master_key

COOKIE_NAME = "fm_session"
STATE_COOKIE_PREFIX = "fm_oidc_state_"


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _secret(settings: Settings) -> bytes:
    encoded = master_key(settings)
    if encoded is None:
        raise ProviderConfigurationError(details={"reason": "session signing key unavailable"})
    return _unb64(encoded)


def _sign(value: str, settings: Settings) -> str:
    signature = hmac.new(_secret(settings), value.encode(), hashlib.sha256).digest()
    return f"{value}.{_b64(signature)}"


def _verify(value: str, settings: Settings) -> str | None:
    try:
        payload, signature = value.rsplit(".", 1)
        expected = _b64(hmac.new(_secret(settings), payload.encode(), hashlib.sha256).digest())
    except (ValueError, ProviderConfigurationError):
        return None
    return payload if hmac.compare_digest(signature, expected) else None


def redirect_uri(settings: Settings, provider_id: str) -> str:
    """Return the fixed callback derived from the deployment URL."""
    return f"{settings.app_public_url.rstrip('/')}/api/v1/auth/{provider_id}/callback"


class OidcService:
    """OIDC discovery, code exchange, claim validation, and local session lifecycle."""

    def __init__(self, session: Session, settings: Settings) -> None:
        self.session = session
        self.settings = settings
        key = master_key(settings)
        self._secrets = EncryptedDatabaseSecretStore(
            session, key, settings.secret_store_key_version
        )

    def provider(self, provider_id: str) -> OidcProviderConfig:
        row = self.session.scalar(
            select(OidcProvider).where(
                OidcProvider.provider_id == provider_id, OidcProvider.enabled.is_(True)
            )
        )
        if row is not None:
            secret = self._secrets.retrieve(
                row.organization_id, row.secret_reference, "oidc-client-secret"
            )
            return OidcProviderConfig(
                id=row.provider_id,
                kind=row.kind,
                display_name=row.display_name,
                issuer_url=row.issuer_url,
                client_id=row.client_id,
                client_secret=secret["client_secret"],
                scopes=row.scopes,
                username_claim=row.username_claim,
                display_name_claim=row.display_name_claim,
                email_claim=row.email_claim,
                mapping_claim=row.mapping_claim,
                logout=row.logout,
            )
        for provider in self.settings.oidc_provider_configs():
            if provider.id == provider_id and provider.enabled:
                return provider
        raise NotAuthenticatedError

    def _authentication_event(  # noqa: PLR0913 -- complete safe authentication evidence context
        self,
        event: str,
        outcome: str,
        *,
        provider_id: str | None = None,
        organization_id: UUID | None = None,
        user_id: UUID | None = None,
        details: dict[str, object] | None = None,
        durable: bool = False,
    ) -> None:
        row = AuthenticationEvent(
            organization_id=organization_id,
            user_id=user_id,
            provider_id=provider_id,
            event=event,
            outcome=outcome,
            details=details or {},
        )
        if durable:
            with SessionFactory() as audit_session:
                audit_session.add(row)
                audit_session.commit()
        else:
            self.session.add(row)

    async def begin(self, provider_id: str, response: Response, *, test_only: bool = False) -> str:
        provider = self.provider(provider_id)
        metadata = await self._metadata(provider)
        state = _b64(secrets.token_bytes(32))
        nonce = _b64(secrets.token_bytes(32))
        state_payload = json.dumps(
            {"state": state, "nonce": nonce, "test_only": test_only}, separators=(",", ":")
        )
        signed = _sign(_b64(state_payload.encode()), self.settings)
        response.set_cookie(
            f"{STATE_COOKIE_PREFIX}{provider.id}",
            signed,
            httponly=True,
            secure=self._secure(),
            samesite="lax",
            max_age=600,
            path=f"/api/v1/auth/{provider.id}",
        )
        params = {
            "response_type": "code",
            "client_id": provider.client_id,
            "redirect_uri": redirect_uri(self.settings, provider.id),
            "scope": " ".join(provider.scopes),
            "state": signed,
            "nonce": nonce,
        }
        return f"{metadata['authorization_endpoint']}?{httpx.QueryParams(params)}"

    async def callback(
        self, provider_id: str, code: str, state: str, response: Response, state_cookie: str | None
    ) -> bool:
        provider = self.provider(provider_id)
        provider_row = self.session.scalar(
            select(OidcProvider).where(OidcProvider.provider_id == provider.id)
        )
        organization_id = provider_row.organization_id if provider_row is not None else None
        if not state_cookie or not hmac.compare_digest(state_cookie, state):
            self._authentication_event(
                "login_failure",
                "FAILED",
                provider_id=provider.id,
                organization_id=organization_id,
                details={"reason": "state_mismatch"},
                durable=True,
            )
            raise NotAuthenticatedError
        raw = _verify(state, self.settings)
        if raw is None:
            self._authentication_event(
                "login_failure",
                "FAILED",
                provider_id=provider.id,
                organization_id=organization_id,
                details={"reason": "invalid_state"},
                durable=True,
            )
            raise NotAuthenticatedError
        try:
            payload = json.loads(_unb64(raw))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._authentication_event(
                "login_failure",
                "FAILED",
                provider_id=provider.id,
                organization_id=organization_id,
                details={"reason": "invalid_state_payload"},
                durable=True,
            )
            raise NotAuthenticatedError from exc
        metadata = await self._metadata(provider)
        async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
            token_response = await client.post(
                metadata["token_endpoint"],
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri(self.settings, provider.id),
                    "client_id": provider.client_id,
                    "client_secret": provider.client_secret.get_secret_value(),
                },
            )
        if token_response.status_code >= 400:
            self._authentication_event(
                "login_failure",
                "FAILED",
                provider_id=provider.id,
                organization_id=organization_id,
                details={"reason": "token_exchange_failed"},
                durable=True,
            )
            raise NotAuthenticatedError
        token = token_response.json()
        try:
            claims = await self._validate_id_token(
                str(token.get("id_token", "")), metadata, provider, payload["nonce"]
            )
        except Exception as exc:
            self._authentication_event(
                "login_failure",
                "FAILED",
                provider_id=provider.id,
                organization_id=organization_id,
                details={"reason": "invalid_id_token"},
                durable=True,
            )
            if isinstance(exc, NotAuthenticatedError):
                raise
            raise NotAuthenticatedError from exc
        if payload.get("test_only") is True:
            response.delete_cookie(
                f"{STATE_COOKIE_PREFIX}{provider.id}", path=f"/api/v1/auth/{provider.id}"
            )
            return True
        subject = str(claims["sub"])
        identity = self.session.scalar(
            select(ExternalIdentity).where(
                ExternalIdentity.issuer == str(provider.issuer_url),
                ExternalIdentity.subject == subject,
            )
        )
        user = (
            self.session.scalar(
                select(User).where(User.id == identity.user_id, User.is_active.is_(True))
            )
            if identity is not None
            else None
        )
        if user is None:
            self._authentication_event(
                "login_failure",
                "FAILED",
                provider_id=provider.id,
                organization_id=organization_id,
                details={
                    "reason": "disabled_user" if identity is not None else "unmapped_identity"
                },
                durable=True,
            )
            raise NotAuthenticatedError
        now = datetime.now(UTC)
        raw_token = secrets.token_urlsafe(48)
        self.session.add(
            AuthSession(
                user_id=user.id,
                token_hash=hashlib.sha256(raw_token.encode()).hexdigest(),
                provider_id=provider.id,
                expires_at=now + timedelta(hours=self.settings.auth_session_absolute_hours),
                last_seen_at=now,
            )
        )
        self._authentication_event(
            "login_success",
            "SUCCESS",
            provider_id=provider.id,
            organization_id=user.organization_id,
            user_id=user.id,
            details={"issuer": str(provider.issuer_url)},
        )
        self.session.flush()
        response.set_cookie(
            COOKIE_NAME,
            raw_token,
            httponly=True,
            secure=self._secure(),
            samesite="lax",
            max_age=self.settings.auth_session_absolute_hours * 3600,
            path="/",
        )
        response.delete_cookie(
            f"{STATE_COOKIE_PREFIX}{provider.id}", path=f"/api/v1/auth/{provider.id}"
        )
        return False

    def logout(self, token: str | None, response: Response) -> None:
        if token:
            row = self.session.scalar(
                select(AuthSession).where(
                    AuthSession.token_hash == hashlib.sha256(token.encode()).hexdigest()
                )
            )
            if row:
                row.revoked_at = datetime.now(UTC)
                self._authentication_event(
                    "logout",
                    "SUCCESS",
                    provider_id=row.provider_id,
                    user_id=row.user_id,
                    organization_id=self.session.scalar(
                        select(User.organization_id).where(User.id == row.user_id)
                    ),
                )
        response.delete_cookie(COOKIE_NAME, path="/")

    def principal(self, token: str | None) -> tuple[User, AuthSession] | None:
        authenticated = self._authenticated_session(token)
        if authenticated is None:
            return None
        return authenticated

    def actor(self, token: str | None) -> tuple[User, AuthSession] | None:
        """Resolve the real authenticated user, even while proxying."""
        authenticated = self._authenticated_session(token)
        if authenticated is None:
            return None
        user, row = authenticated
        actor_id = row.actor_user_id or user.id
        actor = self.session.scalar(
            select(User).where(User.id == actor_id, User.is_active.is_(True))
        )
        if actor is None:
            return None
        return actor, row

    def start_proxy(self, token: str | None, target_user_id: UUID, reason: str) -> None:
        authenticated = self.actor(token)
        if authenticated is None:
            raise NotAuthenticatedError
        actor, row = authenticated
        if actor.role != "admin" or row.actor_user_id is not None:
            raise NotAuthenticatedError
        target = self.session.scalar(
            select(User).where(
                User.id == target_user_id,
                User.organization_id == actor.organization_id,
                User.is_active.is_(True),
            )
        )
        if target is None or target.id == actor.id or target.role == "admin":
            raise NotAuthenticatedError
        row.actor_user_id = actor.id
        row.user_id = target.id
        row.proxy_started_at = datetime.now(UTC)
        row.proxy_reason = reason
        self.session.add(
            AuditEvent(
                organization_id=actor.organization_id,
                actor_user_id=actor.id,
                action="proxy_started",
                resource_type="user",
                resource_id=target.id,
                decision="ALLOW",
                reason_code="PLATFORM_ADMIN_PROXY",
                interface="rest",
                details={
                    "effective_user_id": str(target.id),
                    "effective_user_email": target.email,
                    "reason": reason,
                },
            )
        )

    def stop_proxy(self, token: str | None) -> None:
        authenticated = self.actor(token)
        if authenticated is None:
            raise NotAuthenticatedError
        actor, row = authenticated
        if row.actor_user_id is None:
            raise NotAuthenticatedError
        target_id = row.user_id
        target = self.session.scalar(select(User).where(User.id == target_id))
        row.user_id = actor.id
        row.actor_user_id = None
        row.proxy_started_at = None
        row.proxy_reason = None
        self.session.add(
            AuditEvent(
                organization_id=actor.organization_id,
                actor_user_id=actor.id,
                action="proxy_ended",
                resource_type="user",
                resource_id=target_id,
                decision="ALLOW",
                reason_code="PLATFORM_ADMIN_PROXY",
                interface="rest",
                details={
                    "effective_user_id": str(target_id),
                    "effective_user_email": target.email if target is not None else None,
                },
            )
        )

    def _authenticated_session(self, token: str | None) -> tuple[User, AuthSession] | None:
        if not token:
            return None
        row = self.session.scalar(
            select(AuthSession).where(
                AuthSession.token_hash == hashlib.sha256(token.encode()).hexdigest()
            )
        )
        now = datetime.now(UTC)
        idle_cutoff = now - timedelta(minutes=self.settings.auth_session_idle_minutes)
        if (
            row is None
            or row.revoked_at is not None
            or row.expires_at <= now
            or row.last_seen_at <= idle_cutoff
        ):
            if row is not None and row.revoked_at is None:
                user = self.session.scalar(select(User).where(User.id == row.user_id))
                self._authentication_event(
                    "session_expired",
                    "EXPIRED",
                    provider_id=row.provider_id,
                    organization_id=user.organization_id if user is not None else None,
                    user_id=row.user_id,
                    details={"reason": "revoked" if row.revoked_at else "expired"},
                    durable=True,
                )
            return None
        user = self.session.scalar(
            select(User).where(User.id == row.user_id, User.is_active.is_(True))
        )
        if user is None:
            return None
        # Heartbeat the idle window in bounded intervals, avoiding a write lock on every
        # parallel page request while still providing sliding session expiration.
        if row.last_seen_at <= now - timedelta(minutes=5):
            self.session.execute(
                update(AuthSession)
                .where(AuthSession.id == row.id, AuthSession.last_seen_at == row.last_seen_at)
                .values(last_seen_at=now)
            )
            row.last_seen_at = now
        return user, row

    async def _metadata(self, provider: OidcProviderConfig) -> dict[str, Any]:
        issuer = str(provider.issuer_url).rstrip("/")
        if not issuer.startswith("https://") and self.settings.app_environment not in {
            "development",
            "test",
        }:
            raise ProviderConfigurationError(
                details={"reason": "production OIDC requires HTTPS issuer"}
            )
        discovery = f"{issuer}/.well-known/openid-configuration"
        async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
            result = await client.get(discovery)
        if result.status_code >= 400:
            raise ProviderConfigurationError(details={"reason": "OIDC discovery failed"})
        metadata = result.json()
        if metadata.get("issuer", "").rstrip("/") != issuer:
            raise ProviderConfigurationError(details={"reason": "OIDC issuer mismatch"})
        for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            if not isinstance(metadata.get(key), str) or not metadata[key].startswith("https://"):
                raise ProviderConfigurationError(
                    details={"reason": "OIDC metadata endpoint invalid"}
                )
        return metadata

    async def _validate_id_token(
        self, token: str, metadata: dict[str, Any], provider: OidcProviderConfig, nonce: str
    ) -> dict[str, Any]:
        try:
            header_b64, claims_b64, signature_b64 = token.split(".")
            header = json.loads(_unb64(header_b64))
            claims: dict[str, Any] = json.loads(_unb64(claims_b64))
        except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise NotAuthenticatedError from exc
        if header.get("alg") != "RS256" or not header.get("kid"):
            raise NotAuthenticatedError
        async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
            jwks = (await client.get(metadata["jwks_uri"])).json()
        key = next(
            (
                item
                for item in jwks.get("keys", [])
                if item.get("kid") == header["kid"] and item.get("kty") == "RSA"
            ),
            None,
        )
        if key is None:
            raise NotAuthenticatedError
        public_key = rsa.RSAPublicNumbers(
            int.from_bytes(_unb64(key["e"]), "big"), int.from_bytes(_unb64(key["n"]), "big")
        ).public_key()
        try:
            public_key.verify(
                _unb64(signature_b64), f"{header_b64}.{claims_b64}".encode(), PKCS1v15(), SHA256()
            )
        except Exception as exc:  # cryptography uses backend-specific signature exceptions
            raise NotAuthenticatedError from exc
        now = datetime.now(UTC).timestamp()
        audience = claims.get("aud")
        if (
            claims.get("iss", "").rstrip("/") != str(provider.issuer_url).rstrip("/")
            or claims.get("sub") is None
            or claims.get("nonce") != nonce
            or claims.get("exp", 0) < now
            or (
                provider.client_id not in audience
                if isinstance(audience, list)
                else audience != provider.client_id
            )
        ):
            raise NotAuthenticatedError
        return claims

    def _secure(self) -> bool:
        return self.settings.app_environment in {"staging", "production"}
