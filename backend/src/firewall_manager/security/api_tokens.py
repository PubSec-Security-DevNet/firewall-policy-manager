"""Hash-only, scoped credentials for non-browser API clients."""

import hashlib
import secrets
from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from firewall_manager.persistence.models import ApiToken, User

TOKEN_PREFIX = "fm_"  # noqa: S105 -- public, non-secret token prefix
VALID_SCOPES = frozenset({"read", "write", "admin"})


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode("ascii")).hexdigest()


def create(
    session: Session,
    user: User,
    name: str,
    scopes: list[str],
    expires_at: datetime | None,
) -> tuple[ApiToken, str]:
    normalized = list(dict.fromkeys(scopes))
    if not normalized or any(scope not in VALID_SCOPES for scope in normalized):
        raise ValueError("scopes must contain only read, write, or admin")
    raw = TOKEN_PREFIX + secrets.token_urlsafe(32)
    row = ApiToken(
        organization_id=user.organization_id,
        user_id=user.id,
        name=name,
        token_hash=_hash(raw),
        token_prefix=raw[:12],
        scopes=normalized,
        expires_at=expires_at,
    )
    session.add(row)
    session.flush()
    return row, raw


def authenticate(session: Session, raw: str) -> tuple[ApiToken, User] | None:
    row = session.scalar(select(ApiToken).where(ApiToken.token_hash == _hash(raw)))
    if row is None or row.revoked_at is not None:
        return None
    now = datetime.now(UTC)
    if row.expires_at is not None and row.expires_at <= now:
        return None
    user = session.get(User, row.user_id)
    if user is None or not user.is_active:
        return None
    row.last_used_at = now
    return row, user


def revoke(session: Session, token_id, organization_id) -> bool:
    row = session.scalar(
        select(ApiToken).where(ApiToken.id == token_id, ApiToken.organization_id == organization_id)
    )
    if row is None or row.revoked_at is not None:
        return False
    row.revoked_at = datetime.now(UTC)
    return True


def cleanup_expired(session: Session) -> int:
    cutoff = datetime.now(UTC)
    result = session.execute(
        update(ApiToken)
        .where(ApiToken.expires_at.is_not(None), ApiToken.expires_at <= cutoff)
        .values(revoked_at=cutoff)
    )
    return result.rowcount
