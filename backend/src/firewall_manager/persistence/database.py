"""Database engine and unit-of-work helpers."""

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from firewall_manager.config import get_settings

_engine = create_engine(get_settings().database_url, pool_pre_ping=True)
SessionFactory = sessionmaker(bind=_engine, expire_on_commit=False)


def get_session() -> Generator[Session]:
    """Yield a request-scoped SQLAlchemy session."""
    with SessionFactory() as session:
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise


def new_session() -> Session:
    """Create a caller-managed SQLAlchemy session for non-request processes."""
    return SessionFactory()
