"""SQLAlchemy engine + session factory for the existing TSG (database-first).

Pool sizing is deliberate keep
(api_replicas + workers) x (pool_size + max_overflow) under the MSSQL connection
cap. We NEVER call `metadata.create_all()` — the schema is authoritative and
shared "reuse, do not recreate". `metadata` here is only for querying.
"""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings


@lru_cache
def get_engine() -> Engine:
    """Process-wide singleton Engine (cached via `lru_cache`, no args) so the
    pool_size/max_overflow budget from  is enforced once per process,
    not re-allocated on every call.
    """
    s = get_settings()
    return create_engine(
        s.db_dsn,
        pool_size=s.db_pool_size,
        max_overflow=s.db_max_overflow,
        pool_timeout=s.db_pool_timeout,
        pool_pre_ping=True,
        future=True,
    )


@lru_cache
def _sessionmaker() -> sessionmaker:
    """Cached factory bound to `get_engine()`; `db_session()` is the only
    caller. `expire_on_commit=False` so returned rows stay usable after the
    context manager commits and closes the session.
    """
    return sessionmaker(bind=get_engine(), expire_on_commit=False, future=True)


@contextmanager
def db_session() -> Iterator[Session]:
    """Transactional scope: commit on success, rollback on error, always close."""
    sess = _sessionmaker()()
    try:
        yield sess
        sess.commit()
    except Exception:
        sess.rollback()
        raise
    finally:
        sess.close()
