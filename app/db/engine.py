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

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings


@lru_cache
def get_engine() -> Engine:
    """Plain English: builds the one shared database connection pool for this
    process and hands back that same object on every call, instead of making
    a new pool each time.

    Process-wide singleton Engine (cached via `lru_cache`, no args) so the
    pool_size/max_overflow budget from  is enforced once per process,
    not re-allocated on every call.
    """
    s = get_settings()
    engine = create_engine(
        s.db_dsn,
        pool_size=s.db_pool_size,
        max_overflow=s.db_max_overflow,
        pool_timeout=s.db_pool_timeout,
        pool_pre_ping=True,
        future=True,
        # In short: caps how long we wait when opening a brand-new connection.
        # pyodbc connect-level timeout: bounds opening a *new* connection (pool fill,
        # overflow growth, post-invalidation reconnect). pool_pre_ping only re-validates
        # already-pooled connections; pool_timeout only bounds waiting for a free slot.
        # Neither bounds the DBAPI connect() call itself against a network-unreachable
        # host, which is what this closes.
        connect_args={"timeout": s.db_connect_timeout_seconds},
    )
    if engine.dialect.driver == "pyodbc":
        # In short: caps how long an already-acquired connection may spend actually
        # executing one statement, so a query blocked on a lock held by some other
        # session can't pin a pool connection forever.
        #
        # pyodbc.Connection.timeout (SQL_ATTR_QUERY_TIMEOUT) is a *different* knob
        # from connect_args["timeout"] above (SQL_ATTR_LOGIN_TIMEOUT): the connect_args
        # one only applies while pyodbc.connect() is establishing the connection, and
        # is inert for the lifetime of the connection after that. Query timeout has to
        # be set on the DBAPI connection object itself, after it exists. The "connect"
        # event fires for every new pooled connection -- initial fill, overflow growth,
        # post-invalidation reconnect -- so this covers the whole pool, not just the
        # first connection opened.
        @event.listens_for(engine, "connect")
        def _set_query_timeout(dbapi_connection: object, connection_record: object) -> None:
            dbapi_connection.timeout = s.db_statement_timeout_seconds  # type: ignore[attr-defined]

    return engine


@lru_cache
def _sessionmaker() -> sessionmaker:
    """Plain English: builds (once) the factory used to create new database
    sessions, bound to the shared engine.

    Cached factory bound to `get_engine()`; `db_session()` is the only
    caller. `expire_on_commit=False` so returned rows stay usable after the
    context manager commits and closes the session.
    """
    return sessionmaker(bind=get_engine(), expire_on_commit=False, future=True)


@contextmanager
def db_session() -> Iterator[Session]:
    """Transactional scope: commit on success, rollback on error, always close."""
    # _sessionmaker() returns the cached factory; calling it again (the second `()`) creates a new Session.
    sess = _sessionmaker()()
    try:
        yield sess
        sess.commit()
    except Exception:
        # Something failed while the caller was using the session: undo any partial changes.
        sess.rollback()
        raise
    finally:
        # Always give the connection back to the pool, whether we succeeded or failed.
        sess.close()
