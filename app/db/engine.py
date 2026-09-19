"""SQLAlchemy engine + session factory (database-first).

Keep (api_replicas + workers) x (pool_size + max_overflow) under the MSSQL connection cap.
NEVER call `metadata.create_all()` — the schema is authoritative and shared; `metadata` here
is only for querying.
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
    """Process-wide singleton Engine (cached via `lru_cache`) so the pool_size/max_overflow
    budget is allocated once per process, not per call."""
    s = get_settings()
    engine = create_engine(
        s.db_dsn,
        pool_size=s.db_pool_size,
        max_overflow=s.db_max_overflow,
        pool_timeout=s.db_pool_timeout,
        pool_pre_ping=True,
        future=True,
        # SQL_ATTR_LOGIN_TIMEOUT: bounds opening a NEW connection against an unreachable host.
        # pool_pre_ping only revalidates pooled connections; pool_timeout only bounds the wait
        # for a free slot — neither bounds the DBAPI connect() call itself.
        connect_args={"timeout": s.db_connect_timeout_seconds},
    )
    if engine.dialect.driver == "pyodbc":
        # SQL_ATTR_QUERY_TIMEOUT — a different knob from connect_args["timeout"] above, which
        # is inert once the connection exists. Caps one statement, so a query blocked on
        # someone else's lock can't pin a pool connection forever. The "connect" event fires
        # for every new pooled connection (fill, overflow, reconnect), so it covers the pool.
        @event.listens_for(engine, "connect")
        def _set_query_timeout(dbapi_connection: object, connection_record: object) -> None:
            dbapi_connection.timeout = s.db_statement_timeout_seconds  # type: ignore[attr-defined]

        # retval=True: the "chained" handle_error style, where a returned exception replaces
        # SQLAlchemy's and None keeps it.
        event.listen(engine, "handle_error", map_serialization_failure, retval=True)

    return engine


#: SQLSTATE of a transaction chosen as a deadlock victim (SQL Server 1205) or a serialization
#: failure. Retrying the whole unit of work is the correct response to both.
_SERIALIZATION_FAILURE = "40001"


def map_serialization_failure(ctx) -> Exception | None:
    """A deadlock victim is TEMPORARY: surface it as OperationalError.

    pipeline_common.TRANSIENT_INFRA_ERRORS — the contract that sends an infrastructure hiccup to
    Celery's autoretry instead of failing the run — is (OperationalError,). pyodbc raises its base
    `Error` for SQLSTATE 40001, which SQLAlchemy wraps as a plain DBAPIError, so a deadlock fell
    into the generic handler and a healthy run was recorded as failed. A no-op when the error is
    already an OperationalError or has another SQLSTATE."""
    from sqlalchemy.exc import OperationalError

    if isinstance(ctx.sqlalchemy_exception, OperationalError):
        return None
    args = getattr(ctx.original_exception, "args", ())
    if args and args[0] == _SERIALIZATION_FAILURE:
        return OperationalError(ctx.statement, ctx.parameters, ctx.original_exception)
    return None


@lru_cache
def _sessionmaker() -> sessionmaker:
    """Cached factory bound to `get_engine()`. `expire_on_commit=False` so returned rows stay
    usable after `db_session()` commits and closes."""
    return sessionmaker(bind=get_engine(), expire_on_commit=False, future=True)


@contextmanager
def db_session() -> Iterator[Session]:
    """Transactional scope: commit on success, rollback on error, always close."""
    sess = _sessionmaker()()  # cached factory, then a new Session from it
    try:
        yield sess
        sess.commit()
    except Exception:
        sess.rollback()
        raise
    finally:
        sess.close()
