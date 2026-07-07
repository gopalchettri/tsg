"""Alembic environment — database-first against the existing TSG.

The URL comes from `TSG_DB_DSN` (12-factor). `0001_baseline` is empty and is
applied by `alembic stamp 0001` to mark the current schema as the starting
point; migrations 0002+ only add the M1..M10 guards forward.
"""
from __future__ import annotations

from alembic import context
from sqlalchemy import create_engine

from app.core.config import get_settings
from app.db.models import metadata

target_metadata = metadata


def _url() -> str:
    return get_settings().db_dsn


def run_migrations_offline() -> None:
    context.configure(
        url=_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(_url())
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
