"""Coldline.

===================

File:              migrations/env.py
Component:         Migrations — Alembic environment
Purpose:           Run migrations against the supplied PostgreSQL runtime.
Interacts With:    alembic.ini, migrations/versions/, PostgreSQL
Sprint/Task:       Sprint 2 — Project 2 / Task 2.6
Concepts:          Version-controlled schema evolution
Tools:             Python 3.12, Alembic, SQLAlchemy, asyncpg

This environment is supplied and protected. Two decisions in it are worth
knowing while you write a migration.

Autogeneration is deliberately off. There is no model metadata to compare
against, because the schema is owned by explicit SQL rather than by an ORM, so
`alembic revision --autogenerate` has nothing to diff. You write `upgrade` and
`downgrade` yourself, which is also what makes the rollback real rather than
guessed.

The database URL comes from `COLDLINE_DATABASE_URL`, which the container
already provides. No connection string is committed to this repository, and
`alembic revision` never connects at all - only `upgrade` and `downgrade` do.
"""

import asyncio
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config
from sqlalchemy.pool import NullPool

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# No model metadata: this schema is owned by explicit SQL, so autogenerate has
# nothing to compare and every migration is written by hand.
target_metadata = None


def _database_url() -> str:
    """Return the async database URL, or fail with an actionable message."""
    url = os.environ.get("COLDLINE_DATABASE_URL", "")
    if not url:
        raise RuntimeError(
            "COLDLINE_DATABASE_URL is not set. Run migrations through `poe migrate`, "
            "which executes them inside the API container where it is provided."
        )
    # The runtime uses asyncpg; SQLAlchemy needs that named in the URL scheme.
    return url.replace("postgresql://", "postgresql+asyncpg://", 1)


def run_migrations_offline() -> None:
    """Emit migration SQL without a connection."""
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def _run(connection: Connection) -> None:
    """Run migrations on one live connection."""
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def _run_async() -> None:
    """Open one connection and run the migrations on it."""
    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = _database_url()
    engine = async_engine_from_config(section, prefix="sqlalchemy.", poolclass=NullPool)
    async with engine.connect() as connection:
        await connection.run_sync(_run)
    await engine.dispose()


def run_migrations_online() -> None:
    """Run migrations against the live database."""
    asyncio.run(_run_async())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
