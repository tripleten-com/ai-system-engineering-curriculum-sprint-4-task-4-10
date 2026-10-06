"""Coldline.

===================

File:              migrations/versions/0001baseline_coldline_initialized_schema.py
Component:         Migrations — Baseline
Purpose:           Mark the initializer-created schema as the migration starting point.
Interacts With:    PostgreSQL and infra/postgres/004_migration_baseline.sql
Sprint/Task:       Sprint 2 — Project 2 / Task 2.6
Concepts:          Reversible schema evolution, baseline revision
Tools:             Python 3.12, Alembic

Revision ID: 0001baseline
Revises:
Create Date: 2026-09-07

This baseline is intentionally empty. The `exceptions`, `documents`, `chunks`,
and `idempotency_claims` tables are created by the initializer from explicit
SQL under `infra/postgres/`, before any migration runs. Alembic still needs a
first revision to chain from, and the initializer stamps the database at this
one.

Do not make this revision create anything. It exists to say "the schema as
initialized", and rewriting it would make the stamped state disagree with what
the database actually holds.
"""

from collections.abc import Sequence

revision: str = "0001baseline"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Do nothing: the initializer already created this schema."""


def downgrade() -> None:
    """Do nothing: this baseline created nothing to reverse."""
