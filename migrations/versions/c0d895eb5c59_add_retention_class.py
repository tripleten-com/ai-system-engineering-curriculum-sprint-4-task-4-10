"""Coldline.

===================

File:              migrations/versions/ (revision c0d895eb5c59)
Component:         Migrations — add retention class
Purpose:           Add documents.retention_class with a default and a value constraint.
Interacts With:    PostgreSQL and the application data layer
Sprint/Task:       Sprint 2 — Project 2
Concepts:          Reversible schema evolution
Tools:             Python 3.12, Alembic

Revision ID: c0d895eb5c59
Revises: 0001baseline
Create Date: 2026-09-07 03:55:44.875527

This is the reference migration from Task 2.6, now supplied and protected,
and the initializer applies it on every start. A student's own Task 2.6
migration stays in that Task's pull request and never has to match this file.

The column is added NOT NULL with a server default, which is what lets it
apply to a table that already holds rows: PostgreSQL fills every existing
row with the default rather than refusing the change.

`downgrade` drops the constraint before the column, and drops nothing else.
Recreating the table instead would take its rows - and, through the foreign
key, its chunks - with it.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c0d895eb5c59"
down_revision: str | None = "0001baseline"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add the retention class column with its default and its permitted values."""
    op.add_column(
        "documents",
        sa.Column(
            "retention_class",
            sa.Text(),
            nullable=False,
            server_default=sa.text("'standard'"),
        ),
    )
    op.create_check_constraint(
        "documents_retention_class_check",
        "documents",
        "retention_class IN ('standard', 'extended')",
    )


def downgrade() -> None:
    """Reverse exactly what `upgrade` applied, and nothing more."""
    op.drop_constraint("documents_retention_class_check", "documents", type_="check")
    op.drop_column("documents", "retention_class")
