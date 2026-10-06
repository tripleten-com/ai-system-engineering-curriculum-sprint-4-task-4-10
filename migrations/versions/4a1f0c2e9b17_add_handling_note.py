"""Coldline.

===================

File:              migrations/versions/ (revision 4a1f0c2e9b17)
Component:         Migrations — add handling note
Purpose:           Add exceptions.handling_note, the raw note each stored reading arrived with.
Interacts With:    PostgreSQL and the application data layer
Sprint/Task:       Sprint 4 — Project 4
Concepts:          Reversible schema evolution
Tools:             Python 3.12, Alembic

Revision ID: 4a1f0c2e9b17
Revises: c0d895eb5c59
Create Date: 2026-10-02

The Project 4 opening checkpoint lets a reading carry a free-text handling
note. The reading is stored whole in the JSON column already, so this column
adds no information; it puts the raw note where a query, an audit event, or a
scan can reach it without unpacking the reading. It is nullable: readings
without a note, and every record written before this revision, hold NULL.

`downgrade` drops the column and nothing else. The note inside the JSON
reading is untouched either way.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "4a1f0c2e9b17"
down_revision: str | None = "c0d895eb5c59"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add the nullable handling-note column beside the stored reading."""
    op.add_column("exceptions", sa.Column("handling_note", sa.Text(), nullable=True))


def downgrade() -> None:
    """Reverse exactly what `upgrade` applied, and nothing more."""
    op.drop_column("exceptions", "handling_note")
