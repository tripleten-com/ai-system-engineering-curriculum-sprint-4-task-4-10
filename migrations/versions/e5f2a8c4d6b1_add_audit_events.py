"""Coldline.

===================

File:              migrations/versions/ (revision e5f2a8c4d6b1)
Component:         Migrations — add audit events
Purpose:           Create the audit_events table the audit sink appends to.
Interacts With:    PostgreSQL, src/common/audit.py, src/adapters/persistence/audit_store.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.3
Concepts:          Reversible schema evolution, append-only evidence
Tools:             Python 3.12, Alembic

Revision ID: e5f2a8c4d6b1
Revises: b3d7e9f1c2a4
Create Date: 2026-10-03

One row per audit event: the sequence number that orders the table, the exception the
event is about, the event name, the trace id of the request that recorded it (nullable:
a process without a trace records none), the time, and the event's fields as one JSON
document. The table is deliberately plain and carries no secondary index: reading one
exception's trail scans it. The optional Add-On 4.A2 measures that query on a large
history and adds the index or the rewrite, so nothing here should pre-empt it.

`downgrade` drops the table and nothing else.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "e5f2a8c4d6b1"
down_revision: str | None = "b3d7e9f1c2a4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the append-only audit table."""
    op.create_table(
        "audit_events",
        sa.Column("audit_id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column("exception_id", sa.Text(), nullable=False),
        sa.Column("event", sa.Text(), nullable=False),
        sa.Column("trace_id", sa.Text(), nullable=True),
        sa.Column("recorded_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column(
            "details",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )


def downgrade() -> None:
    """Reverse exactly what `upgrade` applied, and nothing more."""
    op.drop_table("audit_events")
