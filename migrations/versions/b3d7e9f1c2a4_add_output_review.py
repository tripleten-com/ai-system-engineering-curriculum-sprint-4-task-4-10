"""Coldline.

===================

File:              migrations/versions/ (revision b3d7e9f1c2a4)
Component:         Migrations — add output review fields
Purpose:           Add the NEEDS_REVIEW state and the three fields the output policy stores.
Interacts With:    PostgreSQL and the application data layer
Sprint/Task:       Sprint 4 — Project 4 / Task 4.3
Concepts:          Reversible schema evolution
Tools:             Python 3.12, Alembic

Revision ID: b3d7e9f1c2a4
Revises: 4a1f0c2e9b17
Create Date: 2026-10-03

The Task 4.3 checkpoint stores what the output guardrail decided: a ``COMPLETED``
record keeps the validated ``handling_class`` and ``next_step`` beside its summary,
and a ``NEEDS_REVIEW`` record keeps the guardrail's ``rejection_reason`` code beside
the output policy's fixed message. The state check constraint gains ``NEEDS_REVIEW``.

The initializer's ``infra/postgres/001_opening_checkpoint.sql`` already lists the six
states for a fresh database, so dropping and recreating the constraint here is the
same constraint on a fresh stack and the widened one on a database created before
this revision. The three columns are nullable: every record written before this
revision holds NULL in them.

`downgrade` drops the three columns and restores the five-state constraint. It
refuses, with a constraint violation, while any record is in ``NEEDS_REVIEW``: a
downgrade that silently rewrote those records would lose the review they are
waiting for.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b3d7e9f1c2a4"
down_revision: str | None = "4a1f0c2e9b17"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

STATE_CONSTRAINT = "exceptions_state_check"
STATES_BEFORE = "state IN ('RECEIVED', 'QUEUED', 'PROCESSING', 'COMPLETED', 'FAILED')"
STATES_AFTER = (
    "state IN ('RECEIVED', 'QUEUED', 'PROCESSING', 'COMPLETED', 'FAILED', 'NEEDS_REVIEW')"
)


def upgrade() -> None:
    """Add the three nullable output fields and admit NEEDS_REVIEW as a state."""
    op.add_column("exceptions", sa.Column("handling_class", sa.Text(), nullable=True))
    op.add_column("exceptions", sa.Column("next_step", sa.Text(), nullable=True))
    op.add_column("exceptions", sa.Column("rejection_reason", sa.Text(), nullable=True))
    op.drop_constraint(STATE_CONSTRAINT, "exceptions", type_="check")
    op.create_check_constraint(STATE_CONSTRAINT, "exceptions", STATES_AFTER)


def downgrade() -> None:
    """Reverse exactly what `upgrade` applied, and nothing more."""
    op.drop_constraint(STATE_CONSTRAINT, "exceptions", type_="check")
    op.create_check_constraint(STATE_CONSTRAINT, "exceptions", STATES_BEFORE)
    op.drop_column("exceptions", "rejection_reason")
    op.drop_column("exceptions", "next_step")
    op.drop_column("exceptions", "handling_class")
