"""Coldline.

===================

File:              migrations/versions/ (revision ${up_revision})
Component:         Migrations — ${message}
Purpose:           ${message}
Interacts With:    PostgreSQL and the application data layer
Sprint/Task:       Sprint 2 — Project 2 / Task 2.6
Concepts:          Reversible schema evolution
Tools:             Python 3.12, Alembic

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
% if imports:
${imports}
% endif

revision: str = "${up_revision}"
down_revision: str | None = ${'"' + down_revision + '"' if down_revision else "None"}
branch_labels: str | Sequence[str] | None = ${repr(branch_labels)}
depends_on: str | Sequence[str] | None = ${repr(depends_on)}


def upgrade() -> None:
    """Apply the forward schema change."""
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    """Reverse exactly what `upgrade` applied."""
    ${downgrades if downgrades else "pass"}
