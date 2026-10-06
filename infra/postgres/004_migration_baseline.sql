-- Coldline
-- File: infra/postgres/004_migration_baseline.sql
-- Component: Migration baseline
-- Purpose: Stamp the initialized schema as the Alembic baseline revision.
-- Interacts With: PostgreSQL initializer and the Alembic environment
-- Sprint/Task: Sprint 2 — Project 2 / Task 2.6
-- Concepts: Version-controlled schema evolution, idempotent provisioning
-- Tools: PostgreSQL SQL, Alembic

-- The tables in 001-003 are created by the initializer rather than by a
-- migration, so Alembic needs a starting point. This stamps that starting
-- point once and never again: the insert is conditional on the table being
-- empty, so a database already advanced past the baseline keeps its own
-- revision instead of being silently rewound by the next start.
CREATE TABLE IF NOT EXISTS alembic_version (
    version_num VARCHAR(32) NOT NULL,
    CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
);

INSERT INTO alembic_version (version_num)
SELECT '0001baseline'
WHERE NOT EXISTS (SELECT 1 FROM alembic_version);
