-- Coldline
-- File: infra/postgres/001_opening_checkpoint.sql
-- Component: Database initialization
-- Purpose: Create the durable exception table and state constraints.
-- Interacts With: PostgreSQL initializer and domain state contract
-- Sprint/Task: Sprint 4 — Project 4 / Task 4.3
-- Concepts: Idempotent schema setup
-- Tools: PostgreSQL SQL

-- Task 4.3 adds NEEDS_REVIEW to the states. The columns that state stores beside the
-- summary (handling_class, next_step, rejection_reason) come from the migration
-- b3d7e9f1c2a4, which the initializer applies after this file on every start.
CREATE TABLE IF NOT EXISTS exceptions (
    exception_id TEXT PRIMARY KEY,
    reading JSONB NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('RECEIVED', 'QUEUED', 'PROCESSING', 'COMPLETED', 'FAILED', 'NEEDS_REVIEW')),
    accepted_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    summary TEXT,
    failure_reason TEXT
);

CREATE INDEX IF NOT EXISTS exceptions_state_idx ON exceptions (state);
