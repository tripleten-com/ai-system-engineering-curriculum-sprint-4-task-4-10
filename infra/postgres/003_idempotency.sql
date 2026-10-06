-- Coldline
-- File: infra/postgres/003_idempotency.sql
-- Component: Idempotency store initialization
-- Purpose: Create the durable idempotency claim table.
-- Interacts With: PostgreSQL initializer and the idempotency store adapter
-- Sprint/Task: Sprint 2 — Project 2 / Task 2.5
-- Concepts: Idempotent writes, claim ownership
-- Tools: PostgreSQL SQL

-- One row per (key, operation). The primary key is the key alone, so reusing a
-- key for a different operation is detectable rather than silently accepted:
-- the stored operation_id will not match and the store refuses the claim.
CREATE TABLE IF NOT EXISTS idempotency_claims (
    idempotency_key TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL,
    claimed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ,
    response_status INTEGER CHECK (response_status BETWEEN 100 AND 599),
    response_body TEXT,
    -- A completed claim must carry its whole response, and an in-flight claim
    -- must carry none of it. Enforcing that here means no code path can record
    -- a half-completed claim that a replay would then answer from.
    CONSTRAINT idempotency_completion_is_whole CHECK (
        (completed_at IS NULL AND response_status IS NULL AND response_body IS NULL)
        OR (completed_at IS NOT NULL AND response_status IS NOT NULL AND response_body IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS idempotency_claims_operation_idx
    ON idempotency_claims (operation_id, claimed_at);
