"""Coldline.

===================

File:              src/api/initialize.py
Component:         Initialization composition root
Purpose:           Provision the database schema, queue, dead-letter queue, bucket, corpus, and,
                    from Task 4.5, the provider key's secret in the local secret store.
Interacts With:    PostgreSQL, LocalStack S3/SQS/Secrets Manager, and the JobQueue, ObjectStore
                    and SecretProvider adapters
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          Idempotent provisioning, composition root, deterministic fixtures, redrive,
                    a secret created once and replaced by its owner
Tools:             Python 3.12, PostgreSQL, pgvector, boto3
"""

import asyncio
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import asyncpg
from alembic import command
from alembic.config import Config

from adapters.object_store import S3ObjectStore, create_s3_client
from adapters.persistence.corpus_loader import CORPUS_PREFIX
from adapters.queue import create_sqs_client, ensure_queue_when_ready
from adapters.secrets import (
    FIRST_VERSION_VALUE,
    PROVIDER_KEY_SECRET_NAME,
    LocalStackSecretProvider,
    create_secrets_client,
    ensure_secret_when_ready,
)
from api.config import ApiSettings
from domain.failures import ObjectStoreUnavailable

SCHEMA_FILES = (
    "infra/postgres/001_opening_checkpoint.sql",
    "infra/postgres/002_retrieval_corpus.sql",
    "infra/postgres/003_idempotency.sql",
    # Creates the Alembic version table and stamps the initialized schema
    # as the baseline revision, so a migration has a root to chain from.
    "infra/postgres/004_migration_baseline.sql",
)
ALEMBIC_CONFIG = "alembic.ini"
CORPUS_FILES = ("documents.jsonl", "provenance.jsonl")
LOCALSTACK_ATTEMPTS = 30
LOCALSTACK_DELAY_SECONDS = 2.0
POSTGRES_CONNECT_BUDGET_SECONDS = 30.0
POSTGRES_FIRST_RETRY_DELAY_SECONDS = 0.5
POSTGRES_MAX_RETRY_DELAY_SECONDS = 4.0
POSTGRES_ATTEMPT_TIMEOUT_SECONDS = 5.0
# "Not accepting connections yet", as opposed to "misconfigured": a refused, reset, or
# timed-out TCP connect (OSError, which includes TimeoutError), a server that answers but
# is still starting up (SQLSTATE 57P03), or a first-boot server closing mid-handshake.
_POSTGRES_NOT_READY = (
    OSError,
    asyncpg.CannotConnectNowError,
    asyncpg.ConnectionDoesNotExistError,
)


async def initialize() -> None:
    """Wire infrastructure clients and apply idempotent initialization.

    This one-shot process is a composition root. It may construct provider
    clients, but it delegates queue, object-store and secret-store behavior to
    the supplied adapters. Every step is idempotent, so a repeated start, a
    restart, or a Codespaces resume converges on the same state instead of failing.

    Provisioning stops at *resources and artifacts*. Ingesting the corpus into
    PostgreSQL is a separate, student-visible step (`poe ingest`), because
    Task 2.1 asks a student to run and inspect ingestion rather than find it
    already done.
    """
    settings = ApiSettings()  # type: ignore[call-arg]  # values come from the protected environment
    connection = await _connect_when_ready(settings.database_url)
    try:
        for schema_file in SCHEMA_FILES:
            await connection.execute(Path(schema_file).read_text(encoding="utf-8"))
        await _provision_queue(settings)
        await _provision_corpus_objects(settings)
        await _provision_provider_secret(settings)
    finally:
        await connection.close()


async def _connect_when_ready(
    dsn: str,
    *,
    budget_seconds: float = POSTGRES_CONNECT_BUDGET_SECONDS,
    connect: Callable[..., Awaitable[Any]] = asyncpg.connect,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> Any:
    """Connect to PostgreSQL, retrying with backoff while it is still starting.

    Compose starts this initializer once PostgreSQL's healthcheck passes, but a
    first boot runs its setup on a temporary server and then restarts, so a
    connection can still be refused for a moment. The wait is bounded: a
    database that never answers fails the initializer with the reason instead
    of leaving the stack half-provisioned. A configuration error, such as a
    wrong password, is not a readiness failure and surfaces at once.
    """
    deadline = clock() + budget_seconds
    delay = POSTGRES_FIRST_RETRY_DELAY_SECONDS
    attempts = 0
    while True:
        attempts += 1
        remaining = deadline - clock()
        try:
            return await connect(
                dsn=dsn,
                timeout=max(0.1, min(POSTGRES_ATTEMPT_TIMEOUT_SECONDS, remaining)),
            )
        except _POSTGRES_NOT_READY as exc:
            remaining = deadline - clock()
            if remaining <= 0:
                raise RuntimeError(
                    f"PostgreSQL did not accept connections within {budget_seconds:.0f} s "
                    f"({attempts} attempts, last error: {exc!r}); check the postgres "
                    "service with `docker compose logs postgres`"
                ) from exc
            await sleep(min(delay, remaining))
            delay = min(delay * 2, POSTGRES_MAX_RETRY_DELAY_SECONDS)


def apply_migrations() -> None:
    """Bring the schema to the committed head revision.

    The tables in `infra/postgres/` are created by the SQL in ``initialize``
    and stamped at the baseline revision. Everything after that baseline is a
    migration, and from Task 2.6 there is one committed. Applying it here means
    the service never serves traffic against a schema older than the code in
    this repository, which is the ordering a deployment has to guarantee too.

    Alembic is idempotent about this: a database already at head does nothing.

    This step is synchronous and runs outside ``initialize``. The migration
    environment opens and closes its own event loop, and an event loop cannot
    be started from inside one that is already running.
    """
    command.upgrade(Config(ALEMBIC_CONFIG), "head")


async def _provision_queue(settings: ApiSettings) -> None:
    """Create the main queue and its dead-letter queue, bound by a redrive policy.

    Task 3.3 replaces Redis Streams as the ``JobQueue`` transport; Redis stays
    available only for its separate cache role and is no longer provisioned
    here. The bounded visibility timeout and receive-count settings below are
    supplied and protected: they take effect the moment this initializer runs,
    before either service's own wiring is touched.
    """
    client = create_sqs_client(
        endpoint_url=settings.s3_endpoint,
        region_name=settings.s3_region,
        access_key_id=settings.s3_access_key_id,
        secret_access_key=settings.s3_secret_access_key,
    )
    await ensure_queue_when_ready(
        client,
        queue_name=settings.queue_name,
        dead_letter_name=settings.dead_letter_queue_name,
        visibility_timeout_seconds=settings.queue_visibility_timeout_seconds,
        max_receive_count=settings.queue_max_receive_count,
        endpoint=settings.s3_endpoint,
        attempts=LOCALSTACK_ATTEMPTS,
        delay_seconds=LOCALSTACK_DELAY_SECONDS,
    )


async def _provision_corpus_objects(settings: ApiSettings) -> None:
    """Create the corpus bucket and upload the supplied source artifacts.

    The artifacts ship in the repository and are uploaded here so that every
    later read goes through the ``ObjectStore`` port against S3 rather than
    reading the container filesystem. That is what makes the Task 2.1
    object-storage boundary observable instead of assumed.
    """
    store = S3ObjectStore(
        create_s3_client(
            endpoint_url=settings.s3_endpoint,
            region_name=settings.s3_region,
            access_key_id=settings.s3_access_key_id,
            secret_access_key=settings.s3_secret_access_key,
        ),
        bucket=settings.s3_bucket,
    )
    await _await_object_store(store, settings.s3_endpoint)
    for name in CORPUS_FILES:
        payload = (Path("infra/corpus") / name).read_bytes()
        await store.write(f"{CORPUS_PREFIX}{name}", payload)


async def _provision_provider_secret(settings: ApiSettings) -> None:
    """Create the provider key's secret in the local secret store, once.

    Task 4.5: Secrets Manager holds the model provider key under the name
    ``docs/fidelity/SecretProvider.md`` states. The first version is the value the
    opening checkpoint carried as a configuration literal, which Step 2 of the Task
    replaces; a secret that already exists is left as it is, so a restart never undoes
    a replacement. The initializer never prints the value.
    """
    store = LocalStackSecretProvider(
        create_secrets_client(
            endpoint_url=settings.s3_endpoint,
            region_name=settings.s3_region,
            access_key_id=settings.s3_access_key_id,
            secret_access_key=settings.s3_secret_access_key,
        )
    )
    await ensure_secret_when_ready(
        store,
        name=PROVIDER_KEY_SECRET_NAME,
        first_value=FIRST_VERSION_VALUE,
        endpoint=settings.s3_endpoint,
        attempts=LOCALSTACK_ATTEMPTS,
        delay_seconds=LOCALSTACK_DELAY_SECONDS,
    )


async def _await_object_store(store: S3ObjectStore, endpoint: str) -> None:
    """Provision the bucket once object storage answers, or fail with the reason.

    Provisioning is idempotent and retried because the object-storage container
    may still be starting. The wait is bounded: an endpoint that never answers
    fails the initializer instead of leaving the stack half-provisioned, and the
    message names the Compose profile that supplies it.
    """
    last_error: Exception | None = None
    for attempt in range(LOCALSTACK_ATTEMPTS):
        try:
            await store.ensure_bucket()
            return
        except ObjectStoreUnavailable as exc:
            last_error = exc
            if attempt + 1 < LOCALSTACK_ATTEMPTS:
                await asyncio.sleep(LOCALSTACK_DELAY_SECONDS)
    raise ObjectStoreUnavailable(
        f"object storage at {endpoint} did not answer after "
        f"{LOCALSTACK_ATTEMPTS} attempts; start the stack with the localstack "
        "Compose profile enabled (`poe start`)"
    ) from last_error


def main() -> None:
    """Provision resources and artifacts, then bring the schema to head."""
    asyncio.run(initialize())
    apply_migrations()


if __name__ == "__main__":
    main()
