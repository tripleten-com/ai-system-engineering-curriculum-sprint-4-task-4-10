"""Coldline.

===================

File:              src/api/ingest.py
Component:         Ingestion composition root
Purpose:           Run the supplied baseline corpus ingestion inside the API container.
Interacts With:    PostgreSQL, LocalStack S3, ObjectStore adapter, corpus loader
Sprint/Task:       Sprint 2 — Project 2
Concepts:          Composition root, deterministic ingestion, idempotency
Tools:             Python 3.12, PostgreSQL, pgvector, boto3
"""

import asyncio
import json

import asyncpg

from adapters.object_store import S3ObjectStore, create_s3_client
from adapters.persistence import CorpusLoader
from api.config import ApiSettings


async def ingest() -> None:
    """Ingest the supplied corpus and print a report a check can compare.

    The report is printed as one JSON object on the last line so that both a
    student and an automated check read the same values. Re-running this
    command is safe: ingestion upserts by deterministic identifier, so the
    counts and the digest do not change.
    """
    settings = ApiSettings()  # type: ignore[call-arg]  # values come from the protected environment
    pool = await asyncpg.create_pool(dsn=settings.database_url, min_size=1, max_size=2)
    if pool is None:  # pragma: no cover - asyncpg returns a pool or raises
        raise RuntimeError("could not create a PostgreSQL connection pool")
    store = S3ObjectStore(
        create_s3_client(
            endpoint_url=settings.s3_endpoint,
            region_name=settings.s3_region,
            access_key_id=settings.s3_access_key_id,
            secret_access_key=settings.s3_secret_access_key,
        ),
        bucket=settings.s3_bucket,
    )
    try:
        keys = await store.list_keys("corpus/")
        report = await CorpusLoader(pool, store).load()
    finally:
        await pool.close()
    print(f"Read {len(keys)} corpus object(s) through the ObjectStore port: {', '.join(keys)}")
    print(
        json.dumps(
            {
                "documents": report.documents,
                "chunks": report.chunks,
                "tenants": list(report.tenants),
                "access_tiers": list(report.access_tiers),
                "corpus_digest": report.corpus_digest,
                "object_keys": keys,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    asyncio.run(ingest())
