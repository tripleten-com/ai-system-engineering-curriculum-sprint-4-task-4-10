"""Coldline.

===================

File:              src/worker/health.py
Component:         Worker — Health
Purpose:           Probe worker dependencies for the Compose health contract.
Interacts With:    Redis Streams, domain, ports, and adapters
Sprint/Task:       Sprint 1 — Project 1
Concepts:          Background processing, retries, idempotency
Tools:             Python 3.12, PostgreSQL, Redis
"""

import asyncio

import asyncpg
from redis.asyncio import Redis

from worker.config import WorkerSettings


async def check() -> None:
    """Exit successfully only when PostgreSQL and Redis answer."""
    settings = WorkerSettings()  # type: ignore[call-arg]  # protected environment is the source
    pool = await asyncpg.create_pool(dsn=settings.database_url, min_size=1, max_size=1)
    redis = Redis.from_url(settings.redis_url)
    try:
        if await pool.fetchval("SELECT 1") != 1 or not await redis.ping():
            raise RuntimeError("worker dependency probe failed")
    finally:
        await redis.aclose()
        await pool.close()


if __name__ == "__main__":
    asyncio.run(check())
