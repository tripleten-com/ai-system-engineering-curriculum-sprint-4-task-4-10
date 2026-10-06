"""Coldline.

===================

File:              src/api/bootstrap.py
Component:         API — Bootstrap
Purpose:           Compose and run the Coldline API service.
Interacts With:    FastAPI, domain, ports, adapters, the audit sink
Sprint/Task:       Sprint 4 — Project 4
Concepts:          HTTP boundary, composition, asynchronous work, dead-letter redrive, tokens,
                    audit
Tools:             Python 3.12, FastAPI, PostgreSQL, pgvector, boto3, OpenTelemetry, PyJWT
"""

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

import asyncpg
from fastapi import FastAPI
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

from adapters.logging import configure_json_logging
from adapters.object_store import S3ObjectStore, create_s3_client
from adapters.persistence import (
    PostgresAuditStore,
    PostgresExceptionRepository,
    PostgresIdempotencyStore,
)
from adapters.queue import SqsJobQueue, create_sqs_client
from adapters.retriever import PostgresHybridRetriever
from adapters.telemetry import configure_tracing
from api.config import load_api_settings
from api.document_service import DocumentService
from api.experiment import ExperimentRetrieval
from api.extensions import wiring
from api.retrieval_workflow import CITATION_LIMIT, RetrievalWorkflow
from api.routes import create_app
from api.runtime import RuntimeBindings
from api.security.tokens import TokenVerifier
from api.use_cases import ReadingApplication
from common.audit import AuditSink

# Task 4.2's token verification settings, settled. The image carries this file and
# src/api/routes.py as they were when `poe start` built it, so an edit to the route module
# needs `poe start` again, not `poe restart`.
AUTH_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config/auth.yaml"

settings = load_api_settings()
configure_json_logging(settings.service_name)
tracer_provider = configure_tracing(settings.service_name, settings.otel_endpoint)
bindings = RuntimeBindings()
application = ReadingApplication(bindings, bindings, clock=lambda: datetime.now(UTC))

# The verifier every `require_access` rule uses. Composed here, from config/auth.yaml
# and the in-network key-set origin Compose supplies, so a route never reads
# configuration itself. The key set is fetched on first use, not at startup.
token_verifier = TokenVerifier.from_config(
    AUTH_CONFIG_PATH, jwks_origin=settings.issuer_jwks_origin
)

# The composed access policy comes from the student wiring factory. Composing it
# here, rather than defaulting it inside the adapter, is what makes the change
# of enforcement a visible one-line composition change.
access_constraints = wiring.build_access_constraints()

# The two service factories are the student-editable seam. Each returns None
# until an implementation is wired, and the workflow keeps its coupled code for
# whichever half is still None. Composing them here, rather than inside the
# workflow, is what makes a substitution observable from outside.
retrieval = RetrievalWorkflow(
    bindings,
    top_k=settings.retrieval_top_k,
    dense_weight=settings.retrieval_dense_weight,
    token_budget=settings.retrieval_token_budget,
    retrieval_orchestrator=wiring.build_retrieval_orchestrator(
        bindings,
        top_k=settings.retrieval_top_k,
        dense_weight=settings.retrieval_dense_weight,
        citation_limit=CITATION_LIMIT,
    ),
)
documents = DocumentService(bindings.documents)
# The evaluation surface measures the same retrieval port the product
# endpoint uses, with the parameters stated per request instead of composed.
experiment = ExperimentRetrieval(bindings)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Own API dependency startup and shutdown.

    PostgreSQL and the object-storage and queue clients are created once per
    process. The ``finally`` block closes the pool and flushes tracing even
    when startup work or a request fails.
    """
    bindings.mark_serving(settings.ready_delay_seconds)
    bindings.pool = await asyncpg.create_pool(dsn=settings.database_url, min_size=1, max_size=4)
    bindings.repository = PostgresExceptionRepository(bindings.pool)
    # Task 4.3: the audit sink the summary-read event goes through, over the same
    # PostgreSQL audit table the worker writes its events to.
    bindings.audit = AuditSink(PostgresAuditStore(bindings.pool))
    sqs_client = create_sqs_client(
        endpoint_url=settings.s3_endpoint,
        region_name=settings.s3_region,
        access_key_id=settings.s3_access_key_id,
        secret_access_key=settings.s3_secret_access_key,
    )
    queue_url = await asyncio.to_thread(
        lambda: sqs_client.get_queue_url(QueueName=settings.queue_name)["QueueUrl"]
    )
    bindings.queue = SqsJobQueue(sqs_client, queue_url=queue_url)
    bindings.object_store = S3ObjectStore(
        create_s3_client(
            endpoint_url=settings.s3_endpoint,
            region_name=settings.s3_region,
            access_key_id=settings.s3_access_key_id,
            secret_access_key=settings.s3_secret_access_key,
        ),
        bucket=settings.s3_bucket,
    )
    bindings.retriever = PostgresHybridRetriever(
        bindings.pool,
        access_constraints=access_constraints,
    )
    # The student factory decides whether the document API is available. It is
    # given the one process pool rather than being allowed to make its own.
    bindings.document_repository = wiring.build_document_repository(bindings.pool)
    bindings.idempotency_store = PostgresIdempotencyStore(bindings.pool)
    try:
        yield
    finally:
        await bindings.pool.close()
        tracer_provider.shutdown()


# The version 2 router is composed from the student wiring factory. FastAPI
# needs the application object before the lifespan runs, so the idempotency
# store and the audit sink are forwarding bindings rather than clients created here.
app = create_app(
    application,
    bindings,
    retrieval,
    bindings.list_corpus_keys,
    documents,
    experiment=experiment,
    version_two=wiring.build_v2_router(
        documents=documents,
        readings=application,
        store=bindings,
    ),
    readiness=bindings.ready,
    build_version=settings.build_version,
    lifespan=lifespan,
    token_verifier=token_verifier,
    audit=bindings,
)
FastAPIInstrumentor.instrument_app(app)
