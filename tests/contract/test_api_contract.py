"""Coldline.

===================

File:              tests/contract/test_api_contract.py
Component:         Contract tests — Test Api Contract
Purpose:           HTTP contract tests for the Coldline API.
Interacts With:    Published interfaces and repository boundaries
Sprint/Task:       Sprint 4 — Project 4
Concepts:          Compatibility, ownership, export safety
Tools:             Python 3.12, pytest

From Task 4.2 the application is composed with a token verifier, and the one read of
the exception status resource here sends the ``dispatcher-valid`` fixture, so this
contract passes on the fresh starter (the route is open and the header is ignored) and
after the student protects the route. The verifier reads the committed key set file
directly, so these tests still need no container.
"""

from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from api.document_service import DocumentService
from api.retrieval_workflow import RetrievalWorkflow
from api.routes import create_app
from api.security.tokens import AuthSettings, TokenVerifier
from api.use_cases import ReadingApplication
from domain.contracts import (
    AccessLabel,
    AccessTier,
    AuthorizationContext,
    Candidate,
    ChunkRecord,
    DocumentRecord,
    ExceptionRecord,
    ExceptionState,
    RetrievalRequest,
    RetrievalResult,
    RetrievalStage,
    SensorReading,
    StageEvidence,
)
from domain.failures import ObjectStoreUnavailable
from domain.repositories import readable
from tests.security.fixtures import bearer_headers

ROOT = Path(__file__).resolve().parents[2]
COMMITTED_KEY_SET = ROOT / "infra/issuer/jwks.json"


def _verifier() -> TokenVerifier:
    """Return a verifier over the committed key set, so no issuer container is needed.

    The values are the development issuer's own, as its discovery document and the
    access policy publish them; the key set URL is a placeholder the fetcher never opens.
    """
    settings = AuthSettings(
        issuer="https://issuer.coldline.test",
        audience="coldline-api",
        jwks_url="http://issuer.invalid/.well-known/jwks.json",
        algorithms=["RS256"],
        leeway_seconds=30,
    )
    return TokenVerifier(settings, fetch=lambda url: COMMITTED_KEY_SET.read_bytes())


class MemoryRepository:
    """Persist records for HTTP contract tests."""

    def __init__(self) -> None:
        """Initialize empty test state."""
        self.records: dict[str, ExceptionRecord] = {}

    async def get(self, exception_id: str) -> ExceptionRecord | None:
        """Return a stored record."""
        return self.records.get(exception_id)

    async def create(self, record: ExceptionRecord) -> ExceptionRecord:
        """Create or return a record."""
        return self.records.setdefault(record.exception_id, record)

    async def transition(
        self,
        exception_id: str,
        expected: set[ExceptionState],
        target: ExceptionState,
        *,
        summary: str | None = None,
        failure_reason: str | None = None,
    ) -> ExceptionRecord:
        """Apply one test transition."""
        current = self.records[exception_id]
        assert current.state in expected
        updated = current.model_copy(
            update={
                "state": target,
                "summary": summary if summary is not None else current.summary,
                "failure_reason": failure_reason,
                "updated_at": NOW,
            }
        )
        self.records[exception_id] = updated
        return updated


class MemoryQueue:
    """Record published jobs for HTTP contract tests."""

    def __init__(self) -> None:
        """Initialize the publication counter."""
        self.count = 0

    async def publish(self, job: object) -> str:
        """Record one publication."""
        self.count += 1
        return "1-0"


class StubRetriever:
    """Return one fixed candidate so the HTTP contract can be checked offline."""

    def __init__(self) -> None:
        """Record the requests the route produced."""
        self.requests: list[RetrievalRequest] = []

    async def search_hybrid(self, request: RetrievalRequest) -> RetrievalResult:
        """Return a fixed single-candidate ranking with one stage entry."""
        self.requests.append(request)
        candidate = Candidate(
            chunk_id="sop-stub#0000",
            document_id="sop-stub",
            rank=1,
            score=0.5,
            text="stub chunk text for the HTTP contract",
            access=AccessLabel(tenant_id="tenant-stub", access_tier=AccessTier.STANDARD),
            provenance_revision="r1",
        )
        return RetrievalResult(
            query_id=request.query_id,
            results=(candidate,),
            stages=(StageEvidence(stage=RetrievalStage.FUSION, admitted=(candidate.chunk_id,)),),
            authorization_enforced=False,
        )


async def _stub_objects(prefix: str) -> list[str]:
    """Return two fixed object keys for the corpus listing contract."""
    return [f"{prefix}documents.jsonl", f"{prefix}provenance.jsonl"]


async def _failing_objects(prefix: str) -> list[str]:
    """Represent an unreachable object store."""
    raise ObjectStoreUnavailable("object store unreachable")


class MemoryDocumentRepository:
    """Hold documents in memory for the dependency-free HTTP contract tests.

    This double exists only to exercise the HTTP layer offline. It is not a
    model answer and it cannot satisfy Task 2.3: the assessed checks read real
    PostgreSQL rows through a separate connection, which no in-memory store can
    do. It does apply the published scope rule, so the route-level checks below
    are about status codes rather than about access control.
    """

    def __init__(self) -> None:
        """Initialize an empty store."""
        self.documents: dict[str, DocumentRecord] = {}
        self.chunks: dict[str, list[ChunkRecord]] = {}

    async def save_document(self, document: DocumentRecord, chunks: Sequence[ChunkRecord]) -> None:
        """Store one document and its chunks."""
        self.documents[document.document_id] = document
        self.chunks[document.document_id] = list(chunks)

    async def get_document(
        self, document_id: str, *, scope: AuthorizationContext
    ) -> DocumentRecord | None:
        """Return one document the scope may read."""
        stored = self.documents.get(document_id)
        if stored is None or not readable(
            scope, stored.access.tenant_id, stored.access.access_tier
        ):
            return None
        return stored

    async def list_documents(self, *, scope: AuthorizationContext) -> list[DocumentRecord]:
        """Return every document the scope may read."""
        return sorted(
            (
                stored
                for stored in self.documents.values()
                if readable(scope, stored.access.tenant_id, stored.access.access_tier)
            ),
            key=lambda stored: stored.document_id,
        )

    async def get_chunks(
        self, document_id: str, *, scope: AuthorizationContext
    ) -> list[ChunkRecord]:
        """Return the readable chunks of one document."""
        if await self.get_document(document_id, scope=scope) is None:
            return []
        return list(self.chunks.get(document_id, []))


class ExplodingRepository(MemoryRepository):
    """Raise one unexpected persistence error for the HTTP 500 signal test."""

    async def get(self, exception_id: str) -> ExceptionRecord | None:
        """Simulate an unhandled database driver failure."""
        raise RuntimeError("database connection reset")


NOW = datetime(2026, 8, 28, tzinfo=UTC)
PAYLOAD = {
    "reading_id": "reading-syn-001",
    "shipment_id": "shipment-syn-001",
    "temperature_c": 9.2,
    "allowed_min_c": 2.0,
    "allowed_max_c": 8.0,
    "recorded_at": "2026-08-28T00:00:00Z",
}


def _app(
    application: ReadingApplication,
    repository: MemoryRepository,
    **overrides: object,
) -> object:
    """Compose the HTTP layer with in-memory retrieval and object collaborators."""
    store = MemoryDocumentRepository()
    arguments: dict[str, object] = {
        "retrieval": RetrievalWorkflow(StubRetriever(), top_k=5, dense_weight=0.5, token_budget=64),
        "objects": _stub_objects,
        "documents": DocumentService(lambda: store),  # type: ignore[arg-type]
        "token_verifier": _verifier(),
    }
    arguments.update(overrides)
    return create_app(
        application,
        repository,
        arguments.pop("retrieval"),  # type: ignore[arg-type]
        arguments.pop("objects"),  # type: ignore[arg-type]
        arguments.pop("documents"),  # type: ignore[arg-type]
        **arguments,  # type: ignore[arg-type]
    )


@pytest.fixture
def components() -> tuple[object, MemoryRepository, MemoryQueue]:
    """Return an application wired to in-memory boundary implementations."""
    repository = MemoryRepository()
    queue = MemoryQueue()
    application = ReadingApplication(repository, queue, clock=lambda: NOW)
    return _app(application, repository), repository, queue


@pytest.mark.asyncio
async def test_post_reading_returns_accepted_status_contract(
    components: tuple[object, object, object],
) -> None:
    """An exception reading must return its stable polling location."""
    app, _, _ = components
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),  # type: ignore[arg-type]
        base_url="http://test",
    ) as client:
        response = await client.post("/api/v1/readings", json=PAYLOAD)

    assert response.status_code == 202
    assert response.json() == {
        "exception_id": "exc-e6a7451a-fe1a-53ca-b280-9bf67f555977",
        "state": "QUEUED",
        "status_url": "/api/v1/exceptions/exc-e6a7451a-fe1a-53ca-b280-9bf67f555977",
    }


@pytest.mark.asyncio
async def test_duplicate_post_does_not_publish_a_second_job(
    components: tuple[object, MemoryRepository, MemoryQueue],
) -> None:
    """HTTP replay must preserve the application idempotency contract."""
    app, _, queue = components
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),  # type: ignore[arg-type]
        base_url="http://test",
    ) as client:
        await client.post("/api/v1/readings", json=PAYLOAD)
        response = await client.post("/api/v1/readings", json=PAYLOAD)

    assert response.status_code == 202
    assert queue.count == 1


@pytest.mark.asyncio
async def test_failed_duplicate_returns_conflict(
    components: tuple[object, MemoryRepository, MemoryQueue],
) -> None:
    """A terminal failure must return 409 rather than an empty 202 promise."""
    app, repository, queue = components
    exception_id = "exc-e6a7451a-fe1a-53ca-b280-9bf67f555977"
    repository.records[exception_id] = ExceptionRecord(
        exception_id=exception_id,
        reading=SensorReading.model_validate(PAYLOAD),
        state=ExceptionState.FAILED,
        accepted_at=NOW,
        updated_at=NOW,
        failure_reason="job_queue_unavailable",
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),  # type: ignore[arg-type]
        base_url="http://test",
    ) as client:
        response = await client.post("/api/v1/readings", json=PAYLOAD)

    assert response.status_code == 409
    assert response.json()["detail"].endswith("terminal FAILED")
    assert queue.count == 0


@pytest.mark.asyncio
async def test_get_exception_returns_recorded_state(
    components: tuple[object, object, object],
) -> None:
    """The polling endpoint must return the durable exception record.

    Read with the dispatcher's token: ignored while the route is open, required once
    Task 4.2 protects it.
    """
    app, _, _ = components
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),  # type: ignore[arg-type]
        base_url="http://test",
    ) as client:
        accepted = await client.post("/api/v1/readings", json=PAYLOAD)
        response = await client.get(
            accepted.json()["status_url"], headers=bearer_headers("dispatcher-valid")
        )

    assert response.status_code == 200
    assert response.json()["state"] == "QUEUED"
    assert response.json()["summary"] is None


@pytest.mark.asyncio
async def test_in_range_reading_is_rejected_without_exception_work(
    components: tuple[object, MemoryRepository, MemoryQueue],
) -> None:
    """An in-range reading must not create or publish exception work."""
    app, repository, queue = components
    payload = {**PAYLOAD, "temperature_c": 5.0}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),  # type: ignore[arg-type]
        base_url="http://test",
    ) as client:
        response = await client.post("/api/v1/readings", json=payload)

    assert response.status_code == 422
    assert repository.records == {}
    assert queue.count == 0


@pytest.mark.asyncio
async def test_readiness_reports_dependency_failure() -> None:
    """Readiness must fail when the runtime dependencies are unavailable."""
    repository = MemoryRepository()
    application = ReadingApplication(repository, MemoryQueue(), clock=lambda: NOW)

    async def unavailable() -> bool:
        """Represent an unavailable dependency graph."""
        return False

    app = _app(application, repository, readiness=unavailable)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.get("/health/ready")

    assert response.status_code == 503
    assert response.json() == {"status": "not_ready"}


@pytest.mark.asyncio
async def test_metrics_endpoint_exposes_bounded_api_signal(
    components: tuple[object, object, object],
) -> None:
    """The API must expose its request signal without identifier labels."""
    app, _, _ = components
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),  # type: ignore[arg-type]
        base_url="http://test",
    ) as client:
        await client.get("/health/live")
        response = await client.get("/metrics")

    assert response.status_code == 200
    assert "coldline_api_requests_total" in response.text
    assert "exception_id=" not in response.text


@pytest.mark.asyncio
async def test_unhandled_server_error_is_counted_as_http_500() -> None:
    """A server failure must remain visible in the bounded API request metric."""
    repository = ExplodingRepository()
    application = ReadingApplication(repository, MemoryQueue(), clock=lambda: NOW)
    app = _app(application, repository)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),  # type: ignore[arg-type]
        base_url="http://test",
    ) as client:
        failed = await client.get(
            "/api/v1/exceptions/exc-failure", headers=bearer_headers("dispatcher-valid")
        )
        metrics = await client.get("/metrics")

    assert failed.status_code == 500
    assert 'route="/api/v1/exceptions/{exception_id}",status="500"' in metrics.text


@pytest.mark.asyncio
async def test_retrieval_search_returns_results_stages_and_context(
    components: tuple[object, object, object],
) -> None:
    """The retrieval route must return the ranking, the evidence, and the context."""
    app, _, _ = components
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),  # type: ignore[arg-type]
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/api/v1/retrieval/search",
            json={
                "query_id": "q-contract",
                "text": "stub query text",
                "authorization": {"tenant_id": "tenant-stub", "clearance": "standard"},
            },
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["query_id"] == "q-contract"
    assert [item["chunk_id"] for item in payload["results"]] == ["sop-stub#0000"]
    assert [item["stage"] for item in payload["stages"]] == ["fusion"]
    assert payload["authorization_enforced"] is False
    assert payload["citations"] == ["sop-stub@r1 (tenant-stub/standard)"]
    assert payload["used_tokens"] <= payload["token_budget"]


@pytest.mark.asyncio
async def test_retrieval_search_rejects_an_unknown_field(
    components: tuple[object, object, object],
) -> None:
    """The retrieval request contract is closed, so a stray field must fail."""
    app, _, _ = components
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),  # type: ignore[arg-type]
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/api/v1/retrieval/search",
            json={
                "query_id": "q-contract",
                "text": "stub query text",
                "authorization": {"tenant_id": "tenant-stub", "clearance": "standard"},
                "top_k": 20,
            },
        )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_corpus_objects_route_lists_keys_through_the_port(
    components: tuple[object, object, object],
) -> None:
    """Corpus artifacts must be listable without a caller touching a cloud SDK."""
    app, _, _ = components
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),  # type: ignore[arg-type]
        base_url="http://test",
    ) as client:
        response = await client.get("/api/v1/corpus/objects", params={"prefix": "corpus/"})

    assert response.status_code == 200
    assert response.json() == {
        "prefix": "corpus/",
        "keys": ["corpus/documents.jsonl", "corpus/provenance.jsonl"],
    }


@pytest.mark.asyncio
async def test_corpus_objects_route_reports_an_unavailable_object_store() -> None:
    """An object-store failure must surface as 503, not as an opaque 500."""
    repository = MemoryRepository()
    application = ReadingApplication(repository, MemoryQueue(), clock=lambda: NOW)
    app = _app(application, repository, objects=_failing_objects)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),  # type: ignore[arg-type]
        base_url="http://test",
    ) as client:
        response = await client.get("/api/v1/corpus/objects")

    assert response.status_code == 503


@pytest.mark.asyncio
async def test_retrieval_metric_label_stays_bounded(
    components: tuple[object, object, object],
) -> None:
    """The new routes must not add an unbounded metric dimension."""
    app, _, _ = components
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),  # type: ignore[arg-type]
        base_url="http://test",
    ) as client:
        await client.post(
            "/api/v1/retrieval/search",
            json={
                "query_id": "q-contract",
                "text": "stub query text",
                "authorization": {"tenant_id": "tenant-stub", "clearance": "standard"},
            },
        )
        metrics = await client.get("/metrics")

    assert 'route="/api/v1/retrieval/search"' in metrics.text
    assert "q-contract" not in metrics.text


DOCUMENT_PAYLOAD = {
    "document_id": "sop-contract-document",
    "title": "Contract procedure",
    "body": "One two three four five six seven eight nine ten eleven twelve.",
    "access": {"tenant_id": "tenant-contract", "access_tier": "standard"},
    "provenance": {
        "source_uri": "s3://coldline-corpus/source/sop-contract-document.md",
        "custodian": "Contract desk",
        "revision": "r1",
        "recorded_at": "2026-05-01T00:00:00Z",
    },
}


@pytest.mark.asyncio
async def test_document_write_and_scoped_read_round_trip(
    components: tuple[object, object, object],
) -> None:
    """The document routes must persist, read back, and scope by caller."""
    app, _, _ = components
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),  # type: ignore[arg-type]
        base_url="http://test",
    ) as client:
        created = await client.post("/api/v1/documents", json=DOCUMENT_PAYLOAD)
        assert created.status_code == 201, created.text
        assert len(created.json()["chunk_ids"]) >= 1

        fetched = await client.get(
            "/api/v1/documents/sop-contract-document",
            params={"tenant_id": "tenant-contract", "clearance": "standard"},
        )
        assert fetched.status_code == 200
        assert fetched.json()["provenance"]["custodian"] == "Contract desk"

        chunks = await client.get(
            "/api/v1/documents/sop-contract-document/chunks",
            params={"tenant_id": "tenant-contract", "clearance": "standard"},
        )
        assert chunks.status_code == 200
        assert chunks.json()["chunks"]


@pytest.mark.asyncio
async def test_out_of_scope_document_is_indistinguishable_from_absent(
    components: tuple[object, object, object],
) -> None:
    """A document another tenancy owns must answer 404, not 403."""
    app, _, _ = components
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),  # type: ignore[arg-type]
        base_url="http://test",
    ) as client:
        await client.post("/api/v1/documents", json=DOCUMENT_PAYLOAD)
        response = await client.get(
            "/api/v1/documents/sop-contract-document",
            params={"tenant_id": "tenant-other", "clearance": "restricted"},
        )
        listing = await client.get("/api/v1/documents", params={"tenant_id": "tenant-other"})

    assert response.status_code == 404
    assert listing.json()["documents"] == []


@pytest.mark.asyncio
async def test_document_routes_report_an_unwired_repository() -> None:
    """With no repository composed, the document surface must answer 503."""
    repository = MemoryRepository()
    application = ReadingApplication(repository, MemoryQueue(), clock=lambda: NOW)
    app = _app(application, repository, documents=DocumentService(lambda: None))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),  # type: ignore[arg-type]
        base_url="http://test",
    ) as client:
        created = await client.post("/api/v1/documents", json=DOCUMENT_PAYLOAD)
        fetched = await client.get(
            "/api/v1/documents/sop-contract-document", params={"tenant_id": "tenant-contract"}
        )

    assert created.status_code == 503
    assert "build_document_repository" in created.json()["detail"]
    assert fetched.status_code == 503


@pytest.mark.asyncio
async def test_document_metric_labels_stay_bounded(
    components: tuple[object, object, object],
) -> None:
    """Document identifiers must not become metric label values."""
    app, _, _ = components
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),  # type: ignore[arg-type]
        base_url="http://test",
    ) as client:
        await client.post("/api/v1/documents", json=DOCUMENT_PAYLOAD)
        await client.get(
            "/api/v1/documents/sop-contract-document/chunks",
            params={"tenant_id": "tenant-contract"},
        )
        metrics = await client.get("/metrics")

    assert 'route="/api/v1/documents"' in metrics.text
    assert 'route="/api/v1/documents/{document_id}/chunks"' in metrics.text
    assert "sop-contract-document" not in metrics.text
