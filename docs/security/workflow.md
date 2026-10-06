<!--
Coldline - Task 4.1
Supplied material: one exception-resolution request as numbered elements and data flows.
Not student-editable. Read it with the trace `poe scenario` prints and with
docs/security/threat-catalog.yaml, docs/security/scoring.md and docs/security/control-matrix.md.
-->
# The exception-resolution workflow

This page describes one request through the stack: a sensor reading that leaves its handling
range arrives at the API, the worker resolves it into a summary, and a dispatcher reads that
summary. The trace `poe scenario` prints covers everything between the gateway's request and
the stored summary; the dispatcher's read is a separate request to the same API.

Every element and every flow has a stable id. The answer sheet refers to flows by their id, and
the threat catalog refers to elements and flows by theirs. Do not add elements or flows: if the
request does something this page leaves out, record it in the last section of your threat
model.

## Trust

Each element belongs to one of two trust groups.

- **Inside**: Coldline's own processes, and the stores that only those processes write. The
  platform team controls the code, the configuration, and the data in them.
- **Outside**: every party Coldline does not control, and every store whose content such a
  party writes. What arrives from an outside element is whatever its writer put there.

A flow crosses a trust boundary when its two elements are in different groups, whichever
direction the data moves. Data leaving the inside group is exposed to the outside element
that receives it; data arriving from the outside group carries whatever its writers wrote,
instructions included.

## Elements

| Id | Element | In this request | Controlled by | Who can write its data | Group | Code to read |
|---|---|---|---|---|---|---|
| E1 | Sensor gateway | Sends a reading, and the handling note the shipping staff typed, as `POST /api/v1/readings`. | The laboratory's device vendor and the laboratory's shipping staff. | The gateway and the staff typing into it. | Outside | None in this repository; the body is `SensorReading` in `src/domain/contracts.py`. |
| E2 | Dispatcher client | Polls `GET /api/v1/exceptions/{exception_id}` and reads the summary. | TripleTen Medical's dispatch team, on their own workstations. | The dispatcher: the exception id in the path, nothing else. | Outside | None in this repository. |
| E3 | API | Validates the reading's shape, stores the record, publishes the job, and later serves the status read. Also serves procedure search and document writes. | Coldline platform engineers. | The API's own code, from what its callers send. | Inside | `src/api/routes.py`, `src/api/use_cases.py` |
| E4 | Queue | LocalStack SQS `coldline-exception-jobs`, with its dead-letter queue. Carries the job from the API to the worker. | Coldline. Reachable only inside the Compose network, plus the host's own loopback for diagnostics. | The API only. | Inside | `src/adapters/queue/sqs.py` |
| E5 | Worker | Takes the job, logs it, retrieves the matching procedure, builds the model request, parses the answer, and stores the summary. | Coldline platform engineers. Its settings, including the provider key, are literals in `src/worker/config.py`, committed to this repository and built into the image. | The worker's own code: the log line, the model request, the stored summary and state changes. | Inside | `src/worker/use_cases.py`, `src/worker/procedures.py`, `src/worker/config.py`, `src/worker/bootstrap.py` |
| E6 | Retriever | The supplied hybrid retrieval adapter, run inside the worker process with one fixed service scope: the procedure tenancy, every tier. | Coldline. | Nothing; it reads. | Inside | `src/adapters/retriever/postgres_hybrid.py`, `src/worker/procedures.py` |
| E7 | Model provider | Answers the model request with raw text. | The provider. Here it is the deterministic emulator standing in for a hosted service. | The provider: the answer text, which becomes the summary. | Outside | `src/adapters/model/deterministic.py`, `src/adapters/model/resilient.py` |
| E8 | Exception records | PostgreSQL table `exceptions`: the reading with its note, the states, the summary. | Coldline. | The API and the worker only. | Inside | `src/adapters/persistence/postgres.py`, `infra/postgres/001_opening_checkpoint.sql`, `migrations/versions/` |
| E9 | Corpus store | PostgreSQL tables `documents` and `chunks`: the handling procedures the retriever searches. | Coldline runs it. | Corpus editors: the procedure authors who publish through `POST /api/v1/documents`, which records whatever custodian name they type, and the start-up load from the corpus bucket. | Outside | `src/api/routes.py` (`create_document`), `src/adapters/persistence/document_repository.py`, `src/api/ingest.py` |
| E10 | Corpus bucket | LocalStack S3 bucket `coldline-corpus`: the supplied corpus files the initializer loads into the corpus store. | Coldline runs it. | Corpus editors, through the supplied files; the initializer uploads them. | Outside | `src/api/initialize.py`, `src/adapters/object_store/s3.py` |

E10 is not on the request path. It is where the corpus store's content comes from, and it has
no span in the trace.

The repository, its continuous-integration logs, and the built API and worker images are not
elements either; they are where the code and configuration of E3 and E5 come from. Only
Coldline operators can open or merge a pull request against the repository, dependency
changes included. The readers `docs/security/scoring.md` names (anyone with read access to the
repository, a CI log, or a built image) have read-only access: they can read what is
committed and built, and cannot open, change, or merge a pull request.

The ports `compose.yaml` publishes are not a way into the stack for anyone this page does
not name. Every port it publishes binds the host's loopback interface, `127.0.0.1`: the API
(8000), LocalStack's S3 and SQS edge (4566), Jaeger, Prometheus, Alertmanager, and Grafana.
PostgreSQL, Redis, the worker's metrics port, and the OTLP endpoint publish no host port at
all and are reachable only inside the Compose network. A loopback-bound port can be reached
only by a process running on the development host itself, and only Coldline operators run
processes there. A published port therefore adds no party to the ones this page names: it
is how an operator's own tooling (`poe scenario`, `poe ingest`, a diagnostic client against
the queue or the bucket) stands in for the gateway and the dispatcher, or inspects a store,
from the host. The queue's SQS endpoint on the host loopback is such a diagnostic port; the
API remains the queue's only writer. A service bound to every interface (`0.0.0.0`) would be
different: anyone on the host's network could reach it, and they would be a party of their
own. No service in `compose.yaml` is published that way.

## Where each element appears in the trace

The API starts the trace when the gateway's request arrives, the queue message carries the
trace context, and the worker continues it. One request is therefore one trace, and the
`api_trace_id` and `worker_trace_id` that `poe scenario` prints are the same id.

| Element | Service in Jaeger | Span operation names |
|---|---|---|
| E1 | none | The request appears as the API's `POST /api/v1/readings` server span. |
| E2 | none | The read appears as the API's `GET /api/v1/exceptions/{exception_id}` server span, in its own trace. |
| E3 | `coldline-api` | `POST /api/v1/readings`, `GET /api/v1/exceptions/{exception_id}`, and the spans below that run inside them. |
| E4 | `coldline-api` | `job_queue.publish`. The worker's receive has no span of its own. |
| E5 | `coldline-worker` | `coldline.process_exception`, and the spans below that run inside it. |
| E6 | `coldline-worker` | `retriever.search_hybrid` |
| E7 | `coldline-worker` | `model_provider.summarize` |
| E8 | `coldline-api`, `coldline-worker` | `postgres.exceptions.create`, `postgres.exceptions.transition`, `postgres.exceptions.get` |
| E9 | `coldline-worker` | The reads happen inside `retriever.search_hybrid`; there is no span of their own. |

## Data flows

| Id | From | To | What flows | Where in the code |
|---|---|---|---|---|
| DF-01 | E1 | E3 | The reading: shipment id, temperatures, the handling note as typed. | `accept_reading` in `src/api/routes.py` |
| DF-02 | E3 | E8 | The exception record, created as `RECEIVED` and moved to `QUEUED`, holding the reading and the raw note. | `ReadingApplication.accept` in `src/api/use_cases.py`; `create` and `transition` in `src/adapters/persistence/postgres.py` |
| DF-03 | E3 | E4 | The queued job: the exception id, the reading with its note, and the trace context. | `SqsJobQueue.publish` in `src/adapters/queue/sqs.py` |
| DF-04 | E4 | E5 | The delivered job, with its delivery count. | `SqsJobQueue.read` in `src/adapters/queue/sqs.py`; `run_loop` in `src/worker/runtime.py` |
| DF-05 | E5 | E6 | The retrieval request: a question built from the reading's shape, under the worker's fixed scope. | `ProcedureLookup.find` and `query_for` in `src/worker/procedures.py` |
| DF-06 | E9 | E6 | The matching procedure chunks, as corpus editors wrote them. | `PostgresHybridRetriever.search_hybrid` in `src/adapters/retriever/postgres_hybrid.py` |
| DF-07 | E6 | E5 | The ranked chunks; the worker keeps the best one as a bounded excerpt. | `excerpt_from` in `src/worker/procedures.py` |
| DF-08 | E5 | E7 | The model request: the reading, the handling note as typed, and the procedure excerpt. | `WorkerApplication.process` in `src/worker/use_cases.py`; `ModelRequest` in `src/domain/contracts.py` |
| DF-09 | E7 | E5 | The provider's raw answer text. | `DeterministicModelProvider.summarize` in `src/adapters/model/deterministic.py`; `parse_summary` in `src/worker/use_cases.py` |
| DF-10 | E5 | E8 | The `PROCESSING` and `COMPLETED` transitions, the latter with the summary parsed from the answer. | `WorkerApplication.process`; `transition` in `src/adapters/persistence/postgres.py` |
| DF-11 | E2 | E3 | The status request for one exception id. | `get_exception` in `src/api/routes.py` |
| DF-12 | E8 | E3 | The stored record. | `get` in `src/adapters/persistence/postgres.py` |
| DF-13 | E3 | E2 | The status response: the state, the reading with its note, and the summary. | `get_exception` in `src/api/routes.py`; `ExceptionRecord` in `src/domain/contracts.py` |

The worker also writes one log line as it takes the job (`WorkerApplication.process`), which
goes to the container's output. It is not a flow between two elements, which is why it has
no id; the catalog names it where it matters.
