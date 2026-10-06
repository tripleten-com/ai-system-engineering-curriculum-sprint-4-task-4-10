# Local runtime qualification evidence

This record captures authoring runs of the Sprint 2 platform. It supports local sizing decisions.
It does not qualify GitHub Codespaces or a student release.

## Measured run — Sprint 2, 2026-09-07

Host: Windows with Docker Desktop, Docker Engine 29.5.3, Compose v5.1.4, 15.54 GiB available to
the Docker VM. Compose project `coldline-task-2-1`. Published host ports were the documented
defaults: API `8000`, Grafana `3000`, Prometheus `9090`, Jaeger `16686`, LocalStack `4566`.

| Measurement | Result |
|---|---:|
| First `poe start`, building API and worker images | 166 s |
| `poe start` from a clean `poe reset` with cached images | 32 s |
| `poe ready` after that start | 16 s |
| `poe ingest` (53 chunks from 18 documents) | 5 s |
| `poe restart` through `poe ready` | 18 s |
| API image | 238,597,279 bytes |
| Worker image | 233,172,295 bytes |
| Post-readiness memory sample, eight long-running containers | about 604 MiB |

Per-container post-readiness memory sample:

| Container | Sample |
|---|---:|
| Grafana | 190.9 MiB |
| LocalStack | 141.0 MiB |
| API | 81.7 MiB |
| Worker | 49.7 MiB |
| Jaeger | 47.4 MiB |
| PostgreSQL (pgvector) | 44.3 MiB |
| Prometheus | 37.7 MiB |
| Redis | 11.3 MiB |

The initializer completed once with exit code `0`. The runtime used eight long-running containers
— API, worker, PostgreSQL with pgvector, Redis, LocalStack, Jaeger, Prometheus, and Grafana — plus
the one-shot initializer. That is one more long-running container than Sprint 1, which is the
LocalStack S3 emulator this Sprint introduces.

## Measured run — Task 3.1 release tooling, 2026-09-17

Host: Windows with Docker Desktop, Compose project `coldline-task-3-1`, no user traffic during the
rollouts. The candidate release warms up for 20 s by design.

| Measurement | Result |
|---|---:|
| `poe roll-forward` to the candidate behind the supplied health check, until `up --wait` returned | 13.2 s |
| `poe roll-forward` to the candidate behind a health check that waits for readiness, until `up --wait` returned | 33.0 s |
| `poe roll-back` to the known-good release, until `up --wait` returned | 11.4 s |

The difference between the two rollouts is the candidate's 20 s warm-up becoming visible to the
gate; the candidate image did not change. Which endpoint the repaired check probes, how long it
tolerates the warm-up, what each first probe returned, and which limits were applied are the
student's Step 2 and Step 3 results and the evidence pack's records; they are deliberately not
repeated here.

A rollout recreates the single `api` container; these timings say nothing about requests during
the swap. The Sprint 2 memory samples above remain the sizing basis for the limits.

## Boundary of this evidence

- The numbers above are single observations from one host, not averages, percentiles, or peaks.
  Memory is one post-readiness sample.
- The image build reused locally cached base layers; it did not prove a cold network pull.
- Storage and build-cache peaks are not recorded.
- No macOS or Linux run contributed to these timings or image sizes. The bootstrap resolves macOS
  arm64/x86-64 and Linux x86-64/aarch64, and Apple Silicon builds the same multi-architecture
  images for `linux/arm64`, but neither platform is covered by this evidence.
- The run is not a fresh real Codespace, a CMS-generated repository, or an independent student
  pilot. The Codespaces `hostRequirements` in `.devcontainer/devcontainer.json` still need the
  separate real-Codespaces qualification gate.
- Retrieval latency is deliberately absent from this record. A latency figure belongs to the
  Task 2.7 measurement harness with its own units, warmup rules, and tolerances, not to a
  startup-timing record.

## Retained Sprint 1 evidence

The Sprint 1 authoring run of 2026-08-29 measured a seven-container stack without LocalStack: a
no-cache build of 15.8 s, a cold start through health checks of 13.1 s, a restart through
readiness of 13.6 s, a complete history-free walkthrough of 132.8 s, an API image of 186,872,784
bytes, a worker image of 181,513,613 bytes, and a post-readiness sample of about 404 MiB. Those
figures describe the Sprint 1 topology and are retained as history; they are not a current
measurement of this Task.

These limits prevent local speed or resource results from becoming a production, availability, or
student-workload claim.
