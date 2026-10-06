# Coldline Task 4.10 — Optional Task 10: Infrastructure as code against LocalStack

This checkpoint is the finished Project 4 system, the verified Task 7 checkpoint. Its storage
bucket, its job queue, the queue's dead-letter queue and the secret that holds the model
provider key exist because the stack's startup code creates them when it starts. This Task
describes the same resources as code that can be planned, reviewed, applied and destroyed:
you declare your own copy of them in OpenTofu against LocalStack, compare your copy with what
the startup code created, run a Trivy configuration scan and triage one of its findings,
destroy and rebuild the copy, and record what the local run can't establish about a real AWS
account, with your recommendation. This Task is optional and gates no other Task.

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/tripleten-com/ai-system-engineering-curriculum-sprint-4-task-4-10/tree/main)

## Start the system

Prerequisites are Python 3.12 and Docker with Compose v2. The supplied bootstrap supports macOS
arm64/x86-64, Windows x86-64, and Linux x86-64/aarch64, and installs pinned uv 0.11.8 under
`.tools/bin`. OpenTofu and Trivy are not installed on your computer: the supplied commands run
each of them in a container image pinned by digest. If your computer cannot run the stack
locally, use the Codespaces button above.

On macOS and most Linux distributions the interpreter is `python3`; substitute it wherever these
commands say `python`.

```shell
python infra/scripts/bootstrap.py
./.tools/bin/uv sync --frozen
./.tools/bin/uv run --frozen poe preflight
./.tools/bin/uv run --frozen poe start
./.tools/bin/uv run --frozen poe ready
./.tools/bin/uv run --frozen poe tofu-setup
```

Run `poe tofu-setup` once before Step 1. It pulls the pinned OpenTofu and Trivy images and the
AWS provider the lock file pins; it needs no running stack, and running it again changes
nothing. Until it has run, `poe tofu-plan`, `poe tofu-apply`, `poe tofu-destroy`,
`poe tofu-scan` and `poe verify` stop with a message naming it.

PowerShell and POSIX wrappers are available under `infra/scripts/`. After uv is on `PATH`, the
shorter `uv run --frozen poe <task>` form works; in PowerShell on Windows the pinned binary is
`.tools/bin/uv.exe`.

| Service | Local URL | Purpose |
|---|---|---|
| API | `http://localhost:8000` | Submit readings, poll exception summaries, search procedures |
| Token issuer: discovery document | `http://localhost:8180/.well-known/openid-configuration` | The development issuer's OIDC discovery document: its `issuer` and `jwks_uri` |
| Token issuer: key set | `http://localhost:8180/.well-known/jwks.json` | The published key set (JWKS) the settled `config/auth.yaml` names |
| Jaeger | `http://localhost:16686` | Open traces; the trace ids the audit records carry are these |
| Grafana | `http://localhost:3000` | Use the focused diagnostics dashboard |
| Prometheus | `http://localhost:9090` | Query bounded metrics and inspect the deployed alert rule |
| Alertmanager | `http://localhost:9093` | Inspect firing and resolved alerts |
| LocalStack S3/SQS/Secrets Manager | `http://localhost:4566` | The emulated object-storage, queue and secret-store endpoint; `poe infra-diff` reads it here |

Each of these ports can be overridden by setting the matching `COLDLINE_API_HOST_PORT`,
`COLDLINE_ISSUER_HOST_PORT`, `COLDLINE_JAEGER_HOST_PORT`, `COLDLINE_GRAFANA_HOST_PORT`,
`COLDLINE_PROMETHEUS_HOST_PORT`, `COLDLINE_ALERTMANAGER_HOST_PORT`, or
`COLDLINE_LOCALSTACK_HOST_PORT` environment variable in your shell environment or a local
`.env` file (copy `.env.example`) if a default collides with something already running on your
machine. Keep the override in place for every `poe` command. If you remap the issuer port,
keep `config/auth.yaml` unchanged: it is supplied in this Task and names the default port.
Host-side tools (the carried access and audit tests, `poe token-check`) resolve the API's and
the issuer's origins from `COLDLINE_API_HOST_PORT` and `COLDLINE_ISSUER_HOST_PORT` (the
environment, then `.env`, then the default), `poe infra-diff` and the secret tools resolve
LocalStack's host port from `COLDLINE_LOCALSTACK_HOST_PORT` the same way, and the API and the
worker use the Compose-network origins. OpenTofu runs on the Compose network too, where
`infra/tofu/providers.tf` reaches LocalStack as `http://localstack:4566` whatever host port
you publish, so a LocalStack override needs no change to the provider configuration.

This Task runs as its own Compose project, `coldline-task-4-10`. If an earlier Task's stack is
still running, run `poe stop` in that Task's repository first; otherwise `poe start` here fails
because the published ports are already taken.

PostgreSQL, Redis, worker metrics, and OTLP remain inside the Compose network. Codespaces uses the
same `compose.yaml` and keeps every forwarded port private. Redis keeps running only for an
earlier checkpoint's own contract test; no composition root reads it anymore.

## Command path

For this Task, run the supplied commands in this order, with the stack started:

```text
poe tofu-setup     # once, before Step 1
poe tofu-plan      # Step 1: plan your declarations
poe tofu-apply     # Step 2: apply them
poe infra-diff     # Step 2: compare them with the stack's resources; repeat after each fix
poe tofu-scan      # Step 3: scan the declarations
poe tofu-destroy   # Step 4: destroy them, then plan and apply once more
poe answers        # as you complete the answer sheet
poe submission     # before you push: only the four permitted files changed
poe verify
```

The exact public command is `./.tools/bin/uv run --frozen poe verify`, run from the repository
root. Where a Task page shortens a command to `poe <task>`, that is the form it means.

| Command | Use |
|---|---|
| `poe verify` | The public student verification path: the answer format and the permitted files first, then the unit tests; then it starts the stack, plans, applies, compares, destroys and plans again with its own prefix and state, scans the declarations, compares your counts and triage with what it observed, and reruns the Project 4 control checks |
| `poe tofu-plan` | Plan `infra/tofu/` against LocalStack with the `coldline-sandbox` prefix. The summary line says how many resources it would add |
| `poe tofu-apply` | Show the plan again and apply it (`-auto-approve`) |
| `poe tofu-destroy` | Destroy every resource the sandbox's state tracks (`-auto-approve`); the last line says how many |
| `poe infra-diff` | Pair each of the stack's resources with your resource of the same name after the prefix, compare each setting the startup code sets, and print every difference and their count |
| `poe tofu-scan` | Run Trivy's configuration scan on `infra/tofu/` with `infra/tofu/.trivyignore` as its ignore file, and print each finding's check id, the resources it names and the setting it recommends |
| `poe tofu-setup` | Pull the pinned OpenTofu and Trivy images and the provider; run it once before Step 1. It needs no stack, and the other OpenTofu and scan commands stop with a message naming it until it has run |
| `poe answers` | The answer sheet's format: the eight answers in their stated forms, and not a copy of the sample |
| `poe submission` | The same check plus the permitted-files boundary |
| `poe iac-contract` | This Task's own rows, as `poe verify` runs them; start the stack first |
| `poe integrity-record`, `poe integrity-check` | The first and last steps of `poe verify`: hash the answer sheet, your files and the checks' own files into a snapshot outside the repository, then compare the tree with it |
| `poe student-tests` | Run the supplied tests under `tests/student/`: the carried Task 4.2 access tests, Task 4.3 guardrail and audit tests and Task 4.4 redaction tests. None is yours in this Task; start the stack first |
| `poe secret-status`, `poe secret-replace`, `poe provider-auth-check`, `poe secret-check-old` | Task 5's secret tools, still runnable; none prints a value; not this Task's exercise |
| `poe security-setup`, `poe security-scan`, `poe seed-secret`, `poe seed-vulnerable` | Task 5's gate tools, kept as supplied; the `security-gate` job still runs `poe security-scan` on every pull request with the settled thresholds and suppression |
| `poe auth-checks`, `poe token-check <fixture>`, `poe scenario`, `poe audit-trail <exception_id>`, `poe pii-scan <exception_id>`, `poe attack-dev` | The earlier Tasks' tools, still runnable; not this Task's exercise |
| `poe queue-contract`, `poe slo-contract`, `poe gate-contract`, `poe runbook-contract`, `poe e2e` | Project 3's checks and the inherited platform checks, runnable as supplied |
| `poe contract` | Check interfaces, boundaries, submissions, and repository structure |
| `poe restart` | Restart the existing API and worker containers **without rebuilding** |
| `poe stop` | Remove containers and the network, keeping named volumes |
| `poe reset` | Remove containers, the network, and local named volumes; LocalStack starts empty again |

### Your sandbox and its state

`poe tofu-plan`, `poe tofu-apply` and `poe tofu-destroy` name every resource from the
`coldline-sandbox` prefix, so your resources sit beside the stack's `coldline-` resources
instead of replacing them, and the prefix can never be the stack's own. The stack's secret,
`coldline/worker/model-provider-key`, has no `coldline-` to follow: its sandbox copy is
`coldline-sandbox-worker/model-provider-key`. `coldline-sandbox/worker/model-provider-key`
pairs with it as well, because either separator may follow the prefix. OpenTofu keeps the
sandbox's state in `infra/tofu/terraform.tfstate` and its provider in `infra/tofu/.terraform/`;
both are Git-ignored and never part of your pull request. No state encryption is configured,
so every value OpenTofu manages is written to that state file in plain text.

LocalStack keeps nothing across `poe reset` or `poe stop`, but the state file does. If you
reset the stack while the sandbox exists, run `poe tofu-destroy` first, or delete
`infra/tofu/terraform.tfstate` afterwards, so the state doesn't describe resources that are
gone.

`poe verify` never uses your sandbox or your state. It copies your declarations into
`.tools/tofu-verify/`, runs with a `coldline-verify-` prefix of its own and its own state,
and destroys what it created before it ends.

## Folder map

```text
repository root/
├── .gitleaks.toml       The settled secret-scanner configuration from Task 5
├── .semgrepignore       The paths Semgrep leaves out
├── config/              Retrieval configuration, settled since Sprint 2, and the settled auth.yaml
├── docs/                Student guidance, public contracts, fidelity notes, the security and governance material
│   ├── contracts/       Machine-readable public contracts, including this Task's answer schema
│   ├── fidelity/        Local-runtime boundary notes for each active adapter and the token issuer; SecretProvider.md names the secret
│   ├── governance/      The Task 6 analysis, owners, concerns and decision policy, and reference versions of the register and the decision record
│   ├── security/        The supplied workflow, threat catalog, control matrix, access policy, output policy, audit events, redactor, and gate policy
│   ├── architecture/    Supplied vector engine technical profiles, in prose
│   ├── retrieval/       Supplied retrieval pipeline reference
│   └── student/         This Task's contract, your working notes (iac-record.md), and the settled Project 4 records
├── evidence/            Git-ignored: the evidence file `poe attack-dev` writes, if you run it
├── infra/               Local setup and runtime configuration
│   ├── tofu/            The OpenTofu project: providers.tf, variables.tf, the lock file, your main.tf and .trivyignore
│   ├── opentofu.yaml    The OpenTofu image the infrastructure commands run, pinned by digest
│   ├── containers/      The API and worker Dockerfiles, with the build identity arguments
│   ├── issuer/          The development token issuer: its server script and the published key set
│   ├── observability/   Prometheus, Alertmanager, and Grafana configuration
│   ├── release/         The supplied release manifest, unchanged
│   ├── corpus/          Supplied synthetic corpus (one procedure carries the planted instruction), query set, and investigation
│   ├── judge/           Supplied cached judge evidence and its provenance record
│   ├── profiles/        Supplied engine and emulator profiles, and their provenance record
│   └── postgres/        Database initialization and the migration baseline stamp
├── loadtest/            Supplied traffic profile and provider-latency harness
├── migrations/          Alembic environment, revision template, and revisions
├── reports/             Git-ignored: the scan report and the bill of materials `poe security-scan` writes
├── schemas/             The supplied output schema the guardrail enforces
├── security/            The settled gate thresholds, the scanner pins (Trivy among them), the supplied Semgrep rules
├── src/
│   ├── api/             HTTP application code, composition, the initializer (the startup code), the audit-trail command
│   │   └── security/    The settled TokenVerifier and require_access rule
│   ├── worker/          Background application code, the settled settings module, the guardrail, the redaction calls
│   ├── common/          The supplied audit sink and the supplied redactor both services use
│   ├── domain/          Shared domain code, contracts, the failure taxonomy, service and repository contracts
│   ├── ports/           Application interfaces
│   └── adapters/        Technology-specific implementations: the S3 object store, the SQS queue, the Secrets Manager adapter, and the rest
└── tests/
    ├── unit/            Isolated behavior checks
    ├── contract/        Interface and repository checks, this Task's assessed rows and its answer-sheet and boundary checks
    ├── security/        Supplied tooling: the OpenTofu runner, the comparison, the configuration scan, the integrity bookends, the scan and secret tools
    ├── student/         The carried Task 4.2, 4.3 and 4.4 test files; none is yours in this Task
    ├── fixtures/        Supplied fixtures
    ├── smoke/           Running-platform checks
    └── e2e/             Supplied workflow tools and checks
```

## Overview

Use the Task 10 lesson (Task 4.10 in this repository) to decide what to do. This README covers
local setup and repository orientation.

1. `README.md` — local setup, commands, and permitted changes.
2. [`docs/student/task-4-10-contract.md`](docs/student/task-4-10-contract.md) — what this Task
   assesses and who assesses it, how the comparison pairs and compares, how a triage is
   checked, the Check-list rows and the checks that read them, and the permitted paths.
3. [`src/api/initialize.py`](src/api/initialize.py),
   [`src/adapters/object_store/s3.py`](src/adapters/object_store/s3.py) and
   [`src/adapters/queue/sqs.py`](src/adapters/queue/sqs.py) — the startup code: what it
   creates and the settings it sets.
4. [`compose.yaml`](compose.yaml), [`src/api/config.py`](src/api/config.py) and
   [`docs/fidelity/SecretProvider.md`](docs/fidelity/SecretProvider.md) — the names and
   values the startup code reads.
5. [`infra/tofu/providers.tf`](infra/tofu/providers.tf) and
   [`infra/tofu/variables.tf`](infra/tofu/variables.tf) — the supplied provider configuration
   and the `name_prefix` variable your declarations use.
6. [`docs/student/iac-record.md`](docs/student/iac-record.md) — your working notes, one
   section per Step.

## Test levels

| Level | Requires Compose | Main question |
|---|---|---|
| Unit | No | Does one responsibility behave correctly, including failures? |
| Contract | Some | Do interfaces, schemas, paths, and dependency rules stay compatible? |
| Assessed (`poe iac-contract`) | Yes, and Docker | Do your declarations plan, apply, match the stack, scan, destroy and rebuild as your sheet says? |
| Smoke | Yes | Did the complete local platform initialize and become observable? |
| E2E | Yes | Can an external client complete the supplied workflow, in one trace? |
| Student | Issuer | Do the carried Task 4.2, 4.3 and 4.4 tests still hold over the supplied code? |

Contract checks marked `runtime` need the running stack, and `poe contract` skips them and
the assessed rows. A fresh Task 4.10 checkout is expected to fail `poe answers` (the sheet is
blank) and every row of `poe iac-contract` (`infra/tofu/main.tf` declares nothing yet) until
the Task's work is done.

## Submission checks

Run `poe verify` locally before opening your student pull request. Public GitHub CI repeats
the student checks, running `poe submission` first so a boundary violation fails fast, and the
`security-gate` job runs `poe security-scan` with the settled thresholds. After you submit on
the platform, the protected answer check compares your local limits and your plan and destroy
counts with the course's answer key and reports its result there. The public check and the
protected answer check must both run and pass. Nothing grades `docs/student/iac-record.md` or
the evidence in your pull request description: the plan summary, the final `poe infra-diff`
output, the scan finding with your decision, and the destroy summary, each with its command
and when you ran it.

## Task boundary

The student-editable paths are:

- `infra/tofu/main.tf`
- `infra/tofu/.trivyignore`
- `docs/student/iac-record.md`
- `submission.yaml`

Declare only the bucket, the queue, the dead-letter queue and the secret, all in
`infra/tofu/main.tf`, and give the secret no value: declare no
`aws_secretsmanager_secret_version`. Work against LocalStack only: no real AWS account, no
real credentials, no remote state backend. The startup code, `compose.yaml`, the provider
configuration, the variables, the lock file, the OpenTofu and scan commands, the comparison,
the supplied tests and the workflows stay as supplied, and every Project 4 control keeps
passing its checks. The public check compares the diff from your merge base with the four
permitted files and reports any other change as a boundary violation.

### Student walkthrough

See **Optional Task 10: Infrastructure as code against LocalStack** in your course platform
for the full walkthrough. In outline: read the startup code and declare the bucket, the queue,
the dead-letter queue and the secret in `infra/tofu/main.tf`; plan; apply and compare, correcting your declarations until
`poe infra-diff` reports no differences; scan and fix or accept one check id; destroy, plan
again and apply once more; record your answers in `submission.yaml`; run `poe verify`; and
open your pull request with the evidence in its description.

## Operational limits

This local system does not authenticate users against a managed identity provider, terminate
TLS, or manage production secrets. LocalStack emulates the S3, SQS and Secrets Manager calls
the stack and the AWS provider make, with development credentials. Which properties of a real AWS account a run against it can and
can't establish is this Task's own question, in Step 4; the fidelity notes for the adapters
are [SecretProvider fidelity](docs/fidelity/SecretProvider.md),
[JobQueue fidelity](docs/fidelity/JobQueue.md) and
[ObjectStore fidelity](docs/fidelity/ObjectStore.md). Never place real credentials, personal
data, or production records in this repository.

The configuration scan finds what its checks cover, at the Trivy version pinned in
`security/scanners.yaml`; an absent finding is not an absent weakness.

Alertmanager here is configured with a "default" receiver that has no notification integration:
alerts are queryable through its own API but never sent anywhere real. Never add a webhook, email,
Slack, or paid integration; Sprints 1-4 are emulator-only and never call a hosted endpoint.

Named volumes preserve local PostgreSQL, Redis, Prometheus, Alertmanager, Grafana, and Jaeger state
across `poe stop`. LocalStack object, queue and secret contents are deliberately not persisted;
the initializer re-uploads the supplied corpus artifacts, re-provisions the queues and
re-creates the secret's first version on every start. The `poe reset` command deletes the named
volumes. This topology makes no backup, replication, high-availability, disaster-recovery,
capacity, latency-SLO, or availability claim beyond what Project 3 settled.

See [TokenIssuer fidelity](docs/fidelity/TokenIssuer.md),
[ModelProvider fidelity](docs/fidelity/ModelProvider.md),
[Retriever fidelity](docs/fidelity/Retriever.md), and the
[local runtime evidence](docs/fidelity/local-runtime.md) for the other adapter boundaries.
