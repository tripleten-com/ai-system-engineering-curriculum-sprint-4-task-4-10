"""Coldline.

===================

File:              src/worker/config.py
Component:         Worker — Config
Purpose:           Own and validate every worker environment read, and hand the model
                    client the provider key for each use.
Interacts With:    LocalStack SQS and Secrets Manager, domain, ports, and adapters
Sprint/Task:       Sprint 4 — Project 4 / Task 4.6
Concepts:          Background processing, bounded resilience, redrive, procedure
                    retrieval, a secret read where it is needed
Tools:             Python 3.12, boto3, LocalStack, Pydantic

Supplied and settled from Task 4.6 on: the Task 4.5 completion, carried forward unchanged.
The provider key is no string default here; ``provider_key`` reads the current version of
the key through the supplied SecretProvider adapter on every call (control C-05 in
``docs/security/control-matrix.md``). Not student-editable in Task 4.6; the public check
compares the diff.
"""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from adapters.secrets import PROVIDER_KEY_SECRET_NAME, secret_provider


class WorkerSettings(BaseSettings):
    """Describe the protected runtime configuration for the worker service."""

    model_config = SettingsConfigDict(env_prefix="COLDLINE_", extra="forbid")

    database_url: str = Field(min_length=1)
    redis_url: str = Field(min_length=1)
    otel_endpoint: str = Field(min_length=1)
    service_name: str = "coldline-worker"
    # Vestigial: named the retired Redis Streams key and consumer group. Nothing
    # reads either field anymore; left at their original values rather than
    # renamed, since SQS naming rules never applied to a field nothing uses.
    stream_name: str = "coldline.exception.jobs"
    consumer_group: str = "coldline-workers"
    consumer_name: str = "worker-1"
    maximum_attempts: int = Field(default=3, ge=1, le=3)
    stale_message_ms: int = Field(default=30_000, ge=1_000)
    model_latency_ms: int = Field(default=250, ge=0, le=10_000)
    metrics_port: int = Field(default=9100, ge=1024, le=65535)
    # Task 3.1 release identity, baked into the image by the release manifest's build
    # argument and logged once at startup so a rollout is visible in the worker logs.
    build_version: str = Field(default="dev", min_length=1, max_length=64)
    # Task 3.2 provider-resilience bounds. These wrap every ModelProvider call
    # in its own timeout and attempt budget, independent of the transport's
    # own delivery-count-based redelivery above.
    model_timeout_ms: int = Field(default=2_000, ge=1, le=30_000)
    model_provider_max_attempts: int = Field(default=2, ge=1, le=5)
    model_retry_backoff_ms: int = Field(default=100, ge=0, le=10_000)
    # The model provider's key is no longer a setting: it lives in the secret store under
    # the name docs/fidelity/SecretProvider.md states, and `provider_key` below reads its
    # current version each time the worker needs it.
    # Task 4.4 tooling. When set, the model emulator writes the text of every request it
    # receives to one file per exception under this directory, inside the worker
    # container, so `poe pii-scan` can read what the provider was sent
    # (src/adapters/model/request_log.py). compose.yaml sets it; unset, nothing is
    # recorded.
    model_request_dir: str | None = None
    # Task 4.5 tooling. When set, the model emulator writes the outcome of each key
    # authentication (the version id and a fingerprint, never the value) to this file,
    # inside the worker container, so `poe provider-auth-check` can read which version
    # the worker last authenticated with (src/adapters/model/provider_keys.py).
    # compose.yaml sets it; unset, nothing is recorded.
    provider_auth_record: str | None = None
    # Procedure retrieval. The worker looks the matching procedure up through
    # the Retriever port with one fixed service scope: the tenancy the
    # laboratory's handling procedures live under, and every tier of it.
    procedure_tenant: str = Field(
        default="tenant-northwind",
        min_length=1,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    procedure_top_k: int = Field(default=3, ge=1, le=12)
    # Task 3.3 queue identity. The worker resolves this name to a queue URL at
    # startup; the queue's own visibility timeout and dead-letter redrive policy
    # are provisioned once, by the initializer, and are not the worker's to set.
    # LocalStack serves every emulated service through one edge endpoint, so the
    # worker's queue client, and from Task 4.5 the secret store adapter, reuse the
    # already-supplied S3 endpoint/credentials below rather than a second, redundant
    # set of environment variables. The worker has no S3 use of its own.
    s3_endpoint: str = Field(default="http://localstack:4566", min_length=1)
    s3_region: str = Field(default="us-east-1", min_length=2)
    s3_access_key_id: str = Field(default="localstack-development-key", min_length=1)
    s3_secret_access_key: str = Field(
        default="localstack-development-secret",
        min_length=1,
    )
    queue_name: str = Field(default="coldline-exception-jobs", min_length=1)
    # Task 3.4 dead-letter queue identity. The worker resolves this name to a
    # queue URL at startup, the same way it resolves `queue_name`, and polls its
    # depth for the `ColdlineDeadLetterQueueBacklog` alert
    # (`infra/observability/alerts.yml`, `src/worker/queue_monitor.py`). The name
    # matches the initializer's own provisioning and
    # `tests/failure/force_dlq_arrival.py`'s `DEAD_LETTER_NAME` constant.
    dead_letter_name: str = Field(default="coldline-exception-jobs-dlq", min_length=1)

    async def provider_key(self) -> str:
        """Return the current version of the model provider key, read from the store now.

        The model client awaits this every time it sends a request, so the key it presents
        is whatever the store holds at that moment: a replacement takes effect on the next
        request, with no restart, and an earlier version is never kept anywhere in the
        worker. The adapter is built from the LocalStack settings above
        (docs/fidelity/SecretProvider.md).
        """
        return await secret_provider(self).read(PROVIDER_KEY_SECRET_NAME)
