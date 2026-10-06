"""Coldline.

===================

File:              src/adapters/object_store/s3.py
Component:         Adapter — S3 object store
Purpose:           Implement the ObjectStore port against an S3-compatible endpoint.
Interacts With:    LocalStack S3 in development, domain failure types, composition roots
Sprint/Task:       Sprint 2 — Project 2
Concepts:          Boundary translation, provider isolation, local fidelity limits
Tools:             Python 3.12, boto3, LocalStack
"""

import asyncio
from typing import Any

import boto3
from botocore.client import Config
from botocore.exceptions import BotoCoreError, ClientError
from opentelemetry import trace

from domain.failures import ObjectNotFound, ObjectStoreUnavailable

_TRACER = trace.get_tracer(__name__)


def create_s3_client(
    *,
    endpoint_url: str,
    region_name: str,
    access_key_id: str,
    secret_access_key: str,
) -> Any:
    """Create one S3-compatible client for a composition root.

    Only a composition root calls this. Application code receives the
    ``ObjectStore`` port and never sees a client, an endpoint, or a credential.
    Path-style addressing is required because LocalStack does not resolve
    virtual-host bucket subdomains inside the Compose network.
    """
    return boto3.client(
        "s3",
        endpoint_url=endpoint_url,
        region_name=region_name,
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        config=Config(
            signature_version="s3v4",
            s3={"addressing_style": "path"},
            retries={"max_attempts": 3, "mode": "standard"},
        ),
    )


class S3ObjectStore:
    """Read, write, and enumerate objects behind the published ObjectStore port.

    The client is synchronous, so every call runs on a worker thread rather
    than blocking the event loop. Provider errors are translated at this
    boundary: a missing key becomes ``ObjectNotFound`` and every other
    provider or transport error becomes ``ObjectStoreUnavailable``.

    Fidelity: against LocalStack this adapter exercises the S3 API surface it
    uses, and nothing more. It establishes no claim about managed-S3 IAM policy
    evaluation, durability, cross-region consistency, listing semantics at
    scale, or multipart behavior. See ``docs/fidelity/ObjectStore.md``.
    """

    def __init__(self, client: Any, *, bucket: str) -> None:
        """Bind the adapter to one client and one bucket name."""
        if not bucket:
            raise ValueError("bucket must be a non-empty name")
        self._client = client
        self._bucket = bucket

    @property
    def bucket(self) -> str:
        """Return the bucket this adapter reads and writes."""
        return self._bucket

    async def read(self, key: str) -> bytes:
        """Return the bytes stored under a provider-neutral key."""
        with _TRACER.start_as_current_span(
            "object_store.read", attributes={"coldline.object_key": key}
        ):
            return await asyncio.to_thread(self._read, key)

    async def write(self, key: str, value: bytes) -> None:
        """Store bytes under a provider-neutral key."""
        with _TRACER.start_as_current_span(
            "object_store.write", attributes={"coldline.object_key": key}
        ):
            await asyncio.to_thread(self._write, key, value)

    async def list_keys(self, prefix: str) -> list[str]:
        """Return the stored keys under one prefix in ascending order."""
        with _TRACER.start_as_current_span(
            "object_store.list_keys", attributes={"coldline.object_prefix": prefix}
        ):
            return await asyncio.to_thread(self._list_keys, prefix)

    async def ensure_bucket(self) -> None:
        """Create the configured bucket when it does not exist yet.

        Provisioning belongs to initialization, not to request handling. This
        operation is idempotent so a repeated start, a restart, or a Codespaces
        resume does not fail.
        """
        await asyncio.to_thread(self._ensure_bucket)

    def _read(self, key: str) -> bytes:
        try:
            response = self._client.get_object(Bucket=self._bucket, Key=key)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in {"NoSuchKey", "404", "NotFound"}:
                raise ObjectNotFound(f"no object at {key}") from exc
            raise ObjectStoreUnavailable(f"object store rejected read of {key}") from exc
        except BotoCoreError as exc:
            raise ObjectStoreUnavailable(f"object store unreachable for {key}") from exc
        body: bytes = response["Body"].read()
        return body

    def _write(self, key: str, value: bytes) -> None:
        try:
            self._client.put_object(Bucket=self._bucket, Key=key, Body=value)
        except (BotoCoreError, ClientError) as exc:
            raise ObjectStoreUnavailable(f"object store rejected write of {key}") from exc

    def _list_keys(self, prefix: str) -> list[str]:
        keys: list[str] = []
        token: str | None = None
        try:
            while True:
                arguments: dict[str, Any] = {"Bucket": self._bucket, "Prefix": prefix}
                if token is not None:
                    arguments["ContinuationToken"] = token
                page = self._client.list_objects_v2(**arguments)
                keys.extend(item["Key"] for item in page.get("Contents", []))
                token = page.get("NextContinuationToken")
                if not page.get("IsTruncated") or token is None:
                    break
        except (BotoCoreError, ClientError) as exc:
            raise ObjectStoreUnavailable(f"object store rejected listing of {prefix}") from exc
        return sorted(keys)

    def _ensure_bucket(self) -> None:
        try:
            self._client.head_bucket(Bucket=self._bucket)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in {"404", "NoSuchBucket", "NotFound"}:
                raise ObjectStoreUnavailable(
                    f"object store rejected bucket check for {self._bucket}"
                ) from exc
        except BotoCoreError as exc:
            raise ObjectStoreUnavailable("object store unreachable during provisioning") from exc
        try:
            self._client.create_bucket(Bucket=self._bucket)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            # A concurrent initializer may have won the race; that is success.
            if code not in {"BucketAlreadyOwnedByYou", "BucketAlreadyExists"}:
                raise ObjectStoreUnavailable(
                    f"object store could not create {self._bucket}"
                ) from exc
        except BotoCoreError as exc:
            raise ObjectStoreUnavailable("object store unreachable during provisioning") from exc
