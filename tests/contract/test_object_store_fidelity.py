"""Coldline.

===================

File:              tests/contract/test_object_store_fidelity.py
Component:         Contract tests — Object store fidelity observations
Purpose:           Check candidate fidelity observations without overstating their scope.
Interacts With:    The running LocalStack endpoint and infra/profiles/object-store-fidelity.yaml
Sprint/Task:       Sprint 2 — Project 2 / Task 2.8
Concepts:          Emulator fidelity, observed evidence, bounded claims
Tools:             Python 3.12, pytest, boto3

Supplied and protected, and not part of the assessed set: nothing here reads a
submission. A passing credential check concerns one signed listing request;
it does not test IAM or bucket-policy evaluation. A passing single-page
listing check records a coverage gap, not an emulator/AWS divergence.
Candidate-code membership and these observations do not certify release qualification.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import boto3
import botocore
import pytest
import yaml
from botocore.config import Config

from tests.runtime_config import host_port

TASK_ROOT = Path(__file__).resolve().parents[2]
PROFILE = TASK_ROOT / "infra/profiles/object-store-fidelity.yaml"
ADAPTER = TASK_ROOT / "src/adapters/object_store/s3.py"
BUCKET = "coldline-corpus"
CORPUS_PREFIX = "corpus/"
REGION = "us-east-1"
# The listing cap AWS documents for ListObjectsV2. It is quoted here only to
# say what this environment does not reach.
AWS_LIST_PAGE_LIMIT = 1000
# Any boto3 call that would put this repository on a multipart upload path.
MULTIPART_CALLS = (
    "create_multipart_upload",
    "upload_part",
    "upload_part_copy",
    "complete_multipart_upload",
    "abort_multipart_upload",
    "upload_file",
    "upload_fileobj",
)

pytestmark = pytest.mark.runtime


def _endpoint() -> str:
    """Return the emulator endpoint, honoring the documented host-port override."""
    return f"http://localhost:{host_port('COLDLINE_LOCALSTACK_HOST_PORT', 4566)}"


def _client(*, access_key: str, secret_key: str) -> Any:
    """Return an S3 client for the local emulator with the given credentials."""
    return boto3.client(
        "s3",
        endpoint_url=_endpoint(),
        region_name=REGION,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        config=Config(signature_version="s3v4", retries={"max_attempts": 1}),
    )


def _profile() -> dict[str, Any]:
    """Return the supplied fidelity profile."""
    document = yaml.safe_load(PROFILE.read_text(encoding="utf-8"))
    assert isinstance(document, dict), f"{PROFILE.name} is not a mapping"
    return document


def test_every_qualified_code_carries_an_observation_and_an_aws_description() -> None:
    """Require evidence descriptions without certifying their qualification."""
    profile = _profile()
    limitations = profile["limitations"]
    assert limitations, "the profile publishes no limitation at all"
    for code, entry in limitations.items():
        assert entry["applies_here"] is True, (
            f"{code} is published but marked as not applying here; a code that cannot affect "
            "this system belongs under `withdrawn`, with its reason"
        )
    for code, entry in {**limitations, **profile["coverage_gaps"]}.items():
        for field in ("statement", "local_observation", "aws_behavior", "scope"):
            assert entry.get(field), f"{code} has no {field}"


def test_the_local_endpoint_accepts_unrelated_credentials() -> None:
    """Reproduce the observation behind `credential_validation_gap`.

    This tests credential acceptance for one signed listing request. It sets
    no IAM or bucket policy, so its result establishes no policy-enforcement
    behavior for either the local endpoint or a managed account.
    """
    assert "credential_validation_gap" in _profile()["limitations"]
    rogue = _client(access_key="not-a-real-key", secret_key="not-a-real-secret")

    try:
        page = rogue.list_objects_v2(Bucket=BUCKET, Prefix=CORPUS_PREFIX)
    except botocore.exceptions.ClientError as exc:  # pragma: no cover - would falsify the code
        pytest.fail(
            "the local endpoint refused unrelated credentials with "
            f"{exc.response['Error']['Code']}, so `credential_validation_gap` no longer describes "
            "this configuration and the profile must be re-qualified"
        )

    assert page.get("Contents"), (
        "the listing returned no objects, so this observation proves nothing; run `poe ingest` "
        "and try again"
    )


def test_the_listing_never_truncates_so_the_pagination_loop_is_unexercised() -> None:
    """Record a single-page coverage gap, not a pagination divergence."""
    assert "listing_pagination_not_exercised" in _profile()["coverage_gaps"]
    assert "listing_pagination_not_exercised" not in _profile()["limitations"]
    client = _client(
        access_key="localstack-development-key", secret_key="localstack-development-secret"
    )

    page = client.list_objects_v2(Bucket=BUCKET, Prefix=CORPUS_PREFIX)
    keys = page.get("Contents", [])

    assert keys, "the corpus objects are missing; run `poe ingest` and try again"
    assert len(keys) < AWS_LIST_PAGE_LIMIT, (
        f"{len(keys)} keys is at or above the {AWS_LIST_PAGE_LIMIT}-key page limit AWS "
        "documents, so this corpus would now truncate and the code needs re-qualifying"
    )
    assert page.get("IsTruncated") is False, "the local listing truncated unexpectedly"
    assert not page.get("NextContinuationToken"), (
        "the local listing returned a continuation token, so the adapter's pagination loop "
        "is exercised after all and `listing_pagination_not_exercised` is no longer true"
    )


def test_the_withdrawn_consistency_code_is_not_reintroduced() -> None:
    """A write is immediately readable and listable here, and on AWS too.

    This is why the earlier `distributed_consistency_difference` code was
    withdrawn rather than reworded: Amazon S3 has been strongly read-after-write
    consistent, including for list operations, since December 2020, so there is
    no divergence here to describe.
    """
    profile = _profile()
    assert "distributed_consistency_difference" not in profile["limitations"]
    assert "distributed_consistency_difference" in profile["withdrawn"]

    client = _client(
        access_key="localstack-development-key", secret_key="localstack-development-secret"
    )
    key = f"{CORPUS_PREFIX}fidelity-observation-probe.txt"
    client.put_object(Bucket=BUCKET, Key=key, Body=b"probe")
    try:
        assert client.get_object(Bucket=BUCKET, Key=key)["Body"].read() == b"probe"
        listed = [
            item["Key"]
            for item in client.list_objects_v2(Bucket=BUCKET, Prefix=CORPUS_PREFIX).get(
                "Contents", []
            )
        ]
        assert key in listed, "the local endpoint did not list a just-written object"
    finally:
        client.delete_object(Bucket=BUCKET, Key=key)


def test_the_adapter_performs_no_multipart_upload() -> None:
    """Keep the other withdrawal's reason true rather than merely written down."""
    profile = _profile()
    assert "upload_part_handling_divergence" not in profile["limitations"]
    assert "upload_part_handling_divergence" in profile["withdrawn"]

    module = ast.parse(ADAPTER.read_text(encoding="utf-8"))
    called = {
        node.func.attr
        for node in ast.walk(module)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    reachable = sorted(called & set(MULTIPART_CALLS))
    assert not reachable, (
        f"{ADAPTER.name} calls {reachable}, so the multipart divergence is reachable after all "
        "and must be re-qualified as a published code instead of a withdrawal"
    )
