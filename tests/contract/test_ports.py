"""Coldline.

===================

File:              tests/contract/test_ports.py
Component:         Contract tests — Test Ports
Purpose:           Contract tests for the five accepted application ports.
Interacts With:    Published interfaces and repository boundaries
Sprint/Task:       Sprint 3 — Project 3
Concepts:          Compatibility, ownership, export safety
Tools:             Python 3.12, pytest, PostgreSQL, boto3
"""

import inspect
from typing import Any, cast

import ports
from adapters.model import DeterministicModelProvider
from adapters.object_store import S3ObjectStore
from adapters.queue import SqsJobQueue
from adapters.retriever import PostgresHybridRetriever
from domain.access import UnrestrictedAccessConstraints


def test_exactly_five_application_ports_are_defined_once() -> None:
    """The core package must expose exactly the five accepted provider boundaries."""
    protocol_names = {
        name
        for name, value in inspect.getmembers(ports, inspect.isclass)
        if not name.startswith("_") and getattr(value, "_is_protocol", False)
    }
    assert protocol_names == {
        "JobQueue",
        "ModelProvider",
        "ObjectStore",
        "Retriever",
        "SecretProvider",
    }


def test_active_adapters_satisfy_their_provider_neutral_port_shapes() -> None:
    """Active implementations must expose every operation owned by their core ports.

    Sprint 2 activates two more ports. ``ObjectStore`` gains an S3-compatible
    adapter and ``Retriever`` gains the PostgreSQL hybrid adapter, so both are
    checked here alongside the Sprint 1 adapters.
    """
    sqs_queue = SqsJobQueue(cast(Any, object()), queue_url="https://contract.invalid/queue")
    object_store = S3ObjectStore(cast(Any, object()), bucket="contract-bucket")
    retriever = PostgresHybridRetriever(
        cast(Any, object()), access_constraints=UnrestrictedAccessConstraints()
    )

    assert isinstance(DeterministicModelProvider(latency_ms=0), ports.ModelProvider)
    assert isinstance(sqs_queue, ports.JobQueue)
    assert isinstance(object_store, ports.ObjectStore)
    assert isinstance(retriever, ports.Retriever)


def test_object_store_port_exposes_the_enumeration_operation() -> None:
    """Corpus artifacts must be enumerable without a caller touching a cloud SDK."""
    assert hasattr(ports.ObjectStore, "list_keys")
    assert set(inspect.signature(ports.ObjectStore.list_keys).parameters) == {"self", "prefix"}


def test_retriever_port_exposes_only_the_activated_hybrid_operation() -> None:
    """The activated retrieval contract is one operation with a request object."""
    operations = {
        name
        for name, _ in inspect.getmembers(ports.Retriever, inspect.isfunction)
        if not name.startswith("_")
    }
    assert operations == {"search_hybrid"}
