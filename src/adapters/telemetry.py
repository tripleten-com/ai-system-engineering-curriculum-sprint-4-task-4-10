"""Coldline.

===================

File:              src/adapters/telemetry.py
Component:         Adapter — Telemetry
Purpose:           Configure OpenTelemetry export for supplied runtime adapters.
Interacts With:    Domain contracts, ports, and local providers
Sprint/Task:       Sprint 1 — Project 1
Concepts:          Boundary translation, deterministic infrastructure
Tools:             Python 3.12, OpenTelemetry
"""

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor


def configure_tracing(service_name: str, endpoint: str) -> TracerProvider:
    """Configure OTLP trace export with one stable service identity."""
    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    provider.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint, insecure=True))
    )
    trace.set_tracer_provider(provider)
    return provider
