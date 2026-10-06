"""Coldline.

===================

File:              src/common/__init__.py
Component:         Common — Package exports
Purpose:           Expose the cross-service code both the API and the worker use.
Interacts With:    API and worker use cases, the audit store adapter
Sprint/Task:       Sprint 4 — Project 4 / Task 4.3
Concepts:          Shared provider-neutral collaborators
Tools:             Python 3.12

``common`` holds code the API and the worker share without either importing the
other: the audit sink that writes the events ``docs/security/audit-events.md``
lists. It imports ``domain`` and nothing provider-specific; the PostgreSQL store
behind the sink is an adapter.
"""

from common.audit import AuditEvent, AuditRecord, AuditRecorder, AuditSink, AuditStore

__all__ = ["AuditEvent", "AuditRecord", "AuditRecorder", "AuditSink", "AuditStore"]
