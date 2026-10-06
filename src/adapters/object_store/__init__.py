"""Coldline.

===================

File:              src/adapters/object_store/__init__.py
Component:         Adapter — Object store package exports
Purpose:           Re-export the supplied S3-compatible object-store adapter.
Interacts With:    Composition roots and the corpus loader
Sprint/Task:       Sprint 2 — Project 2
Concepts:          Boundary translation, deterministic infrastructure
Tools:             Python 3.12
"""

from adapters.object_store.s3 import S3ObjectStore, create_s3_client

__all__ = ["S3ObjectStore", "create_s3_client"]
