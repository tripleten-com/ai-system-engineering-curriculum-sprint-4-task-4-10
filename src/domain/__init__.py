"""Coldline.

===================

File:              src/domain/__init__.py
Component:         Domain — Package exports
Purpose:           Expose Coldline exception-domain behavior.
Interacts With:    API and worker use cases
Sprint/Task:       Sprint 1 — Project 1
Concepts:          Business rules, immutable contracts, state
Tools:             Python 3.12
"""

from domain.exceptions import exception_id_for, requires_exception

__all__ = ["exception_id_for", "requires_exception"]
