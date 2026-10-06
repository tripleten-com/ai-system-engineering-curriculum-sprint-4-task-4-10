"""Coldline.

===================

File:              src/api/extensions/__init__.py
Component:         API — Student extension package
Purpose:           Hold the application code a Task permits a student to add or change.
Interacts With:    The composition root, the retrieval workflow, domain and ports
Sprint/Task:       Sprint 2 — Project 2
Concepts:          Dependency direction, bounded student surface
Tools:             Python 3.12

Modules here may import from `domain` and `ports`. They may not import
`adapters`, `worker`, a concrete infrastructure library, or the application
module that calls them. The automated dependency check enforces that, and the
restriction is what makes an extracted service testable without a database or
a network.

This is the application layer on purpose. A service that depends on one of the
five ports is application logic: `domain` may not import outward, so a
port-dependent service cannot live there.
"""
