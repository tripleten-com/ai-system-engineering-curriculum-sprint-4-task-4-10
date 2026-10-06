"""Coldline.

===================

File:              tests/security/__init__.py
Component:         Security tooling — Package
Purpose:           Host-side tools and helpers for the exception summary access checks.
Interacts With:    tests/fixtures/tokens/fixtures.yaml, config/auth.yaml, the running API and issuer
Sprint/Task:       Sprint 4 — Project 4 / Task 4.2
Concepts:          Token fixtures, access policy, mutation checks
Tools:             Python 3.12

Supplied, not student-editable. The modules here back `poe token-check`,
`poe auth-checks`, `poe auth-config`, `poe access-mutation`, the two static guards
(`poe route-guard`, `poe student-guard`), the integrity bookends, the in-process harness
the student tests use, the stored-exception precondition of the live rows, and the
assessed checks in `tests/contract/test_exception_access.py`.
"""
