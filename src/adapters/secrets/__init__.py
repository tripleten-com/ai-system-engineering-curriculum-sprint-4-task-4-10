"""Coldline.

===================

File:              src/adapters/secrets/__init__.py
Component:         Secret adapters — Package exports
Purpose:           Expose the supplied LocalStack Secrets Manager adapter behind SecretProvider.
Interacts With:    ports.SecretProvider, composition roots, src/worker/config.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          Dependency inversion, a secret read on every use, versions and fingerprints
Tools:             Python 3.12, boto3, LocalStack
"""

from adapters.secrets.localstack import (
    FIRST_VERSION_VALUE,
    PROVIDER_KEY_SECRET_NAME,
    LocalStackEndpoint,
    LocalStackSecretProvider,
    SecretStatus,
    SecretUnavailable,
    SecretVersion,
    create_secrets_client,
    ensure_secret_when_ready,
    fingerprint,
    secret_provider,
)

__all__ = [
    "FIRST_VERSION_VALUE",
    "PROVIDER_KEY_SECRET_NAME",
    "LocalStackEndpoint",
    "LocalStackSecretProvider",
    "SecretStatus",
    "SecretUnavailable",
    "SecretVersion",
    "create_secrets_client",
    "ensure_secret_when_ready",
    "fingerprint",
    "secret_provider",
]
