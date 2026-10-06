"""Coldline.

===================

File:              src/adapters/model/__init__.py
Component:         Model adapters — Package exports
Purpose:           Expose active model-provider adapters and the provider-key check.
Interacts With:    Domain contracts, ports, and local providers
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          Boundary translation, deterministic infrastructure, bounded resilience,
                    a provider that accepts only the current key
Tools:             Python 3.12
"""

from adapters.model.deterministic import DeterministicModelProvider
from adapters.model.provider_keys import (
    FileAuthenticationRecord,
    MemoryAuthenticationRecord,
    ProviderKeyRejected,
    SecretStoreKeyAuthenticator,
)
from adapters.model.resilient import ResilientModelProvider, classify_default

__all__ = [
    "DeterministicModelProvider",
    "FileAuthenticationRecord",
    "MemoryAuthenticationRecord",
    "ProviderKeyRejected",
    "ResilientModelProvider",
    "SecretStoreKeyAuthenticator",
    "classify_default",
]
