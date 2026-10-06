"""Coldline.

===================

File:              tests/security/issuer_origin.py
Component:         Security tooling — host-side issuer origin
Purpose:           Resolve the issuer's host origin from the effective issuer port, so host-side
                   token verification follows a remapped COLDLINE_ISSUER_HOST_PORT.
Interacts With:    tests/security/harness.py, tests/security/token_check.py, config/auth.yaml
Sprint/Task:       Sprint 4 — Project 4 / Task 4.3
Concepts:          Port overrides, JWKS origin mapping
Tools:             Python 3.12

From Task 4.3 on, ``config/auth.yaml`` is supplied and settled. Its ``jwks_url`` names the
default issuer port (8180). Processes on the host (the in-process test harness and
``poe token-check``) fetch the key set from that URL. When ``COLDLINE_ISSUER_HOST_PORT`` is
remapped, they must look where the issuer actually listens, with the same path. The API
container already maps the origin to the issuer's in-network address; this module does
the same for the host.

The ``.env`` file is read the way Compose reads it: a blank line or a ``#`` line is
skipped, an optional ``export`` prefix is dropped, the value may be quoted (single or
double quotes, with the quotes removed), and an unquoted value ends at an inline
`` #`` comment. The resolved port must be an integer between 1 and 65535, whatever its
source; anything else is an ``IssuerPortError`` naming the source, not a malformed URL.
"""

from __future__ import annotations

import os
from pathlib import Path

TASK_ROOT = Path(__file__).resolve().parents[2]
PORT_VARIABLE = "COLDLINE_ISSUER_HOST_PORT"
DEFAULT_PORT = "8180"
_QUOTES = ("'", '"')


class IssuerPortError(ValueError):
    """Report an issuer host port that is not an integer in the TCP port range."""


def _unquote(value: str) -> str:
    """Return a ``.env`` value with its quotes removed, or its inline comment cut off."""
    value = value.strip()
    if len(value) >= 2 and value[0] in _QUOTES and value[-1] == value[0]:
        return value[1:-1]
    for quote in _QUOTES:
        if value.startswith(quote):
            closing = value.find(quote, 1)
            if closing != -1:
                return value[1:closing]
    for marker in (" #", "\t#"):
        if marker in value:
            value = value.split(marker, 1)[0]
    return value.strip()


def env_file_values(path: Path) -> dict[str, str]:
    """Return every ``NAME=value`` assignment a ``.env`` file makes, parsed as Compose reads it.

    The last assignment of a name wins. A missing file is an empty mapping.
    """
    if not path.is_file():
        return {}
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        name, separator, value = line.partition("=")
        if not separator:
            continue
        name = name.strip()
        if name:
            values[name] = _unquote(value)
    return values


def _port_from_env_file(path: Path) -> str | None:
    """Return the issuer port a ``.env`` file sets, if it sets one (and not blank)."""
    value = env_file_values(path).get(PORT_VARIABLE)
    return value if value else None


def validate_port(value: str, *, source: str) -> str:
    """Return ``value`` when it is an integer TCP port, or raise naming where it came from."""
    text = value.strip()
    if not text.isdigit() or not 1 <= int(text) <= 65535:
        raise IssuerPortError(
            f"{PORT_VARIABLE} from {source} is {value!r}, not an integer between 1 and 65535"
        )
    return str(int(text))


def effective_issuer_port(root: Path = TASK_ROOT) -> str:
    """Return the issuer host port in effect: the environment, then ``.env``, then the default."""
    from_environment = os.environ.get(PORT_VARIABLE)
    if from_environment:
        return validate_port(from_environment, source="the environment")
    from_file = _port_from_env_file(root / ".env")
    if from_file is not None:
        return validate_port(from_file, source=f"{(root / '.env').as_posix()}")
    return DEFAULT_PORT


def host_issuer_origin(root: Path = TASK_ROOT) -> str:
    """Return ``http://localhost:<port>`` for the effective issuer host port.

    The environment wins, then the repository's ``.env``, then the default port.
    """
    return f"http://localhost:{effective_issuer_port(root)}"
