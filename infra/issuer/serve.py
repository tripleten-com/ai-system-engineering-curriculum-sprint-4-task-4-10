"""Coldline.

===================

File:              infra/issuer/serve.py
Component:         Development token issuer
Purpose:           Serve the OIDC discovery document and the published key set over plain HTTP.
Interacts With:    compose.yaml (the `issuer` service), infra/issuer/jwks.json, config/auth.yaml
Sprint/Task:       Sprint 4 — Project 4 / Task 4.2
Concepts:          OIDC discovery, JWKS, fixed issuer identifier, host-port remapping
Tools:             Python 3.12 standard library

Runs inside the `issuer` container, from the pinned python:3.12 image, with this directory
bind-mounted read-only. It serves exactly two documents:

- ``/.well-known/openid-configuration``: the discovery document. ``issuer`` is the fixed
  identifier the token fixtures carry in ``iss``; it does not resolve anywhere and does not
  change when a host port is remapped. ``jwks_uri`` is rendered when the container starts,
  from the host port Compose published (``COLDLINE_ISSUER_HOST_PORT``), so a browser on the
  host, ``poe token-check``, and the student tests can open it as printed.
- ``/.well-known/jwks.json``: the key set, read from ``jwks.json`` beside this file. One
  RSA public key, ``alg`` RS256. Nothing is signed here at runtime; the private key that
  signed the fixtures is not in this repository.

Not student-editable. ``docs/fidelity/TokenIssuer.md`` records what this issuer does not
prove about a managed identity provider.
"""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

LISTEN_PORT = 8180
ISSUER = "https://issuer.coldline.test"
HERE = Path(__file__).resolve().parent
JWKS_PATH = HERE / "jwks.json"
DISCOVERY_PATH = "/.well-known/openid-configuration"
JWKS_ROUTE = "/.well-known/jwks.json"


def discovery_document(host_port: str, key_set: dict[str, object]) -> dict[str, object]:
    """Return the discovery document for the host port the container was published on."""
    keys = key_set.get("keys")
    entries = keys if isinstance(keys, list) else []
    algorithms = sorted(
        {str(key["alg"]) for key in entries if isinstance(key, dict) and "alg" in key}
    )
    return {
        "issuer": ISSUER,
        "jwks_uri": f"http://localhost:{host_port}{JWKS_ROUTE}",
        "id_token_signing_alg_values_supported": algorithms,
        "subject_types_supported": ["public"],
        "claims_supported": ["iss", "sub", "aud", "exp", "iat", "role", "scope"],
        "response_types_supported": [],
        "coldline_note": (
            "Development issuer for the Coldline Task 4.2 checkpoint. It issues no tokens at "
            "runtime; the token fixtures under tests/fixtures/tokens/ were signed once with "
            "the private half of the published key."
        ),
    }


def _documents() -> dict[str, bytes]:
    """Render both documents once, at container start."""
    key_set = json.loads(JWKS_PATH.read_text(encoding="utf-8"))
    host_port = os.environ.get("COLDLINE_ISSUER_HOST_PORT", str(LISTEN_PORT))
    discovery = discovery_document(host_port, key_set)
    return {
        DISCOVERY_PATH: json.dumps(discovery, indent=2).encode("utf-8"),
        JWKS_ROUTE: json.dumps(key_set, indent=2).encode("utf-8"),
    }


class _Handler(BaseHTTPRequestHandler):
    """Answer the two published paths and nothing else."""

    documents: dict[str, bytes] = {}

    def do_GET(self) -> None:
        """Serve one of the two documents, or 404."""
        body = self.documents.get(self.path.split("?", maxsplit=1)[0])
        if body is None:
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "not found"}')
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        """Print one access line per request, as the other services do."""
        print(f"issuer: {format % args}", flush=True)


def main() -> int:
    """Serve until stopped."""
    _Handler.documents = _documents()
    # Every interface: the API reaches this container over the Compose network and Compose
    # publishes the port on the host loopback only.
    server = ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), _Handler)
    print(
        f"issuer: serving {ISSUER} discovery and key set on port {LISTEN_PORT} "
        f"(host port {os.environ.get('COLDLINE_ISSUER_HOST_PORT', LISTEN_PORT)})",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
