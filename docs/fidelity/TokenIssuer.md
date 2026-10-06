# TokenIssuer fidelity

The active issuer is the `issuer` service in `compose.yaml`: a static file server from the
pinned python:3.12 image that publishes an OIDC discovery document and a key set holding one
RSA public key (`kid` `coldline-dev-2026`, `alg` RS256). The eight tokens under
`tests/fixtures/tokens/` were signed once with the private half of that key, outside this
repository, and committed. The issuer signs nothing at runtime, issues no token to any caller,
and has no login, consent, token, or revocation endpoint.

The issuer identifier is `https://issuer.coldline.test`. It resolves nowhere and is never
contacted: it is the string the fixtures carry in `iss` and the value `config/auth.yaml`
pins, chosen so that remapping the issuer's host port (`COLDLINE_ISSUER_HOST_PORT`) changes
no token. What the port changes is the discovery document's `jwks_uri`, rendered when the
container starts from the port actually published, so the key set URL a browser,
`poe token-check`, and the student tests open is the one printed. Inside the Compose network
that host port does not exist: the API composes its `TokenVerifier` with
`COLDLINE_ISSUER_JWKS_ORIGIN` (`http://issuer:8180`), and the verifier swaps the origin of
the configured `jwks_url` for it while keeping the path. A wrong path therefore fails in the
container as it does on the host; a wrong host port fails on the host.

It proves what Project 4 needs it to prove: that the API verifies a token's signature against
a published key set with the algorithm pinned in configuration, then its issuer, audience,
and expiry with a bounded leeway, and that a role-and-scope rule on one route tells an
unidentified caller (`401`) from an identified but ungranted one (`403`), deterministically,
against tokens whose outcome is known in advance.

It does not prove how a managed identity provider behaves. There is no key rotation: the key
set never changes, so a token signed under a retired key, a `kid` the verifier has not seen,
or a cache that outlives a rotation is never exercised here, even though the verifier does
refetch the key set once for an unknown `kid`. There are no short-lived tokens, no refresh,
no revocation, no issuance tied to a login, no consent, no device identity (a gateway token
names a gateway because the fixture says so), and no token endpoint whose availability the
API depends on. The discovery document and the key set travel over plain HTTP on the Compose
network and the host loopback; nothing here shows TLS termination, certificate validation, or
what a man-in-the-middle could do to a key set fetched over an untrusted network. The claims
and scopes are the Coldline development vocabulary in `docs/security/access-policy.md`, not a
provider's. No live identity provider or credential is used, and the checks that pass here
show how the verifier treats the supplied fixtures, signed by keys that never change, and
nothing about tokens the student does not control.
