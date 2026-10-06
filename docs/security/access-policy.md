<!--
Coldline - Task 4.2
Supplied material: who may do what in the Coldline API, as roles, scopes, and grants.
Not student-editable. The checks read two rows of it by their first cell: the API
audience row and the leeway_seconds row. Keep the tables' shape if this file is revised.
-->
# Access policy

Coldline identifies a caller by a bearer token the development issuer signed. The token's
claims say who the caller is (`sub`), which job they hold (`role`), and what this particular
token was issued to do (`scope`). A verified token is evidence about the caller; this policy
says what each caller may do with it. The API is the audience of every token it accepts.

## Audience

| Setting | Value | Meaning |
|---|---|---|
| API audience (`aud`) | `coldline-api` | The name of this API in a token's `aud` claim. A token issued for another service, even by the same issuer, is refused. |

The issuer identifier and the key set URL are not policy: read them from the issuer's
discovery document, whose URL `README.md` lists.

## Clock leeway

| Setting | Minimum | Maximum | Meaning |
|---|---|---|---|
| `leeway_seconds` | 0 | 60 | The allowance, in whole seconds, for clock differences between the issuer and the API when the `exp` claim is checked. Every second of leeway lets a token through for that long after it expires, so the range is small. |

A `leeway_seconds` value outside this range fails `poe verify`'s check of `config/auth.yaml`
against this policy, whatever the tokens do with it.

## Roles

| Role (`role` claim) | Who holds it |
|---|---|
| `dispatcher` | TripleTen Medical's dispatch staff, who decide what to tell a clinic about a shipment |
| `sensor_gateway` | The sensor gateways that submit temperature readings on the shipments' behalf |
| `clinic_liaison` | Staff who talk to the clinics about deliveries; they do not handle exception summaries |
| `corpus_editor` | The team that maintains the handling procedures the retriever searches |

## Scopes

| Scope (`scope` claim, space-separated) | What a token issued with it may do |
|---|---|
| `exceptions:read` | Read an exception record and its stored summary |
| `readings:write` | Submit a sensor reading |
| `procedures:search` | Search the handling procedures |
| `documents:write` | Add a procedure document to the corpus |

A token carries the scopes it was issued for, not every scope its role could hold. A
dispatcher's token issued only for searching procedures does not read summaries.

## Grants

A route admits a caller only when the token's role **and** one of its scopes match the row
for that action. Both are checked; a role without the scope, or the scope under another
role, is refused with `403`.

| Action | Route | Role | Scope | Enforced from |
|---|---|---|---|---|
| Read an exception summary | `GET /api/v1/exceptions/{exception_id}` | `dispatcher` | `exceptions:read` | Task 2 (this Task) |
| Submit a reading | `POST /api/v1/readings` | `sensor_gateway` | `readings:write` | Not in this Task. The JSON intake stays unauthenticated; the optional Add-On 4.A1 applies this row to a gRPC intake |
| Search procedures | `POST /api/v1/retrieval/search` | `dispatcher` or `corpus_editor` | `procedures:search` | Not in this Project (control C-10 in the control matrix) |
| Add a procedure document | `POST /api/v1/documents` | `corpus_editor` | `documents:write` | Not in this Project (control C-14) |

## What a refusal means

| Status | Meaning | Examples among the supplied fixtures |
|---|---|---|
| `401` | The caller could not be identified: no bearer token, or a token the verifier refused (signature, issuer, audience, or expiry) | `bad-signature`, `wrong-issuer`, `wrong-audience`, `expired` |
| `403` | The caller was identified, and the policy does not grant them this action | `gateway-valid`, `wrong-role`, `missing-scope` |

## Token claims the API reads

| Claim | Meaning |
|---|---|
| `iss` | The issuer's identifier. Must equal the configured issuer. |
| `aud` | The audience the token was issued for. Must name the API audience above. |
| `exp` | Expiry, seconds since the epoch. Checked with the configured leeway. |
| `sub` | The caller's identity, as the issuer names it. Recorded, never granted anything by itself. |
| `role` | One role from the table above. |
| `scope` | The scopes this token was issued for, space-separated. |
