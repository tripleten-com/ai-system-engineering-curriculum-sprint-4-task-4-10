<!--
Coldline - Task 4.6
Supplied material: the AI-generated governance analysis a team member obtained for the
laboratory's renewal review. Not student-editable. Its claims are numbered so you can
classify each one in submission.yaml and correct it in docs/student/governance-corrections.md.
The wording is the assistant's, kept as received; it is wrong in places on purpose, and
nothing in it is evidence.
-->
# Coldline security and governance position

> Draft prepared by an AI assistant from the repository, the Project 4 lesson pages and a
> conversation with the team, for the laboratory's renewal review. Supplied as received.

## Summary

Coldline's exception-resolution workflow now carries the controls Project 4 set out to build:
token verification on the summary read, output validation with an audit trail, redaction of
personal details, a provider key held in a secret store, and a security gate in the pull
request path. Each numbered claim below states one position the team can put in front of the
laboratory. The claims are numbered for review; the governance concern a claim refers to is
named by its id in `docs/governance/concerns.md`, and the control by its id in
`docs/security/control-matrix.md`.

## Claims

### CL-01

The summary read, `GET /api/v1/exceptions/{exception_id}`, refuses a caller whose bearer
token has expired: the response is `401`, and no part of the record is returned to that
caller.

### CL-02

A provider answer that does not pass the output schema is never stored as the summary. The
exception moves to `NEEDS_REVIEW`, the record holds the fixed review message in the summary's
place, and none of the answer's text reaches the record.

### CL-03

Only authenticated callers can reach Coldline's API: every route verifies a bearer token
against the issuer's published key set before it does any work, so an anonymous request is
refused wherever it arrives.

### CL-04

The audit sink (C-03) serves the data-minimisation concern (GC-08). Because every processing
step and every read is recorded with its fields, the personal data Coldline keeps is reduced
to the minimum the records need.

### CL-05

Every personal detail in a handling note is removed before the note is logged or sent to the
model provider, so neither the container logs nor the provider ever receive a contact's name,
number or address.

### CL-06

As far as the team is aware, model requests leave Coldline over a TLS connection to the
provider, so the reading, the note and the procedure excerpt are encrypted in transit and
cannot be read on the way.

### CL-07

The worker reads the model provider key from the secret store each time it sends a request.
A replaced key is presented on the next request without a restart, and the provider refuses
the previous version.

### CL-08

The token verification and role check on the summary read (C-01) serves the access-control
concern (GC-04): the read is granted to the dispatcher role with the exceptions-read scope and
refused to every other caller.

### CL-09

The CI security gate (C-06) serves the record-keeping concern (GC-01). The scan report and
the software bill of materials it uploads for every pull request are the audit record of the
system's operation, which makes Coldline EU AI Act compliant on logging.

### CL-10

We believe the audit trail records every access to exception data, so any read of a
shipment's summary can be reconstructed afterwards with who made it and when.

### CL-11

Procedure searches are logged with the caller's identity and the documents returned, so a
restricted procedure found in the wrong hands can be traced to the search that returned it.

### CL-12

The PII redaction (C-04) fully satisfies the data-minimisation concern (GC-08): no personal
data leaves Coldline, which meets the HIPAA minimum-necessary standard for the laboratory's
shipments.
