<!--
Coldline - Task 4.7
Supplied checkpoint: a completion/reference version of the Task 6 corrections to the
AI-generated analysis, carried into the Task 4.7 checkpoint as settled material. It is not
your evidence: at the Project Defense, cite your own corrections at Task 6's accepted
commit. It is not student-editable in this Task; the only file a Task 4.7 pull request may
change is submission.yaml. A blockquote that starts with `> Analysis (CL-nn):` quotes the
supplied analysis's own wording, not a statement of this file.
-->
# Governance corrections

## Claim corrections

### CL-03

- What is wrong: Only one route verifies a bearer token. The summary read `GET /api/v1/exceptions/{exception_id}` takes the verified principal through `require_access`; the reading intake, the procedure search and the document writes accept any caller, as the grants table of the access policy and the threat model's TH-02, TH-08 and TH-16 record.
- Corrected statement: The summary read refuses a caller without a verified dispatcher token with the read scope (401 without an identity, 403 with another role or scope); every other route of the API is reached without a token.
- Evidence: docs/security/access-policy.md (the grants table), src/api/routes.py (`get_exception` is the one route with `require_access`), attack-dev:token_check, tests/unit/api/test_require_access.py::test_a_route_without_the_rule_stays_open.

### CL-04

- What is wrong: The audit sink serves record-keeping, not data minimisation. Recording every processing step and every read adds records and reduces nothing: it fails the first criterion of GC-08 in docs/governance/concerns.md (a control serves it only when it removes, replaces or withholds a detail because it is personal, before the detail reaches a place that does not need it), while it meets every criterion of GC-01.
- Corrected statement: The audit sink (C-03) serves the record-keeping concern (GC-01): what the worker did with each request and who read the result can be reconstructed from the audit table. The data-minimisation concern (GC-08) is served by the redactor (C-04), within its documented limits.
- Evidence: docs/governance/concerns.md (GC-01 and GC-08), docs/security/audit-events.md, attack-dev:audit_trail.

### CL-05

- What is wrong: The redactor replaces the three kinds it recognizes, at a fixed version, with documented limits. In the development attack the phone number and the email address were replaced, and the contact name that opens a sentence reached the worker log line and the model request (RL-05 in the limitations table).
- Corrected statement: Before the note is logged or sent to the provider, the redactor replaces the phone numbers, email addresses and cue-following contact names it recognizes with placeholders; a personal detail of another shape, including a name that does not follow a contact cue, reaches the worker log and the provider as typed.
- Evidence: attack-dev:redactor, docs/security/redactor.md (the limitations table), tests/student/test_redaction.py::test_no_marked_pii_from_n01_or_pii_echo_reaches_any_location.

### CL-06

- What is wrong: Nothing in the repository encrypts a model request in transit. The provider is the deterministic emulator inside the worker process, the README states that the local system terminates no TLS, and no adapter, configuration or test names a TLS connection to a provider.
- Corrected statement: Model requests are handed to the in-process deterministic emulator; this repository shows no transport to a hosted provider and no encryption of one, so nothing can be said about a request in transit.
- Evidence: src/adapters/model/deterministic.py, docs/fidelity/ModelProvider.md, README.md (Operational limits).

### CL-09

> Analysis (CL-09): The scan report and the software bill of materials it uploads for every pull request are the audit record of the system's operation, which makes Coldline EU AI Act compliant on logging.

- What is wrong: The security gate's report and bill of materials record what the scanners found in a pull request, not what the system did with a request: the gate fails the third criterion of GC-01 in docs/governance/concerns.md (the record is about the system's handling of requests, not about the changes that were merged), while it meets every criterion of GC-05. The closing regulatory wording is a claim of conformity that no mapping in this Project makes; it is removed, not reworded.
- Corrected statement: The CI security gate (C-06) serves the secure-development concern (GC-05): a pull request that adds a secret, a known high-severity dependency or a static-analysis finding at or above the threshold fails before it merges, and the run keeps its report. The record of the system's operation is the audit trail (C-03, GC-01).
- Evidence: docs/governance/concerns.md (GC-01 and GC-05), docs/security/gate-policy.md, docs/security/audit-events.md.

### CL-10

- What is wrong: The trail records a summary read only when the read returned a stored outcome. A request for an unknown id, a poll of an unfinished record and a refused request record nothing, and nothing records who reads the audit table itself.
- Corrected statement: Every summary read that returns a stored outcome through `GET /api/v1/exceptions/{exception_id}` is recorded with the caller's subject and role and the trace id of its request, so such a read can be reconstructed afterwards; reads that never reached the route, and reads of the audit table, are not recorded.
- Evidence: docs/security/audit-events.md (Reads that are not summary reads), attack-dev:audit_trail, attack-dev:token_check (the refused read added no event), tests/student/test_audit.py::test_one_interaction_leaves_every_listed_event_in_order.

### CL-11

- What is wrong: Procedure searches are not logged with anything. The search route returns the ranking and writes nothing, the retriever span carries only the caller's own query id, and the control that would record searches (C-15) is not built in this Project; the threat model rates TH-17 high for this reason.
- Corrected statement: No record of a procedure search's caller or returned documents is kept; a restricted procedure found in the wrong hands cannot be traced to the search that returned it.
- Evidence: docs/student/threat-model.md (TH-17), docs/security/control-matrix.md (C-15), src/api/routes.py (`search`).

### CL-12

> Analysis (CL-12): no personal data leaves Coldline, which meets the HIPAA minimum-necessary standard for the laboratory's shipments.

- What is wrong: C-04 does serve GC-08, but not fully and not for all personal data: the redactor recognizes three kinds with documented limits, the development attack shows a contact name reaching the model request, and the stored reading and the queued job keep the raw note. The closing regulatory wording is a claim of conformity the mapping does not make; it is removed, not reworded.
- Corrected statement: The PII redaction (C-04) contributes to the data-minimisation concern (GC-08) by replacing the recognized phone numbers, email addresses and cue-following names in the note before it is logged or sent, and in the answer before it is stored; it does not establish that no personal data leaves Coldline, and the raw note remains in the stored reading.
- Evidence: attack-dev:redactor, docs/security/redactor.md (Where the worker applies it, and the limitations table), docs/governance/concerns.md (GC-08).

## Omitted risks

### OR-01

- Risk: TH-09, restricted procedure text sent to the model provider. The worker retrieves procedures under one fixed scope that sees every tier of the procedure tenancy and places the excerpt in the model request; the analysis says nothing about what leaves Coldline in the request besides the note, and no Project 4 control narrows the scope (C-09 is not built).
- Evidence: docs/student/threat-model.md (TH-09 in the likelihood basis), docs/security/threat-catalog.yaml, src/worker/procedures.py.

### OR-02

- Risk: TH-16, anyone can write a procedure document. `POST /api/v1/documents` stores a document under any tenancy and tier with a custodian name the caller typed, and the retriever ranks it with the supplied ones, so its text can be the excerpt the worker sends; the analysis never mentions the corpus or its writers, and C-14 is not built.
- Evidence: docs/student/threat-model.md (TH-16, and the last section on corpus writes), src/api/routes.py (`create_document`).
