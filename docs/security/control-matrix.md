<!--
Coldline - Task 4.1
Supplied material: the controls that can address the catalog's threats.
Not student-editable. Task 6 reuses this matrix.
-->
# Control matrix

Each control has a stated purpose, the element it acts on, the one STRIDE property it
addresses, and where in the workflow it acts. Choose a control for a threat by its purpose on
that threat's element and category, not by its name. Several controls share an element and a
property; their purposes differ in what they act on.

The last column says where a control comes from. Some are built in this Project, one is in
place since Project 3, and the rest are listed because they address catalog threats whether or
not this Project builds them. Nothing in that column says how high a threat ranks: that is the
scoring rule's job.

| Id | Control | Purpose | Element | Property | Where it acts | Where it comes from |
|---|---|---|---|---|---|---|
| C-01 | Token verification and role/scope check on the summary read | Reject a summary read whose caller presents no verifiable identity, and allow it only for the one role and scope the access policy grants for reading a summary. | E3 | spoofing | `GET /api/v1/exceptions/{exception_id}` | Project 4, Task 2 |
| C-02 | Output validation | Accept the provider's answer only when it matches the strict output schema; otherwise store a fixed message and mark the record for review, never the answer. | E5 | tampering | Between the provider's answer and the stored record | Project 4, Task 3 |
| C-03 | Audit sink | Record each summary read with the caller's subject and role, and each processing step with the request, the answer's digest, and the stored outcome, in PostgreSQL. | E3 and E5 | repudiation | The summary read, and the worker's processing steps | Project 4, Task 3 |
| C-04 | PII redaction | Replace personal details in the handling note and in the provider's answer with placeholders before the note is logged or sent, and before the answer is stored. | E5 | information_disclosure | The note as the worker reads it; the answer before it is stored | Project 4, Task 4 |
| C-05 | SecretProvider | Read the worker's provider key, and any other credential it starts with, from Secrets Manager on each use instead of from a configuration literal, so no credential is in the repository or the image. | E5 | information_disclosure | The worker's configuration | Project 4, Task 5 |
| C-06 | CI security gate | Fail a pull request that adds a secret, a vulnerable dependency or image, or a static-analysis finding at or above the configured threshold, before it merges and ships in the worker or API image. | E5 | tampering | Pull requests, before merge | Project 4, Task 5 |
| C-07 | Gateway authentication on reading ingest | Accept a reading only from a caller holding the sensor-gateway identity and the readings write scope. | E3 | spoofing | `POST /api/v1/readings` | Not in this Project; optional Task 8 adds a token check on a gRPC ingest |
| C-08 | Signed job envelope | Sign each queued job in the API and have the worker verify the signature before processing, so an altered body is refused. | E5 | tampering | The queue message, as the worker reads it | Not in this Project |
| C-09 | Least-clearance retrieval scope | Retrieve for the worker with the standard tier only, so restricted procedures never enter a model request. | E5 | information_disclosure | The worker's retrieval scope | Not in this Project |
| C-10 | Token verification on procedure search | Take the caller's tenant and clearance from a verified token rather than from the request body. | E3 | spoofing | `POST /api/v1/retrieval/search` and the document reads | Not in this Project |
| C-11 | Per-service database roles | Give the worker a database role that reads the corpus and writes only exception records, and the API a role that cannot alter the schema. | E9 | elevation_of_privilege | PostgreSQL roles | Not in this Project |
| C-12 | Ingest rate limit | Bound the readings any one caller may post per minute, and refuse the rest with a retry-after. | E3 | denial_of_service | `POST /api/v1/readings` | Not in this Project |
| C-13 | Bounded provider calls | Time out each provider call, retry a bounded number of times, and after the bounded processing attempts record the exception as `FAILED` and acknowledge the job, so one slow or failing provider call cannot hold the worker. A delivery the worker never acknowledges is dead-lettered by the queue's redrive policy. | E7 | denial_of_service | Each model-provider call | In place since Project 3 (Tasks 3.2 and 3.3) |
| C-14 | Authenticated, reviewed corpus writes | Accept a procedure document only from an authenticated corpus editor, and publish it only after a second editor approves it. | E9 | tampering | `POST /api/v1/documents` and the corpus load | Not in this Project |
| C-15 | Procedure-search audit | Record each procedure search's caller and the ids of the documents returned, in PostgreSQL. | E3 | repudiation | `POST /api/v1/retrieval/search` | Not in this Project |

## Limits the Project's controls state

Task 6 maps risks to these controls and needs each control's limit. They are recorded here once
so the later Tasks quote one source.

- C-01 verifies a token against the development issuer's published keys. It shows how this
  system checks a token; it does not show how a managed identity provider would issue one.
- C-02 narrows what an injected instruction can change to what the schema allows. It does not
  detect or prevent prompt injection.
- C-03 records what the API and the worker do. It cannot record a read that never reached the
  API, and it records nothing about who read the audit table itself.
- C-04 redacts the kinds of personal data the redactor recognizes, at a fixed version, and has
  documented limitations.
- C-05 moves one key behind one adapter against LocalStack Secrets Manager. It shows the read
  path and the version check; it does not show AWS IAM or KMS behavior.
- C-06 finds what its scanners are configured to find, at the thresholds set for it.
