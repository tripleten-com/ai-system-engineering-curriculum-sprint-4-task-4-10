<!--
Coldline - Task 4.4
Supplied material: the audit events one interaction leaves behind, in order, with the
fields each may carry. Not student-editable. The checks read the event names from the
first column of the table; keep its shape if this file is revised.
-->
# Audit events

When a clinic questions a summary, someone reconstructs what happened from the audit
records alone: which request started the processing, what the model returned (by digest and
length, never by text), what the output check decided, what was stored, and who read it.
`src/common/audit.py` supplies the sink; the worker records the first four events in
`src/worker/use_cases.py` and the API records the last one in `src/api/routes.py`. The sink
writes to the PostgreSQL table `audit_events`, and `poe audit-trail <exception_id>` prints
one exception's events in order.

## What every record carries

| Field | Value | Who fills it |
|---|---|---|
| `event` | One name from the table below | The recording code |
| `exception_id` | The exception the event is about | The recording code |
| `trace_id` | The trace id of the request that recorded the event: the worker's events carry the scenario's trace (the worker continues the API's trace through the queue), and each summary read carries the trace of its own request | The sink, from the current span |
| `recorded_at` | When the sink recorded it | The sink |
| `details` | The event's own fields, from the table below, and nothing else | The recording code |

## The events, in order

One interaction produces the four worker events in this order, then one summary-read event
per read that returned a stored outcome.

| Event (`event`) | Recorded | Where | Fields `details` may carry | Must never carry |
|---|---|---|---|---|
| `processing_requested` | Once the record is this attempt's: after the `PROCESSING` transition, before retrieval and the provider call | `WorkerApplication.process` | `reading_id`, `delivery_count` | Any caller identity: the intake is unauthenticated, so there is none to record |
| `model_responded` | When the provider's answer comes back, before it is redacted or checked | `WorkerApplication.process` | `provider`, `answer_digest` (the SHA-256 hex digest of the raw answer text as the provider returned it, `common.audit.answer_digest`), `answer_length` (characters of that text) | The answer's text, or any part of it |
| `output_validated` | When `validate_summary` accepts the answer | `WorkerApplication.process` | `handling_class`, `next_step` (the validated values) | The summary text (it is in the stored outcome, once) |
| `output_rejected` | When `validate_summary` refuses the answer | `WorkerApplication.process` | `reason_code` (the guardrail's code, `docs/security/output-policy.md`) | The answer's text, the offending field, or its value |
| `outcome_stored` | When the outcome is final, immediately before the terminal `COMPLETED` or `NEEDS_REVIEW` transition stores it: a read can return a stored outcome only after that transition, so every summary read follows this event in the trail | `WorkerApplication.process` | `state` (the state the transition stores), `summary` (the stored summary, or the output policy's fixed message) | Anything the record does not store |
| `summary_read` | After the record is loaded for the response, and only when it holds a stored outcome: state `COMPLETED` or `NEEDS_REVIEW` with a summary | `get_exception` in `src/api/routes.py` | `subject`, `role` (from the verified `Principal` the access rule hands the route) | The token, the `Authorization` header, any request header, or anything else from the request |

Position three is one of two names: `output_validated` or `output_rejected`, never both for
one answer. Position four, `outcome_stored`, is recorded just before the terminal
transition rather than after it: the record and the audit table are two stores with no
shared transaction, and a dispatcher polling the record could otherwise read the stored
outcome, and leave a `summary_read`, before the event that says it was stored existed.
Recording first keeps the trail's order true without a cross-store transaction. The
record's state is the authority on what was stored: a trail whose `outcome_stored` names
a state the record does not hold reveals a terminal transition that failed after the
event was recorded. A redelivery of that record records a new sequence of events; it does
not amend the earlier one. A record whose deliveries are exhausted ends `FAILED`
(`processing_attempts_exhausted`), and the earlier `outcome_stored` event stays in the
trail as evidence of the attempt that did not complete.

## Reads that are not summary reads

A request for an exception id that does not exist is a `404`, not a read, and records
nothing. A poll of a record that is still `QUEUED` or `PROCESSING` returns the record but
no outcome, and records nothing. A refused request (`401`, `403`) never reaches the route
body and records nothing. Only a read that returned a stored outcome is a `summary_read`.
The scenario's own read of the finished record, and every later read by a dispatcher,
each add one.

## What a record must never contain

No audit record contains a credential: not a bearer token, not an `Authorization` header
in any letter case, not a provider key, not a database password. The people who read audit
records are not the people a credential was issued to, and anyone holding a credential can
act as its owner. The sink stores exactly the `details` it is handed; it filters nothing.
Record the listed fields and no others.

## From Task 4: redaction and the trail

Task 4 redacts the handling note where the worker first reads it and the provider's raw
answer before the guardrail checks it (`docs/security/redactor.md`). Two consequences for
the trail, both deliberate:

- `model_responded` digests the answer **as the provider returned it**, before the
  redaction call. The event records what came back over the wire, so an audit reader can
  tell two answers apart and prove which one the worker received; the redaction is the
  worker's own step, applied to that text afterwards. The checks replay the emulator over
  the request a correct worker sends (the note already redacted) and compare the digest
  with that answer.
- `outcome_stored` carries the stored summary, which from Task 4 is the redacted summary:
  the placeholders, not the details. Before Task 4, personal data typed into a note could
  reach the audit table through this event, as it reached the stored record. `poe pii-scan`
  searches every record's `details` for the fixture's marked values, so a redaction call
  placed after the event, or missing, shows up here.
