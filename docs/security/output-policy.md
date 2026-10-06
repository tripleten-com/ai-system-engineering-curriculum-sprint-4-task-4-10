<!--
Coldline - Task 4.3
Supplied material: what the system stores and shows when a model answer fails the output
check. Not student-editable. The checks read the fixed message from the code block below
and the reason codes from the table; keep both shapes if this file is revised.
-->
# Output policy

The worker sends the model provider a reading, a handling note, and a procedure excerpt, and
gets back raw text. Nothing about that text is trusted until it has passed the output
schema. This policy says what the schema is, what happens to an answer that passes it, and
what happens to one that does not. The policy is applied in the worker, at the point where
the record is stored; a check in a display layer would protect one screen and leave every
other reader of the record unprotected.

## The schema

`schemas/exception-summary.schema.json` is the one document the provider may answer with.
It is strict:

| Rule | What it means for an answer |
|---|---|
| Five properties, all required | `summary`, `handling_class`, `next_step`, `procedure_id`, `response_id`; an answer missing one is rejected |
| No other property | An answer with a field the schema does not name is rejected, whatever the field holds |
| `handling_class` is a closed list | One of `thermal_excursion`, `seal_integrity`, `equipment_failure`, `documentation_hold`, `handling_rule_breach` |
| `next_step` is a closed list | One of `operational_review`, `hold_at_relay`, `escalate_to_duty_coordinator`, `continue_transit`; every value keeps a person in the decision |
| Every string is bounded | `summary` is 1 to 2000 characters; `procedure_id` is an identifier or null; `response_id` is sixteen hexadecimal characters |

`src/worker/guardrail.py` enforces it. `validate_summary(raw)` returns a `ValidatedSummary`
when the whole document passes and a `RejectedSummary` otherwise. It never strips a field,
repairs a value, or passes part of an answer through: an answer is stored whole or not at
all.

## What the schema does and does not claim

The schema bounds the fields and the values a stored answer can have. An injected
instruction that makes the model add a field, or choose a step outside the list, is stopped
by the schema. An instruction that keeps the answer inside the schema, for example by
choosing a permitted but wrong next step, is not: the summary is advice for a person to
judge, and this policy does not claim to detect or prevent prompt injection.

## The accepted outcome

An answer that passes the schema is stored on the `COMPLETED` transition, and only its
validated fields are stored:

| Record field | Value |
|---|---|
| `state` | `COMPLETED` |
| `summary` | The validated `summary` |
| `handling_class` | The validated `handling_class` |
| `next_step` | The validated `next_step` |
| `rejection_reason` | null |
| `failure_reason` | null |

## The fail-safe outcome

An answer that fails the schema is refused whole. The exception moves to `NEEDS_REVIEW`, a
finished state that means "an answer came back and a person must review this exception
before anyone acts on it". The dispatcher sees one fixed message in place of the model's
text:

```text
Automatic summary withheld: the model's answer did not pass the output check. A dispatcher must review this exception before anyone acts on it.
```

The record stores exactly this:

| Record field | Value |
|---|---|
| `state` | `NEEDS_REVIEW` |
| `summary` | The fixed message above, verbatim |
| `rejection_reason` | The guardrail's reason code (table below) |
| `handling_class` | null |
| `next_step` | null |
| `failure_reason` | null |

None of the model's text reaches the record: not the rejected summary, not the field that
broke the rule, not its value. The reason code is for engineers; the fixed message is for
the dispatcher.

## `FAILED` is for runs where no answer came back

`FAILED` keeps its Project 3 meaning: the worker never got an answer it could check. Its
`failure_reason` values are `model_provider_terminal_failure`, `model_provider_exhausted`,
and `processing_attempts_exhausted` (and `job_queue_unavailable` from the API). An answer
that came back and failed the check is not a failure of the run; it moves to `NEEDS_REVIEW`.
A rejected answer is never retried: a retry would hide the refusal instead of recording it.

## Reason codes

The guardrail reports one code per rejected answer: the first category in this order that
the answer broke, with the schema field appended after a colon when the rule applies to one
property (`value_not_permitted:next_step`). The code names the rule, never the answer: an
unknown property's own name is answer text and is not carried.

| Code | The rule the answer broke |
|---|---|
| `not_json` | The text is not a JSON document (the supplied `malformed` response stops partway) |
| `not_an_object` | The JSON is not an object |
| `missing_property` | A required property is absent |
| `unknown_property` | The answer carries a property the schema does not name (the supplied `manipulated` response adds one) |
| `wrong_type` | A property has the wrong JSON type |
| `value_not_permitted` | A value is outside its closed list or pattern (the `manipulated` response also sets `next_step` outside the list; `unknown_property` is reported first) |
| `too_short` | A string is below its minimum length |
| `too_long` | A string is over its maximum length |

## Finished states

`COMPLETED`, `FAILED`, and `NEEDS_REVIEW` are the finished states. A repeated delivery of a
job whose record is in any of them is acknowledged without a new model call: a rejected
answer is not asked for again.

## Audit

Each decision this policy describes is recorded as an audit event:
`docs/security/audit-events.md` lists the validated and rejected events and the stored
outcome event, with the fields each may carry.
