<!--
Coldline - Task 4.4
Supplied material: the PII redactor at its fixed version, what it recognizes, what it
replaces each kind with, and the limitations its authors know about. Not student-editable.
The checks read the limitation ids from the first column of the limitations table; keep its
shape if this file is revised.
-->
# PII redactor

A free-text handling note travels with each reading, and some notes name a contact person
or give a phone number or email address so dispatch can reach them. The worker logs the
note as it reads the job, places it in the text sent to the model provider, and stores the
summary the model writes, which repeats the note. The redactor supplied here replaces the
kinds of personal detail it recognizes with a labeled placeholder, so a copy made after
the redaction carries the placeholder and not the detail. Where the worker applies it is
the Task's work; what it does is written here.

## Version and call form

| Item | Value |
|---|---|
| Module | `src/common/redactor.py` |
| Version | `1.0.0` (`REDACTOR_VERSION`); a change to any rule below changes the version |
| Call form | `from common.redactor import redact`, then `redact(text)` for one string; `redact(None)` is `None`, so a reading without a note needs no special case |
| Result | The same text with every recognized value replaced by its kind's placeholder; the rules are applied in the order email, phone, name |
| Stability | Redacting an already redacted text changes nothing. Placeholders contain no quote, backslash or line break. The supplied default and `pii-echo` fixtures remain schema-valid after redaction; other text can grow, so `validate_summary` must check the redacted answer |

## What it recognizes

| Kind | Recognized form | Placeholder |
|---|---|---|
| `email` | An address of the form `local@domain.tld`: a local part of letters, digits and `._%+-`, one `@`, a domain of letters, digits and hyphens with one or more dots, and a top-level label of two or more letters (`dispatch@example.com`, `qa-review@example.org`) | `[REDACTED:email]` |
| `phone` | A phone number of 7 to 15 digits in groups of two to four, separated by one space, hyphen or period, optionally starting with a `+` country code of one to three digits and optionally with one group in parentheses (`555-0142`, `+1 555 0142`, `(555) 0142`). A run of fewer than 7 digits (`8`, `12.5`) is left as it is | `[REDACTED:phone]` |
| `name` | A contact name recognized by its position: one or two words that start with a capital letter and continue in lowercase, directly after one of the contact cues `call`, `contact`, `ask for`, `notify`, `reach`, `page` (the cue in any letter case). The cue and the space after it stay; the words are replaced (`Call Priya Natarajan on` becomes `Call [REDACTED:name] on`) | `[REDACTED:name]` |

Nothing else is recognized. A placeholder matches none of the three rules, which is what
makes a second pass harmless.

## Where the worker applies it

Task 4 places two calls in `WorkerApplication.process` (`src/worker/use_cases.py`): on the
handling note where the worker first reads it from the job, before the log line that
records the job and before the note goes into the model request, so the redacted note is
the one every later line uses; and on the provider's raw answer before `validate_summary`
checks it, so the guardrail sees the text that will be stored, placeholders included. The
copies made before the worker runs, the stored reading and the queued job, keep the raw
note; that residual is named in the lesson and this document does not close it.

## Limitations

Every entry here is a limitation of this module at this version: a pattern it recognizes
wrongly, or a pattern it does not recognize at all. The ids are stable and are what
`answers.documented_limitation` in `submission.yaml` names.

| Id | Limitation |
|---|---|
| RL-01 | A phone number is recognized only in the digit-group shapes above. A number written in words (`five five five`), with other separators, or run together with letters is not recognized and stays in place. |
| RL-02 | Any run of 7 to 15 digits in those shapes is taken for a phone number whether or not it is one. A seal number, a waybill number or a date written with hyphens (`2026-10-04`) in a note is replaced with `[REDACTED:phone]`. |
| RL-03 | An email address is recognized only in the form `local@domain.tld`. An address written with spaces around the `@`, or with `at` and `dot` spelled out, is not recognized and stays in place. |
| RL-04 | A contact name is recognized by position alone: whatever capitalized word or pair of words directly follows one of the contact cues is replaced with `[REDACTED:name]`. A capitalized place, team, depot or product name in that position is replaced too, although it names no person. |
| RL-05 | A contact name that does not follow one of the cues is not recognized. A name that opens a sentence, follows another verb (`send it to`, `hand it over to`), or stands on its own stays in place. |
| RL-06 | A name written in lowercase after a cue is not recognized, and a name carrying a hyphen, an apostrophe or an honorific followed by a period (`Dr.`) is replaced only up to the punctuation, leaving the rest in place. |
| RL-07 | The redactor recognizes the three kinds above and nothing else. Postal addresses, dates of birth, identification and badge numbers, vehicle registrations, and every other personal detail stay in place. |

## What a clean scan shows

`poe pii-scan` searches four places for the values the fixture marks for a note
(`tests/fixtures/pii/notes.yaml`) and the contact a supplied response adds: the worker
logs, the model request, the audit records and the stored summary. A clean scan shows that
those marked values are absent from those four places for that run, and it is clean only
when all four were read: a location whose evidence is not there (no worker log line names
the exception, or the request record is gone, as after the worker container is recreated)
is reported `unavailable`, never `clean`, and the scan exits 2. It does not show that
every note is free of personal data, that this redactor recognizes what a given note holds
(the limitations above are real), or that the system complies with a privacy regulation.
