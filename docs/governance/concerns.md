<!--
Coldline - Task 4.6
Supplied material: the governance concerns this Project maps technical controls to, with the
sources each one is drawn from and the criteria a control must meet to serve each, for
educational use. Not student-editable. The checks read the concern ids from the `## GC-nn`
headings; keep their shape if this file is revised. This file names no control: which
control serves which concern is derived from the criteria, the control matrix and the
evidence, never read off a list. The ids are labels in the order the concerns are listed,
and nothing else: an id's number says nothing about which control, if any, serves it.
-->
# Governance concerns

A governance concern is one intent a regulation or a standard expresses, stated in plain words
so a technical control can be related to it. The mapping is for understanding: it says what a
control contributes to the concern's intent and what it does not. It is not a statement that
Coldline satisfies, complies with, or is certified under any regulation or standard, and no
file you write in this Task may make one. The sources are named so you can read the intent
where it comes from; they are paraphrased here for educational use, not quoted as legal text.

## How to read a concern

Each concern states its intent, its sources, and the criteria a control must meet to serve it:
what the control would have to do, on which input, at which point in the workflow. A control
serves a concern only when it meets every criterion, as the control matrix describes the
control (`docs/security/control-matrix.md`: its purpose, the element it acts on, where it acts,
and the limit it states) and as the evidence shows it (`evidence/attack-dev.json`, the tests
it cites, an earlier Task's run). A control that meets some criteria and fails one does not
serve the concern, however close its name, its element or the data it touches sounds to the
concern; a claim that links such a control to the concern links a control to a concern it
does not address. Compare each criterion with what the control does, not with what it
touches. Some concerns are served by no control this Project built; the ids are listed in
one order and carry no hint of which.

## GC-01 Record-keeping and traceability of the system's operation

- Intent: what the system did with each request, what the automated component returned, and
  who read the result can be reconstructed afterwards from records the system kept.
- Sources: the logging and record-keeping intent of the EU AI Act (Article 12); the
  accountability principle of the GDPR (Article 5(2)); audit-logging families of NIST SP 800-53
  (AU).
- Served when all of these hold:
  1. The control writes durable lifecycle records for each exception-processing run and
     records the reader of each summary read that returns a stored outcome.
  2. Those records carry enough to reconstruct those events afterwards: for a processing
     run, the request's identity, what the automated component returned (at least its
     digest) and the outcome that was stored; for such a read, the reader's identity and
     role.
  3. The record is about the system's handling of requests, not about the code that was
     built or the changes that were merged.

## GC-02 Credential and secret management

- Intent: credentials are held outside the code and the images, read where they are needed,
  replaceable without a restart, and revocable: a replaced credential stops working.
- Sources: authenticator management in NIST SP 800-53 (IA-5); ISO/IEC 27001 Annex A on
  authentication information and secure configuration.
- Served when all of these hold:
  1. The control concerns a credential of Coldline's own, one the system presents to another
     service, not a credential a caller presents to Coldline.
  2. It keeps that credential out of the repository and the images, and reads it from a
     store where it is used, at the time of use.
  3. It lets a replaced credential take effect without a restart, and the previous one stop
     working.

## GC-03 Transparency to the people affected

- Intent: the people whose data or shipments the system handles can learn that an automated
  component is involved and what it does.
- Sources: the transparency intent of the EU AI Act (Article 13) and of the GDPR (Articles 13
  and 14).
- Served when all of these hold:
  1. The control tells the people whose data or shipments the system handles (the laboratory,
     the gateway's staff, the writer of a handling note) that an automated component is
     involved and what it does with their data.
  2. It does so in a place those people see and in words meant for them, not in a message, a
     table or a log that only Coldline's own operators read.

## GC-04 Access control and least privilege

- Intent: a protected record is read or changed only by an identified party holding a role
  that is granted that action, and nothing more than the action needs.
- Sources: the access-control families of NIST SP 800-53 (AC) and ISO/IEC 27001 Annex A; the
  "appropriate access" wording of health-data privacy rules.
- Served when all of these hold:
  1. The control establishes who is making a request from a credential it verifies, before
     the request is served.
  2. It grants or refuses that request by the party's role and by the scope of the action
     requested, so a party without the granted role or scope receives nothing of the record.
  3. It acts on a route that returns or changes a protected record, at the point where the
     record would otherwise be returned or changed.

## GC-05 Secure development and supply chain

- Intent: what merges and ships is checked for secrets, known-vulnerable dependencies and
  insecure code before it merges, and the check's result is kept.
- Sources: the NIST Secure Software Development Framework; the vulnerability-handling intent
  of the EU Cyber Resilience Act.
- Served when all of these hold:
  1. The control runs on a change before it merges, in the pull request path, not on a
     request at runtime.
  2. It checks the change for a committed secret, a known-vulnerable dependency or image, and
     insecure code, and refuses the change at a configured threshold.
  3. It keeps the check's result where a reviewer can read it later.

## GC-06 Availability and resilience of the service

- Intent: the workflow keeps serving, or fails in a bounded, visible way, when a dependency is
  slow or failing.
- Sources: the resilience intent of the EU Digital Operational Resilience Act for financial
  entities, read here as a general operational intent; ISO/IEC 27001 Annex A on continuity.
- Served when all of these hold:
  1. The control bounds how long a slow or failing dependency can hold the workflow: a time
     limit on each call to it and a limit on the attempts.
  2. After the bound, it records a visible, bounded failure outcome for the case and releases
     the worker, so other requests keep being served.
  3. It acts on the call to the dependency itself, not on the content of a request or of an
     answer.

## GC-07 Human oversight of automated output

- Intent: an automated output that a person acts on can be checked, overridden or withheld
  by a person before it has effect, and the system makes clear when it has been withheld.
- Sources: the human-oversight intent of the EU AI Act (Article 14) and of ISO/IEC 42001.
- Served when all of these hold:
  1. The control decides, before a person acts on an automated output, whether that output
     may be acted on, and withholds it whole when it may not.
  2. The withholding is visible in the record a person reads, in a fixed form that says a
     person must review the case before anyone acts on it.
  3. A person's review, not the automated component, is what releases the withheld case.

## GC-08 Data minimisation and protection of personal data

- Intent: personal data is limited to what the purpose needs, and is kept out of places that
  do not need it: logs, outside parties, stored copies.
- Sources: the data-minimisation principle of the GDPR (Article 5(1)(c)); the
  minimum-necessary intent of health-data privacy rules.
- Served when all of these hold:
  1. The control acts on personal details as such: it removes, replaces or withholds a
     detail because it is personal, before the detail reaches a place that does not need it
     (a log line, an outside party, a stored copy).
  2. It acts at the point where the data would leave or be kept, before the data arrives
     there, not after the fact.
  3. What it leaves in place is bounded and stated: the kinds of detail it recognizes and
     the places it covers are documented, and the evidence shows it on a note that carries
     personal details.
