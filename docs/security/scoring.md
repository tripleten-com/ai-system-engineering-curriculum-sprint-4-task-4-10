<!--
Coldline - Task 4.1
Supplied material: how to classify, rate, and rank the catalog's threats.
Not student-editable.
-->
# Scoring rule

This page fixes three things so two people reading the same code reach the same ranking: what
each STRIDE category means, how a likelihood follows from the code, and how scores are ordered.
The impact of each threat is supplied below; it is not yours to rate.

## STRIDE categories

Each category names one security property the threat breaks. Classify the threat as the
catalog describes it, on the element it names. Do not classify by what an attacker could do
next with what they gain: a readable key is about confidentiality, whatever is done with the
key afterwards.

| Category | Value in `submission.yaml` | Broken property | The threat is this kind when |
|---|---|---|---|
| Spoofing | `spoofing` | Authentication | The element acts on a request as if it came from a particular party, but has no evidence of who sent it. This holds whenever the element accepts the identity or access scope a caller asserts, whatever the caller gains by it; the rules below say which supplied content is tampering instead. |
| Tampering | `tampering` | Integrity | Data the element stores, carries, or runs is changed, replaced, or supplied by someone not entitled to decide its content, so it is no longer what the element's operators intend. |
| Repudiation | `repudiation` | Accountability | After an action, no record can show who did it or what produced an outcome, so the action can be denied or cannot be reconstructed. |
| Information disclosure | `information_disclosure` | Confidentiality | Data reaches a place or a party it should not reach, when who the reader is has already been established or is not the issue. |
| Denial of service | `denial_of_service` | Availability | The workflow stops, slows, or falls behind for the requests that should be served. |
| Elevation of privilege | `elevation_of_privilege` | Authorization | A component or a known caller can do more than its role needs or allows. |

Three rules decide the cases that seem to fit two categories:

1. Accepting a caller's asserted identity or access scope is spoofing. A caller asserts an
   identity or scope by naming it in the request (a tenant or clearance in the body), or by
   using an endpoint the element serves to one party (the dispatcher's status read, the
   gateway's reading ingest) while presenting nothing that proves who sent it. The category
   is spoofing whatever the caller gains by it, data included. Information disclosure is for
   data that travels to the wrong place or party when who the reader is has already been
   established or is not the issue.
2. Alteration or supply of queued messages, procedure documents, dependencies, or provider
   answers is tampering, even when the write path also lacks authentication: what breaks is
   the element's trust in that content, not its knowledge of who wrote it. This rule is for
   content from outside the element's trust group; when the writer is a Coldline component
   or a known caller acting beyond what its role needs, the category is elevation of
   privilege.
3. A reading accepted as originating from the sensor gateway is an asserted-identity case,
   spoofing, not tampering: the API's failure is to take the sender for the gateway, and
   what a reading says is the gateway's to decide. Rule 2 names the content kinds that are
   tampering; a reading is not among them.

## Likelihood

Rate each threat against the code in this repository today, before any Project 4 control
exists. Start from the element and flow the catalog names, open the files
`docs/security/workflow.md` lists for that element, and answer two questions in order.

**Question 1. Can a party other than the element's operator reach the path?** To reach a path
is to send the request, to write the data the element consumes, or to read where the data
sits. The parties are the ones `docs/security/workflow.md` names: the sensor gateway and the
staff who type into it, the dispatcher, the model provider, the corpus editors, and anyone
with read access to the repository, a CI log, or a built image. Those readers read; as
`docs/security/workflow.md` states, only Coldline operators can open or merge a pull request,
dependency changes included, so a path that is reached only by changing what merges is reached
by nobody but the operator. Likewise, as that page states, every port `compose.yaml` publishes
binds the host's loopback interface, and only Coldline operators run processes on the
development host, so a published port adds no party to the ones the page names: a path that
is reached only through such a port (the queue's SQS endpoint, the corpus bucket) is reached
by nobody but the operator either. If nobody but Coldline's own operators and processes can
reach the path, the likelihood is `low`.

**Question 2. If the path is reachable, does code on it check, limit, or record what the
threat needs?**

- Nothing does: `high`.
- Something does, but it does not count. A check does not count when it checks a value the
  same party supplied (a tenant or clearance the caller stated, a custodian name the caller
  typed, an identity derived from the request itself), or when it covers only part of what
  the threat names (one of several routes the description lists, one shape of the data but
  not another). A limit also does not count when it acts on something other than the
  security property the threat breaks: a cap on how much text is sent does not count while
  the text still reaches a reader who should not receive it. Rate as if nothing were there:
  `high`.
- Something bounds or refuses part of what the threat needs, and the threat as described
  remains possible inside that bound: `medium`.
- Something refuses exactly what the threat needs: `low`.

Rate the whole path the catalog describes. When a description names several routes (logs,
the provider, the record), one route with nothing on it makes the likelihood `high`.

| Value | Number |
|---|---|
| `low` | 1 |
| `medium` | 2 |
| `high` | 3 |

### Worked example, not in the catalog

Grafana answers anyone who can reach port 3000 with no login; `compose.yaml` enables anonymous
access with the viewer role. Question 1 turns on who can reach the port. `compose.yaml`
publishes it as `127.0.0.1:3000`, on the host's loopback interface only, and
`docs/security/workflow.md` states that only Coldline operators run processes on the
development host, so as shipped nobody but the operator reaches it: likelihood `low`, and
Question 2 is never asked. Had the port been published on every interface (`3000:3000`, with
no address in front), anyone on the host's network could reach it, they are not the operator,
and Question 2 would find nothing that checks who they are: likelihood `high`. The dashboards
show counts and latencies, no customer data, so the impact would be *internal* (2) either way,
and the score 2 as shipped or 6 on every interface.

## Impact

Impact is supplied. It describes what is lost if nothing stops the threat, on this scale:

| Level | Number | Meaning |
|---|---|---|
| limited | 1 | One shipment's processing is delayed, or one bogus item appears for a dispatcher to review and dismiss. Nothing leaves Coldline. |
| internal | 2 | Coldline's own operating data or processing is affected: a procedure, a queue, a dependency, an answer a dispatcher can still check against the shipment's own history. |
| accountability or credentials | 3 | Coldline cannot reconstruct what happened, or a Coldline credential is exposed. |
| customer | 4 | The laboratory's shipment data or its staff's personal details reach someone they should not, or a dispatcher acts on a wrong summary. |

| Threat | Impact | Why |
|---|---|---|
| TH-01 | 4 | The summaries are about the laboratory's shipments and, with the handling note, its staff. |
| TH-02 | 2 | A forged reading creates an exception a dispatcher reviews; the shipment's own sensor history lets them dismiss it. |
| TH-03 | 4 | A manipulated summary is what a dispatcher acts on, and the dispatch team has started to trust summaries without a second look. |
| TH-04 | 2 | The worker processes a reading or a note the API never accepted, for one job. |
| TH-05 | 3 | Who read a summary cannot be reconstructed, which is the laboratory's first question. |
| TH-06 | 4 | A contact's phone number and email address reach the provider and every reader of the record. |
| TH-07 | 3 | A Coldline credential is exposed to everyone who can read the repository or the image. |
| TH-08 | 2 | Restricted procedures are Coldline's internal handling detail; no customer or personal data is in them. |
| TH-09 | 2 | The same restricted procedures, reaching the provider instead of a caller. |
| TH-10 | 2 | The record's states and timestamps still say what the worker did; what is missing is the link to the request and the answer. |
| TH-11 | 1 | The values grant nothing outside the Compose network. |
| TH-12 | 2 | A vulnerable dependency ships in Coldline's own images. |
| TH-13 | 2 | The corpus is Coldline's operating data; the worker needs a prior compromise to touch it. |
| TH-14 | 1 | A flood delays real exceptions behind it; the queue keeps them. |
| TH-15 | 2 | Every exception waits; none is lost. |
| TH-16 | 2 | A written procedure enters a model request; what the dispatcher sees still passes through the worker's handling of the answer. |
| TH-17 | 2 | What was searched and which procedures came back is Coldline's internal handling detail; no shipment or person is in it, and the laboratory has no question about it. |

## Score and ranking

```text
score = impact x likelihood
```

Rank the threats by score, highest first. Break every tie in this order, applying each rule
only when the earlier ones tie:

1. the higher impact;
2. the higher likelihood;
3. the element that comes earlier on the request path, by its number in
   `docs/security/workflow.md` (E1 before E2, and so on);
4. the lower threat id (TH-01 before TH-02).

Together these order every threat in the catalog, so the top five and their order are
determined once the likelihoods are. Record them highest first in `answers.top_threats`.
