# ObjectStore fidelity

The active adapter is `src/adapters/object_store/s3.py`, an S3-compatible client pointed at the
supplied LocalStack container. **LocalStack is an Amazon Web Services (AWS) emulator**, not
managed object storage.

What it emulates depends on which build, edition, and configuration is running, so this is
pinned rather than implied. A limitation observed on one configuration is not a limitation of
LocalStack in general.

| Pinned | Value |
|---|---|
| Product and edition | LocalStack Community |
| Image | `localstack/localstack:4.9.1` |
| Digest | `sha256:ef90c3d6d69e36752d0154f9bc21099fc70dfbffc99a0145a6d7d04a721a6124` |
| Configuration | `SERVICES=s3`, `PERSISTENCE=0`, `EAGER_SERVICE_LOADING=1`, `DEBUG=0` |
| Region | `us-east-1` |
| Exercised API behavior | `CreateBucket`, `HeadBucket`, `PutObject`, `GetObject`, `ListObjectsV2` |

A divergence in an operation this repository never calls is outside the scope of the codes
below.

## What the local runtime proves

- The published `ObjectStore` port shape: `read`, `write`, and `list_keys`.
- That application code reaches stored objects only through that port. No module outside
  `src/adapters/object_store/` imports `boto3` or `botocore`, and both the authoring integrity
  check and a public contract test fail if one does.
- Bucket provisioning is idempotent, so a repeat start, a restart, and a Codespaces resume all
  converge on the same bucket and the same corpus artifacts.
- Provider errors are translated at the boundary: a missing key becomes `ObjectNotFound` and any
  other provider or transport error becomes `ObjectStoreUnavailable`.
- The corpus and its custody record are read from object storage rather than from the container
  filesystem, which is why the Task 2.1 boundary is observable rather than asserted.

## What the local runtime does not prove

LocalStack answering a request establishes nothing about managed S3. In particular this runtime
does **not** prove:

| Not proven | Why it matters |
|---|---|
| IAM and bucket-policy evaluation | The supplied credential check contains no policy allow/deny case. A successful local listing therefore does not establish policy enforcement or an AWS caller's permissions. |
| Durability and replication | There is no multi-facility storage, no versioning guarantee, and no restore path behind this container. |
| Listing behavior at scale | The supplied corpus listing fits in one response. Its successful read does not exercise the adapter's continuation path or demonstrate a pagination difference from AWS. |
| Multipart upload and large-object handling | The corpus artifacts are small; no multipart path is exercised. |
| Encryption at rest, key management, access logging, or object lock | The supplied checks do not exercise these controls. |
| Throughput, latency, request cost, or throttling | The container shares one host; no measurement here is a managed-service figure. |

## Published fidelity code and qualification limits

The Task 2.8 contract accepts `credential_validation_gap`.
[`infra/profiles/object-store-fidelity.yaml`](../../infra/profiles/object-store-fidelity.yaml)
is the machine-readable form; its `limitations` keys and the answer enum match.
The pagination observation is retained under `coverage_gaps` and is not an accepted answer.

This locally qualified release uses the credential observation only. Codespaces verification
and additional supported-environment review remain deferred; no environment-parity claim is made.

### `credential_validation_gap`

The supplied check exercises credential acceptance for one signed corpus-listing request. It
does not configure or test an IAM identity policy or a bucket policy.

- **Observation.** Signing a `ListObjectsV2` request for the corpus bucket with an *invented*
  access key and secret must return a nonempty listing to pass the check. Retain an actual run
  result against the pinned configuration before claiming that observation is qualified.
- **AWS behavior.** AWS authenticates signed requests using their signing credentials;
  inventing credentials does not establish an AWS identity. Authentication is distinct from
  the permission to perform an operation. See [AWS SigV4](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv.html).
  An unknown access key ID yields `InvalidAccessKeyId` (HTTP 403), not a listing, as documented
  in [Amazon S3 error responses](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/ErrorResponses.html).
- **Scope.** This request, bucket/prefix, and emulator configuration only. A pass does not show
  that policies are never enforced, or establish any other S3 operation's behavior.

## Ungraded coverage gap: `listing_pagination_not_exercised`

This code was withdrawn from the answer enum and retained as a coverage record.
The supplied corpus run does not exercise the adapter's continuation path. That identifies a
limit in the test coverage, not an observed LocalStack/AWS difference.

- **Observation.** The check requires a nonempty result with fewer than 1000 keys,
  `IsTruncated: false`, and no `NextContinuationToken`. It does not force another page.
- **AWS behavior.** `ListObjectsV2` returns at most 1000 keys per response and provides a
  continuation token for a truncated listing. A smaller listing can finish in one response too.
  See the [AWS API reference](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html).
- **Qualification limit.** Both services can produce the observed single-page result. The current
  check therefore does not qualify this code as the divergence required by ADR009-R08.
  It is excluded from the answer enum and remains useful as a limit on the evidence.

## Codes withdrawn from the earlier draft list

Recorded rather than deleted, so the withdrawal is reviewable. None is an accepted answer.

| Withdrawn | Why |
|---|---|
| `policy_enforcement_gap` | Replaced by `credential_validation_gap`: the supplied observation tests credentials, not IAM or bucket-policy enforcement. |
| `distributed_consistency_difference` | The claim it rested on is false. Amazon S3 has provided strong read-after-write consistency for PUT and DELETE, **including for list operations**, since December 2020. Locally, writing an object and immediately reading and listing it also succeeds, so there is no observed divergence to describe. |
| `upload_part_handling_divergence` | No code here can reach it. `S3ObjectStore.write` calls `PutObject` with a whole body, and the adapter exposes no create-multipart, upload-part, or complete-multipart path. A check asserts that, so the reason cannot quietly stop being true. |

A divergence no code here can reach is a difference between the emulator and AWS, but it is not
a limitation *of this system*. A divergence whose premise is untrue is not a limitation at all.

Object contents are deliberately **not persisted** between runs. The initializer re-uploads the
supplied artifacts on every start, so no state accumulates and no run depends on a previous one.

## Credentials

The values in `compose.yaml` are LocalStack development strings. They are not secrets, they grant
nothing outside the local Compose network, and they must never be replaced with a real account
credential in this repository. A managed deployment supplies credentials through its own protected
configuration, never through a file in a student repository.
