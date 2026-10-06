# SecretProvider fidelity

The active adapter is `LocalStackSecretProvider` in `src/adapters/secrets/localstack.py`, behind
the `SecretProvider` port, against the Secrets Manager service of the `localstack` container
(`compose.yaml` enables it beside S3 and SQS; it listens on the same edge endpoint with the same
development credentials). The initializer creates one secret on every start and leaves it alone
when it already exists.

## The secret

| Item | Value |
|---|---|
| Name | `coldline/worker/model-provider-key` (`PROVIDER_KEY_SECRET_NAME` in `src/adapters/secrets/`) |
| First version | The value the opening checkpoint carries as the string default of `WorkerSettings.model_provider_key` in `src/worker/config.py`. The initializer writes it once, when the secret does not exist; Step 2 of the Task replaces it |
| Later versions | Whatever `poe secret-replace` generates: a random key in the Coldline provider-key format (`cpk_` and 32 hex characters, the format the supplied Gitleaks rule matches, so a replaced key that ever reaches a file is a finding), stored as the new current version. The previous current version becomes the previous version |
| What a version shows | Its id (the store's identifier) and a fingerprint: the first twelve hex characters of the value's SHA-256. No command, test, log or record prints a value |

## The call form

```python
from adapters.secrets import PROVIDER_KEY_SECRET_NAME, secret_provider

key = await secret_provider(settings).read(PROVIDER_KEY_SECRET_NAME)
```

`secret_provider(settings)` builds the adapter from the LocalStack endpoint and credentials the
worker's settings already carry for the queue (`s3_endpoint`, `s3_region`, `s3_access_key_id`,
`s3_secret_access_key`), so a settings module needs no new environment variable to reach the
store. `read` is asynchronous, as every port method is. `from ports import SecretProvider` is
the port, for an annotation.

## Read timing

`read(name)` returns the **current** version on every call. The adapter keeps no cache and no
time to live, and the Task asks the worker to call it each time it needs the key, not once when
the settings load, for one reason: the model emulator accepts only the current version of the
key. A worker that read the value once and kept it would be refused the moment the key is
replaced, and would need a restart to recover; the Task's Step 2 check (`poe secret-replace`,
then a scenario, then `poe provider-auth-check`) is what shows the difference.

## What the emulator does with the key

The worker presents the key with every request (`src/worker/config.py`'s `provider_key` is
awaited per request by the client in `src/adapters/model/deterministic.py`). The emulator
compares it with the current version in the store and refuses anything else, an earlier
version included, as a terminal provider failure: the exception ends `FAILED` with
`model_provider_terminal_failure`, and nothing is retried. It records the outcome, the version
id it matched and a fingerprint in a file inside the worker container
(`COLDLINE_PROVIDER_AUTH_RECORD`); `poe provider-auth-check` prints it. See
[ModelProvider fidelity](ModelProvider.md).

## The tools

| Command | What it prints |
|---|---|
| `poe secret-status` | The current version's id and fingerprint, the previous version's when there is one, and how many versions the store holds |
| `poe secret-replace` | Generates a new value, stores it as the current version, and prints the new version's id and fingerprint and the id the previous version now has |
| `poe provider-auth-check` | The version id and fingerprint the worker last authenticated with, from the record in the worker container, and a refusal when the most recent attempt was one |
| `poe secret-check-old` | Reads the previous version from the store, asks the emulator's key check to authenticate it, and reports that it was rejected (exit 0) or, which must not happen, accepted (exit 1) |

`poe verify` runs the replacement check itself (a new version, a scenario, the record, the
previous version refused). When it finishes, it stores the value that was current before its
own replacement as a new current version again, so a worker that reads the key per use, and a
worker that still carries the opening literal, both work afterwards; the version ids you
recorded by hand in Step 2 stay what they were.

## What the local store shows, and what it does not

It shows that the worker reads the current version of one secret through one adapter on each
use, that a replaced value takes effect without a restart, and that an earlier version is
refused. It does not show how AWS Secrets Manager, IAM, or KMS would decide who may read the
secret, how the value is encrypted at rest, how rotation would be scheduled or driven by an
event, how a replica or a cross-account read would behave, or how an audit trail of secret
reads would be kept: LocalStack records no such trail, and nothing here reads one. Persistence
is off for the `localstack` container, so `poe reset` followed by `poe start` gives a store that
holds the first version again; `poe stop` keeps nothing either.
