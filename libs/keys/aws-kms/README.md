# @qauth-labs/keys-aws-kms

An optional KEK provider that keeps QAuth's key-encryption key (KEK) in AWS KMS
([ADR-019 Decision 9](../../../docs/adr/019-deployment-topology-and-trust-boundaries.md), #577).

QAuth stores every realm key envelope-encrypted: a random data key encrypts the key material, and
the KEK wraps the data key ([`@qauth-labs/server-keys`](../../server/keys/README.md)). With this
provider the KEK is a symmetric encryption key in KMS and never leaves it: QAuth sends a data key
to KMS `Encrypt` to wrap it and to KMS `Decrypt` to unwrap it. Signing stays in QAuth's signer,
because KMS support for EdDSA and ML-DSA varies.

The auth server does not depend on this package. `KEK_PROVIDER=aws-kms` makes the signer import
it at boot; any other value never loads it. See [Installing](#installing).

## Settings

| Variable             | Meaning                                                                                                                                                    |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `KEK_PROVIDER`       | `aws-kms` selects this provider.                                                                                                                           |
| `KEK_AWS_KMS_KEY_ID` | Required. The **key ARN** of a symmetric encryption KMS key, for example `arn:aws:kms:eu-central-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab`. |
| `KEK_AWS_REGION`     | Optional. The key's region. The ARN names it, so when set it must agree.                                                                                   |

The boot stops, naming the variable, when:

- `KEK_AWS_KMS_KEY_ID` is missing, or is a key ID, an alias name or an alias ARN. An alias can be
  moved to another key, which would change the KEK without a configuration change, and only the ARN
  tells QAuth, without a call to KMS, which key a stored row names.
- `KEK_AWS_REGION` is not the region of the ARN.
- Any other `KEK_AWS_*` variable is set. QAuth settings hold no credentials (below), so a variable
  such as `KEK_AWS_SECRET_ACCESS_KEY` is a mistake. The error names the variable, never its value.

`KEK`, `KEK_PATH`, `KEK_PREVIOUS` and `KEK_PREVIOUS_PATH` belong to the default provider; this one
warns when they are set and ignores them.

Creating the provider makes no KMS call, so a KMS outage does not stop the boot. The first wrap or
unwrap is the first call.

## Credentials

The KMS client uses the default AWS credential chain of the AWS SDK for JavaScript: the `AWS_*`
variables, `AWS_PROFILE` and the shared files, web identity (an EKS service account), and the
container or instance role. QAuth settings accept no static keys. Prefer a role: an ECS task
role, an EKS service account role or an EC2 instance profile, so no long-lived key exists.

The SDK also reads its own endpoint settings, such as `AWS_ENDPOINT_URL_KMS` and
`AWS_USE_FIPS_ENDPOINT`. A VPC endpoint for KMS with private DNS needs neither.

## The KMS key

Create a symmetric encryption key and turn on automatic rotation:

```console
aws kms create-key --key-spec SYMMETRIC_DEFAULT --key-usage ENCRYPT_DECRYPT \
  --description "QAuth key-encryption key"
aws kms enable-key-rotation --key-id <key ID>
```

A KMS key rotation keeps the key ARN and keeps the old key material for `Decrypt`, so stored keys
keep opening. Each row's `kekRef` records the key material that wrapped it, so the KEK rotation of
#545 can find and re-wrap rows wrapped before a rotation.

Choose the provider and the key before the first boot that stores keys. A row wrapped under one
KEK opens only under that KEK: a deployment that changes `KEK_AWS_KMS_KEY_ID` to another key, or
moves from `KEK_PROVIDER=local` to `aws-kms`, cannot open its stored keys (`KEK_UNKNOWN_REF`) until
the KEK rotation (#545) can re-wrap them.

## IAM policy for the signer role

Only the signer role calls KMS. In a single deployment the auth server is the signer; give its
role, and no other, this policy. It needs exactly two actions on the one key:

| Action        | Used for                                                                                        |
| ------------- | ----------------------------------------------------------------------------------------------- |
| `kms:Encrypt` | Wrapping a new key's data key: the key import at boot, `auth-server:keys:create`, a rotation.   |
| `kms:Decrypt` | Unwrapping a key the first time a process uses it, and checking every wrap before it is stored. |

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "QAuthSignerWrapsDataKeys",
      "Effect": "Allow",
      "Action": ["kms:Encrypt", "kms:Decrypt"],
      "Resource": "arn:aws:kms:eu-central-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
      "Condition": {
        "ForAllValues:StringEquals": {
          "kms:EncryptionContextKeys": [
            "qauth:aad-version",
            "qauth:realm-id",
            "qauth:purpose",
            "qauth:scope-id",
            "qauth:kid",
            "qauth:algorithm"
          ]
        },
        "Null": { "kms:EncryptionContext:qauth:realm-id": "false" }
      }
    }
  ]
}
```

- The two conditions let the role use the key only with QAuth's encryption context: no key outside
  that list, and a realm always named. Neither is needed for QAuth to work; both narrow what a
  stolen role credential can do with the key.
- The role needs nothing else: no `kms:GenerateDataKey*`, `kms:ReEncrypt*`, `kms:CreateGrant` or
  `kms:DescribeKey`.
- The key policy must let IAM policies grant access to the key, as the default key policy does, or
  name the role itself.
- `kms:Encrypt` without `kms:Decrypt` is refused at the first wrap, with `KEK_ACCESS_DENIED`: every
  wrap is decrypted once before the key is stored, so a key QAuth could not open is never stored.

### What KMS sees

Each data key is bound to the key it protects through the encryption context, one pair per field
of the key's associated data:

| Context key         | Value                                    |
| ------------------- | ---------------------------------------- |
| `qauth:aad-version` | the associated-data format, `1`          |
| `qauth:realm-id`    | the realm's ID                           |
| `qauth:purpose`     | the key purpose, such as `token_signing` |
| `qauth:scope-id`    | the scope, only for a scoped key         |
| `qauth:kid`         | the key's `kid`                          |
| `qauth:algorithm`   | the key's algorithm, such as `EdDSA`     |

A wrapped data key copied to another realm, purpose, scope, `kid` or algorithm does not open: KMS
refuses the other context. CloudTrail logs the context of every call, so it shows which realm and
key each `Decrypt` opened. The values are identifiers, not secrets. `health()` wraps a random
probe under realm `qauth-kek-health` and purpose `kek_health`; a policy that restricts the values,
not only the keys, must allow those too.

## When KMS is unavailable

Every KMS call is tried at most 3 times, with exponential backoff and jitter. A connection that
does not open within 2 s, or a request that gets no answer within 3 s, counts as a failed attempt,
so one call gives up within about 20 s, backoff included. Throttling, timeouts and KMS server faults are
retried; a refusal is not.

During a KMS outage:

- **Keys already in memory keep working.** The signer unwraps a key the first time it needs it and
  keeps it in memory (up to 256 keys by default), so a running node keeps signing and decrypting
  with the keys it has loaded. Public keys, the JWKS and token verification need no KMS call.
- **Loading a key that is not in memory fails**: the first use of a key after a restart, a key
  created since, or one pushed out of the cache. The operation that needs it fails with a server
  error: the signer's error is `KEK_UNAVAILABLE`, with the KMS error as its cause. The next call
  tries KMS again.
- **Creating a key fails**: the key import at boot (the boot stops when a key variable must be
  imported or a standard key created), `auth-server:keys:create`, and a rotation.
- **A node that restarts boots but holds no keys** until KMS answers again, since nothing is
  loaded yet. Avoid restarting signer nodes during an outage.

A refused call (`KEK_ACCESS_DENIED`) means an operator has to act: the policy, the credentials,
or the key's state (disabled or pending deletion). A ciphertext KMS refuses
(`KEY_DECRYPTION_FAILED`) is a row that does not belong to that key and context; it is never
retried.

## Installing

The auth-server image does not contain this package. Add it where the auth server resolves
packages: `node_modules/@qauth-labs/keys-aws-kms` beside the deployed server. For example, in a
copy of `apps/auth-server/Dockerfile`, deploy the package in the builder stage and copy it into the
runner stage:

```dockerfile
# builder stage, after the auth server's `pnpm deploy`
RUN --mount=type=cache,id=pnpm,target=/pnpm/store \
    pnpm --filter @qauth-labs/keys-aws-kms deploy --prod \
    --store-dir /pnpm/store /kek-adapter

# runner stage, after `COPY --from=builder ... /deploy ./`
COPY --from=builder --chown=nodejs:nodejs /kek-adapter ./node_modules/@qauth-labs/keys-aws-kms
```

Then set `KEK_PROVIDER=aws-kms` and `KEK_AWS_KMS_KEY_ID`. Without the package,
`KEK_PROVIDER=aws-kms` stops the boot with "KEK_PROVIDER names a KEK provider whose package is not
installed".

## Tests

- `pnpm exec nx run keys-aws-kms:test` runs the KEK provider contract against a KMS test double
  (`src/testing/kms-double.ts`), directly and through the real SDK client on a local server that
  speaks the KMS protocol, plus the settings, the error mapping, the attempt limit and the
  timeouts.
- `KMS_TEST_KEY_ARN=<key ARN> pnpm exec nx run keys-aws-kms:test-kms` runs the contract against a
  real KMS key, with credentials from the default chain. It is opt-in and manual: CI does not run
  it, and without `KMS_TEST_KEY_ARN` it is skipped.
