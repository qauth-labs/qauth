# @qauth-labs/keys-vault

An optional KEK provider that keeps QAuth's key-encryption key (KEK) in a Vault Transit key
([ADR-019 Decision 9](../../../docs/adr/019-deployment-topology-and-trust-boundaries.md), #578).

QAuth stores every realm key envelope-encrypted: a random data key encrypts the key material, and
the KEK wraps the data key ([`@qauth-labs/server-keys`](../../server/keys/README.md)). With this
provider the KEK is a key of Vault's Transit secrets engine and never leaves Vault: QAuth sends a
data key to Transit `encrypt` to wrap it and to Transit `decrypt` to unwrap it. Signing stays in
QAuth's signer; Vault only wraps data keys.

The auth server does not depend on this package. `KEK_PROVIDER=vault` makes the signer import it
at boot; any other value never loads it. See [Installing](#installing).

## Settings

| Variable                   | Meaning                                                                                                                           |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `KEK_PROVIDER`             | `vault` selects this provider.                                                                                                    |
| `KEK_VAULT_ADDR`           | Required. The `https://` origin of the Vault server, for example `https://vault.internal:8200`. No path; plain `http` is refused. |
| `KEK_VAULT_TRANSIT_KEY`    | Required. The name of the Transit key that is the KEK, for example `qauth-kek`.                                                   |
| `KEK_VAULT_TRANSIT_MOUNT`  | Optional. The path the Transit engine is mounted at. Default `transit`.                                                           |
| `KEK_VAULT_NAMESPACE`      | Optional. The Vault namespace that holds the Transit mount and the auth method, sent as `X-Vault-Namespace`.                      |
| `KEK_VAULT_CA_CERT_FILE`   | Optional. A PEM file of the CA certificates that sign Vault's TLS certificate. When set, Vault calls trust only these.            |
| `KEK_VAULT_TOKEN_FILE`     | Token login: a file holding a Vault token, such as the sink of a Vault Agent.                                                     |
| `KEK_VAULT_ROLE_ID`        | AppRole login: the role ID.                                                                                                       |
| `KEK_VAULT_SECRET_ID_FILE` | AppRole login: a file holding a secret ID of that role.                                                                           |
| `KEK_VAULT_APPROLE_MOUNT`  | Optional, AppRole only. The path the AppRole auth method is mounted at. Default `approle`.                                        |

Set either `KEK_VAULT_TOKEN_FILE`, or `KEK_VAULT_ROLE_ID` with `KEK_VAULT_SECRET_ID_FILE`; not both.

The boot stops, naming the variable, when:

- `KEK_VAULT_ADDR` or `KEK_VAULT_TRANSIT_KEY` is missing, the address is not `https://`, has a
  path, or holds a user name or password.
- No login is set, both are, or the token or secret ID file is missing, empty, not a regular
  file, or holds more than one value.
- Any other `KEK_VAULT_*` variable is set. A token or secret ID is never read from a variable,
  where it would show in the process environment: `KEK_VAULT_TOKEN` and `KEK_VAULT_SECRET_ID`
  are refused with a pointer to the `_FILE` variable. The error names the variable, never its
  value.

The boot warns when group or others can read the token or secret ID file: restrict it with
`chmod 600`. `KEK`, `KEK_PATH`, `KEK_PREVIOUS` and `KEK_PREVIOUS_PATH` belong to the default
provider; this one warns when they are set and ignores them.

Creating the provider makes no Vault call, so a Vault outage does not stop the boot. The first
wrap or unwrap logs in.

## The Transit key

Enable the Transit engine and create a **derived** AES-256-GCM key:

```console
vault secrets enable transit
vault write -f transit/keys/qauth-kek type=aes256-gcm96 derived=true
```

`derived=true` is required. QAuth sends each data key's associated data (its realm, purpose,
scope, `kid` and algorithm) as the Transit `context`, and a derived key encrypts each context under
its own key, so a wrapped data key copied to another realm or key does not open. Vault ignores the
context of a key that is not derived, without an error, which would drop that binding; the
provider reads the key's settings before its first wrap or unwrap, and again every 15 minutes
while it is used, and refuses such a key with `KEK_ACCESS_DENIED`. `chacha20-poly1305` is accepted
too. Every wrap is also decrypted once more under another context, which Vault must refuse, so
each stored row proves the key derived, even between two checks.

A key with `exportable=true` or `allow_plaintext_backup=true` lets the KEK leave Vault, and one
with `deletion_allowed=true` can be deleted with every data key it wraps. Such a key wraps nothing:
each wrap, and so `health()`, fails with `KEK_ACCESS_DENIED`. Unwraps go on, with a warning at each
key check, because Vault cannot switch the first two off again and refusing unwraps would lock the
stored keys out of the one key that opens them: move the KEK to a new derived key and re-wrap the
rows with the KEK rotation (#545), or set `deletion_allowed=false`. A key imported into Transit
(`imported_key=true`) only logs a warning: its material exists outside Vault too, so keep that copy
as safe as the KEK.

Choose the provider and the key before the first boot that stores keys. A row wrapped under one
KEK opens only under that KEK: a deployment that changes `KEK_VAULT_TRANSIT_KEY`, the mount or the
namespace, or moves from `KEK_PROVIDER=local` to `vault`, cannot open its stored keys
(`KEK_UNKNOWN_REF`) until the KEK rotation (#545) can re-wrap them.

### Rotating the Transit key

```console
vault write -f transit/keys/qauth-kek/rotate
```

A rotation adds a key version. New wraps use the latest version, and every older version still
decrypts. Each row's `kekRef` names the key and the version that wrapped it:

```text
vault:transit/keys/qauth-kek#v2
vault:<namespace>/<mount>/keys/<name>#v<version>
```

so the KEK rotation of #545 finds the rows wrapped before a Transit rotation and re-wraps them to
the latest version. Raise the key's `min_decryption_version` only after that: a row whose version
is below it no longer opens (`KEK_UNKNOWN_REF`). Transit's `auto_rotate_period` rotates the key on
a schedule the same way. The key check reads every version from `min_decryption_version` on, and
reads at most 1 MiB, some tens of thousands of versions: with a short `auto_rotate_period`, raise
`min_decryption_version` once the rows are re-wrapped, so the key's settings stay small.

## Vault policy for the signer role

Only the signer role talks to Vault. In a single deployment the auth server is the signer; give its
token or AppRole, and no other, this policy. For the key `qauth-kek` on the mount `transit` it
needs exactly these paths:

```hcl
# Wrap a data key: a new key's import or creation at boot, `auth-server:keys:create`,
# a rotation, and health checks.
path "transit/encrypt/qauth-kek" {
  capabilities = ["update"]
}

# Unwrap a data key the first time a process uses it, and check every wrap before
# it is stored.
path "transit/decrypt/qauth-kek" {
  capabilities = ["update"]
}

# Read the key's settings before the first wrap or unwrap and every 15 minutes after, to
# refuse a key that is not derived or that can leave Vault.
path "transit/keys/qauth-kek" {
  capabilities = ["read"]
}

# Read the token's TTL, renew it, and revoke an AppRole token the provider no longer
# uses. Vault's default policy grants all three; list them so a token created without
# the default policy works too.
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "auth/token/revoke-self" {
  capabilities = ["update"]
}
```

```console
vault policy write qauth-signer qauth-signer.hcl
```

- **No `create`.** Transit's `encrypt` creates a missing key when the policy grants `create` on
  its path. The provider never needs that: it reads the key's settings first and refuses a
  missing key with `KEK_ACCESS_DENIED`. Leaving `create` out keeps the signer's token from
  making keys at all.
- The role needs nothing else: no `transit/rewrap`, `transit/datakey`, `transit/export`,
  `transit/backup`, `transit/keys/<name>/rotate` or `transit/keys/<name>/config`. Rotating and
  configuring the key is an operator's task, under another identity.
- An AppRole login needs no policy: `auth/approle/login` is open by design.
- A token that may encrypt but not decrypt is refused at the first wrap, with
  `KEK_ACCESS_DENIED`: every wrap is decrypted once before the key is stored, so a key QAuth could
  not open is never stored.

With a mount other than `transit` or a namespace, put the mount in each Transit path:
`kek/transit/encrypt/qauth-kek` for `KEK_VAULT_TRANSIT_MOUNT=kek/transit`. A namespace's policy
is written inside that namespace (`vault policy write -namespace=team-a ...`) with the same paths.

## Logging in

### A token from a file

`KEK_VAULT_TOKEN_FILE` names a file that holds one Vault token. The provider reads it at each
login and asks Vault for its TTL (`auth/token/lookup-self`). Once two thirds of the TTL have
passed it renews the token (`auth/token/renew-self`), in the background, so an idle signer keeps a
valid token. When a renewal no longer extends the token, because it reached its maximum TTL, the
provider reads the file once more; after that it reads it again at its next use once it is about to
expire, or after Vault refuses it. A Vault Agent with a file sink, or an orchestrator, should write
a fresh token there before the old one expires. A token that does not expire is never renewed.

A token with the root policy, or one that never expires, logs a warning at the login that brings
it. A Vault dev server's root token works, but in production give the signer a token with only
the policy above and a TTL.

```console
vault token create -policy=qauth-signer -period=24h -orphan
```

A periodic token is renewed forever as long as the signer runs. Prefer AppRole or a Vault Agent
over a long-lived token written by hand.

### AppRole

```console
vault auth enable approle
vault write auth/approle/role/qauth-signer token_policies=qauth-signer \
  token_ttl=1h token_max_ttl=24h secret_id_num_uses=0
vault read -field=role_id auth/approle/role/qauth-signer/role-id
vault write -f -field=secret_id auth/approle/role/qauth-signer/secret-id > /run/secrets/qauth-secret-id
```

The provider logs in with the role ID and the secret ID, read from `KEK_VAULT_SECRET_ID_FILE` at
each login, renews the token as above, and logs in again before the token reaches its maximum TTL.
It then revokes the token it replaced (`auth/token/revoke-self`), and the token it holds when the
server shuts down; a revocation that fails is ignored, and that token expires at its TTL.
The secret ID is used for every login, so it must allow unlimited uses (`secret_id_num_uses=0`)
and outlive the signer process, or be rewritten in the file before it expires. A login whose
answer was lost is not sent again, so it does not spend uses, but a limited secret ID still runs
out. Bind it to the signer's addresses with `secret_id_bound_cidrs` where you can.

### Refused tokens

When Vault refuses a call with 403, the provider asks Vault whether the token still works
(`auth/token/lookup-self`). If it does, the policy refused the call: the token is kept and the call
fails with `KEK_ACCESS_DENIED`, so a path the policy denies never mints new tokens. If it does not,
the provider logs in again once and repeats the call. With AppRole that replaces a revoked token. A
revoked token in a token file is refused again: the call fails with `KEK_ACCESS_DENIED`, nothing
falls back to another credential, and the operation that needed the key fails closed. A boot step
that has to wrap a key, such as importing a key variable the store does not hold yet, stops the
boot.

A policy without Vault's default policy may deny `lookup-self` itself. The provider finds that out
at the first refusal: when Vault also refuses `lookup-self` to the token fresh from the new AppRole
login, every later 403 counts as the policy's, so a denied path does not mint a token per call. A
revoked token is then replaced only when its renewal fails or it expires. Keep
`auth/token/lookup-self` in the policy, as above.

Tokens and secret IDs are never logged and never appear in an error or in `health()`. Errors carry
the HTTP status, the Vault operation and Vault's own messages.

## TLS

Every call goes to `KEK_VAULT_ADDR` over HTTPS, with certificate and host name checks that cannot
be turned off. Set `KEK_VAULT_CA_CERT_FILE` when a private CA signs Vault's certificate. A
certificate the provider does not trust (another CA, expired, or for another host name) fails the
call with `KEK_ACCESS_DENIED` and is not retried. Redirects
are not followed, because a request carries the token: a standby node that redirects instead of
forwarding fails the attempt. The address is an operator setting, never user input, so the egress
client that guards user-supplied URLs is not involved.

## When Vault is unavailable

Every Vault call is tried at most 3 times, with exponential backoff and jitter. A request that gets
no answer within 5 s, connecting included, counts as a failed attempt, so one call gives up within
about 16 s. Connection failures, timeouts, `412`, `429` and server faults (a sealed Vault answers
`503`) are retried; a refusal is not. An AppRole login is repeated only when Vault cannot have
served it: a connection that never opened, `429` or `503`. A wrap makes up to four calls (the key
check, `encrypt` and two `decrypt`s), plus a login, so against a Vault that stops answering one
wrap can take about a minute before it fails.

During a Vault outage:

- **Keys already in memory keep working.** The signer unwraps a key the first time it needs it and
  keeps it in memory (up to 256 keys by default), so a running node keeps signing and decrypting
  with the keys it has loaded. Public keys, the JWKS and token verification need no Vault call.
- **Loading a key that is not in memory fails**: the first use of a key after a restart, a key
  created since, or one pushed out of the cache. The signer's error is `KEK_UNAVAILABLE`, with the
  Vault error as its cause. The next call tries Vault again.
- **Creating a key fails**: the key import at boot (the boot stops when a key variable must be
  imported or a standard key created), `auth-server:keys:create`, and a rotation.
- **Token renewal is tried again** while the token lasts. A token that expires during the outage
  is replaced by a login when Vault answers again (AppRole, or a token file that was rewritten).

`KEK_ACCESS_DENIED` means an operator has to act: the policy, the token or secret ID, the key
(missing or not derived, or for a wrap, able to leave Vault or be deleted), or Vault's TLS
certificate. `KEY_DECRYPTION_FAILED` is a row that does not belong to that key and
context; it is never retried.

## Installing

The auth-server image does not contain this package. Add it where the auth server resolves
packages: `node_modules/@qauth-labs/keys-vault` beside the deployed server. For example, in a copy
of `apps/auth-server/Dockerfile`, deploy the package in the builder stage and copy it into the
runner stage:

```dockerfile
# builder stage, after the auth server's `pnpm deploy`
RUN --mount=type=cache,id=pnpm,target=/pnpm/store \
    pnpm --filter @qauth-labs/keys-vault deploy --prod \
    --store-dir /pnpm/store /kek-adapter

# runner stage, after `COPY --from=builder ... /deploy ./`
COPY --from=builder --chown=nodejs:nodejs /kek-adapter ./node_modules/@qauth-labs/keys-vault
```

Then set `KEK_PROVIDER=vault` and the settings above. Without the package, `KEK_PROVIDER=vault`
stops the boot with "KEK_PROVIDER names a KEK provider whose package is not installed". The
package has no runtime dependency outside QAuth's own libraries: it speaks to Vault with Node's
`https` module.

## Tests

- `pnpm exec nx run keys-vault:test` runs the KEK provider contract against a Vault test double
  (`src/testing/vault-double.ts`), logging in with a token file and with AppRole, plus the
  settings, the error mapping, the retry limit, token renewal on a manual clock and the HTTPS
  transport against a local TLS server.
- `pnpm exec nx run keys-vault:test-integration` runs the contract against a Vault dev server in a
  container, with the policy above applied as written, plus a wrong context, a key that is not
  derived, a Transit key rotation and the re-wrap of a stored key to the new version, token
  renewal, a call after the AppRole token's maximum TTL and a revoked token. It needs Docker; CI's integration
  job runs it when the package is affected.
