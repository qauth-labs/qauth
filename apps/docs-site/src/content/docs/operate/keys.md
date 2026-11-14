---
title: Keys
description: How QAuth keeps its keys in each realm's encrypted key store behind a KEK — what the store holds, how keys are imported, replaced and added with auth-server:keys:create, a provider-issued client-assertion key such as Sign in with Apple's, the rotation windows, and the JWKS rule for relying parties.
sidebar:
  order: 2
lastVerified: '2026-11-12'
---

Every realm keeps its keys in its own encrypted key store in Postgres, one set
per purpose
([ADR-019 Decision 9](/reference/records/adr/019-deployment-topology-and-trust-boundaries/)).
A key-encryption key (KEK) wraps every stored key. Only the signer role holds
the KEK and the private keys. This page says what the store holds, how keys
get into it, how they are replaced, and what relying parties do with the
published keys. What QAuth imports is verified against
`libs/server/keys/src/lib/environment-keys.ts`.

QAuth signs tokens with up to three key types:

| Key             | Variable needed?                                              | Signs                                                           |
| --------------- | ------------------------------------------------------------- | --------------------------------------------------------------- |
| EdDSA (Ed25519) | No — generated for a fresh realm                              | Access tokens always; ID tokens when the realm has no RS256 key |
| RS256           | No — generated for a fresh realm; import one to keep yours    | ID tokens, when the realm has one (access tokens stay EdDSA)    |
| ML-DSA-65 seed  | No — generated with the Ed25519 key when hybrid signing is on | The post-quantum half of a hybrid access token                  |

## The key store

The store has two tables. `realm_keys` holds each key's private material,
wrapped under the KEK; only the signer reads it. `realm_public_keys` holds the
public halves, which every process reads to verify tokens and to serve the
JWKS, without a KEK.

A key has one of four statuses:

| Status        | Signs | Verifies | In the JWKS                   |
| ------------- | ----- | -------- | ----------------------------- |
| `next`        | No    | No       | Yes, before it signs          |
| `active`      | Yes   | Yes      | Yes                           |
| `retired`     | No    | Yes      | Yes, until its retention ends |
| `compromised` | No    | No       | No                            |

A realm has one active key per purpose and algorithm. A fresh default realm
gets these keys at its first boot:

| Purpose         | Algorithm | When                   | Published at                                     |
| --------------- | --------- | ---------------------- | ------------------------------------------------ |
| `token_signing` | EdDSA     | Always                 | `/.well-known/jwks.json`                         |
| `token_signing` | RS256     | A fresh realm only     | `/.well-known/jwks.json`                         |
| `token_signing` | ML-DSA-65 | With hybrid signing on | `/.well-known/jwks.json`                         |
| `event_signing` | EdDSA     | Always                 | `/ssf/jwks.json`, for the SSF transmitter's SETs |
| `cookie_hmac`   | HS256     | Always                 | Never: it signs the browser cookies              |
| `data_at_rest`  | A256GCM   | Always                 | Never: it encrypts the realm's secrets           |

The OID4VP request-signing key exists only when the key boot step imports it
from `OID4VP_VERIFIER_SIGNING_KEY`. A key a realm lacks, such as an RS256 key
for an upgraded realm, is added with
[`auth-server:keys:create`](#adding-a-key-auth-serverkeyscreate).

## The KEK

Every stored key is wrapped with the KEK. `KEK_PROVIDER` picks where the KEK
lives. The default, `local`, reads `KEK` or `KEK_PATH`.

**Make one.** The KEK is the standard base64 of exactly 32 random bytes:

```bash
mkdir -p -m 700 ~/qauth-secrets
(umask 077 && openssl rand -base64 32 > ~/qauth-secrets/qauth-kek)
```

Set `KEK_PATH` to the file, or `KEK` to its content. `KEK_PATH` wins when both
are set. The server warns when group or others can read or write the file.
Hex and base64url values are refused.

`umask 077` keeps the file its owner's alone from the start. Keep it in a
directory of its own, outside any git checkout and apart from the database
backups. In a container the server reads the file as its own user, uid `1001`
in QAuth's image. A Compose secret from a file is the host file, with its
owner and mode, so give it to that user:
`sudo chown 1001 ~/qauth-secrets/qauth-kek`.

**Where it goes.** Only a process whose `SERVICE_ROLES` holds `signer`, or is
`all`, receives the KEK. Any other process refuses to boot when it finds one
([Service roles](/operate/service-roles/#keys-stay-on-the-signer)).

**Keep it apart from the database.** The database, and every backup of it,
holds the stored keys, wrapped. Whoever has a backup and the KEK has every
key. Never store the KEK in the database backup. Back it up on its own, for
example in a secret manager and once more offline. Restoring a backup needs the
KEK it was taken under.

**Losing it loses every stored key.** Nothing opens a stored key without the
KEK that wrapped it, and nothing recovers one. The signing keys, the cookie
key and the data-at-rest key are lost, and with the last one the realm's
encrypted secrets, such as the mail password. The server cannot sign a token
or a cookie any more, and `/ready` fails its `kek` check.

**Without a KEK.** `NODE_ENV=production` refuses to start without one, and
refuses the published development KEK. Outside production the server falls
back to that development KEK and warns. It refuses to import a key variable
under it in every environment: the development KEK would protect nothing.

**A previous KEK.** `KEK_PREVIOUS` (or `KEK_PREVIOUS_PATH`) holds the KEK in
use before a change of KEK. Keys wrapped under it still open; every new key is
wrapped under `KEK`. Nothing re-wraps a stored key yet: the KEK rotation
([#545](https://github.com/qauth-labs/qauth/issues/545)) will. Until then a
key wrapped under the previous KEK opens only while `KEK_PREVIOUS` holds it.

**A key management service.** An optional adapter package can keep the KEK
in a key service instead. Two ship. For example, `KEK_PROVIDER=aws-kms` with
`@qauth-labs/keys-aws-kms`, which sends data keys to AWS KMS to be wrapped and
unwrapped, while signing stays in QAuth. Its
[guide](https://github.com/qauth-labs/qauth/blob/main/libs/keys/aws-kms/README.md)
gives the settings, the IAM policy of the signer role and what happens when
KMS is unavailable. `KEK_PROVIDER=vault` with `@qauth-labs/keys-vault` keeps it
in a Vault Transit key, logging in with a token file or AppRole; its
[guide](https://github.com/qauth-labs/qauth/blob/main/libs/keys/vault/README.md)
gives the settings, the Vault policy of the signer role and the token renewal.
The auth-server image holds neither package: install the one you need into
your image. Choose the provider before the first boot that stores keys: a key
wrapped under one KEK does not open under another.

## The key boot step

At every boot the server runs a key step for the default realm, on every
process that holds the signer, after the realm's own step and under an
advisory lock, so nodes that start together do it once:

1. It imports each key variable the realm's store does not hold yet:
   `JWT_PRIVATE_KEY` as the Ed25519 signing key, `JWT_RS256_PRIVATE_KEY` as the
   RS256 one, `JWT_MLDSA_PRIVATE_KEY` (with `HYBRID_SIGNING_ENABLED` on) as the
   ML-DSA-65 key of the hybrid pair, `SESSION_COOKIE_SECRET`, when you set it,
   as the cookie key, and `OID4VP_VERIFIER_SIGNING_KEY` as the wallet
   verifier's request-signing key. A `_PATH` variable counts as its variable.
   A key variable that holds a key the store lacks replaces the store's active
   key of its kind (see [Replacing a signing key](#replacing-a-signing-key) and
   [Replacing the cookie key](#replacing-the-cookie-key)).
2. It creates the keys the realm still lacks: the event-signing and
   data-at-rest keys, and the cookie key when `SESSION_COOKIE_SECRET` is unset.
   A realm that neither holds nor imports a signing key gets an Ed25519 and an
   RS256 signing key (and, with hybrid signing on, the ML-DSA-65 key of the
   pair), so a fresh deployment needs no key variable at all.
3. It logs `realm keys ready`, naming each key it imported or created by
   purpose, algorithm and `kid`.
4. It warns once for each key variable that is still set, naming it.

Each imported key keeps `JWT_RS256_KID` or `JWT_MLDSA_KID` as its `kid` when
set, and otherwise gets the RFC 7638 thumbprint of its public key. The cookie
key gets a random `kid`. The keys themselves do not change, so tokens signed
before the upgrade still verify.

The boot stops, and names the variable, when:

- a key must be imported and no KEK is set;
- `JWT_PUBLIC_KEY` or `JWT_RS256_PUBLIC_KEY` is not the public half of its
  private key;
- `JWT_RS256_PRIVATE_KEY` is shorter than 2048 bits (RFC 7518 §3.3);
- a new key comes with a `JWT_RS256_KID` or `JWT_MLDSA_KID` that already
  names a stored key: a new key needs a new `kid`;
- with hybrid signing on, only one of `JWT_PRIVATE_KEY` and
  `JWT_MLDSA_PRIVATE_KEY` holds a new key: the two keys of a pair are stored,
  and replaced, together;
- with hybrid signing on, the realm's active Ed25519 signing key has no
  ML-DSA-65 key beside it: tokens would be signed classical-only. Set
  `JWT_PRIVATE_KEY` and `JWT_MLDSA_PRIVATE_KEY` to a new pair, or turn hybrid
  signing off.

A key variable never holds a key another realm stores: the step refuses to
import one, naming the variable, so a token signed by one realm's key never
verifies as another realm's.

The key variables are read only by this step. Once the store holds a key, the
variable signs nothing, and a new key in it is how you replace the stored one.
The server boots without them. Each boot warns about every one still set:

```text
JWT_PRIVATE_KEY is in the realm's key store, which signs the tokens: the variable is read only at boot, where a new key in it replaces the stored key and unpublishes the old one at once. Remove it unless you may roll back to a release that signs with it.
```

Remove them once you no longer need to roll back to a release that signs with
them. [Remove the key variables](/operate/upgrades/#remove-the-key-variables)
says when, and which public key to keep a little longer. Production refuses
every `SESSION_COOKIE_SECRET` value QAuth's examples published
([Replacing the cookie key](#replacing-the-cookie-key)).

### Tokens are signed through the key store

Every access token, ID token and hybrid token is signed with the keys of the
realm it is issued in, by the signer. The token's `iss` is the realm's issuer,
and its protected header names the key that signed it in `kid` (a hybrid token
also names its ML-DSA-65 key in `pqc_kid`). Each realm publishes its own keys
at its own `/.well-known/jwks.json`, and the server verifies a token only with
the keys of the realm the request is for, so a token one realm issued is
refused by another.

The server picks the key by the token's `kid` and `alg` together, from the
realm's verification set: its active keys, and its retired keys until their
retention ends. A `next` key and a `compromised` key verify nothing. A hybrid
token's ML-DSA-65 key is found the same way, by its `pqc_kid`. Every process
reads a realm's key list again at most every 60 seconds.

A token issued before the upgrade to 0.2 carries no `kid`. It still verifies,
but only against the Ed25519 key that `JWT_PRIVATE_KEY` or `JWT_PUBLIC_KEY`
holds, never against a key the store generated. Keep one of them set until the
tokens issued before the upgrade have expired (the longest access token
lifetime of any realm, a development client's included): the next release
refuses every token without a `kid`.

If `JWT_ISSUER` ends with a slash, the tokens now name the issuer without it,
as discovery does, while 0.1 named it with the slash. Upgrade such a
deployment all at once rather than node by node: in a mixed fleet each release
refuses the other's access tokens until they expire. A relying party that
compares `iss` with the slashed form must drop the slash.

## Rotation

### The rotation windows

ADR-019 fixes how a scheduled or manual rotation overlaps the old and the new
key, so that a relying party's JWKS cache never meets a token signed by a key
it has not seen, and nobody signs in again:

| When                       | The old key                          | The new key                                     |
| -------------------------- | ------------------------------------ | ----------------------------------------------- |
| 7 days before the rotation | `active`: signs                      | `next`: in the JWKS, signs and verifies nothing |
| The rotation               | `retired`: in the JWKS, verifies     | `active`: signs                                 |
| 14 days after the rotation | Leaves the JWKS and verifies nothing | `active`                                        |

- The next key is published **7 days** before it starts signing.
- A retired key stays published **14 days** after the rotation, and never for
  less than the longest lifetime of a token it signed. An access token lives at
  most a day (`ACCESS_TOKEN_LIFESPAN` is capped at 86400 seconds), so 14 days
  covers every token.
- A key rotates every **90 days**.
- Both keys of a hybrid pair rotate together. The cookie key and the
  data-at-rest key rotate the same way: the new key signs or encrypts, and the
  old one only verifies or decrypts until it is retired.

`KEY_ROTATION_PERIOD_DAYS`, `KEY_PREPUBLISH_DAYS` and
`KEY_RETIRED_RETENTION_DAYS` change the three windows for the whole deployment
(advanced keys of [the configuration](/operate/configuration/)). A period
shorter than the pre-publication window is refused at boot.

### The scheduled rotation

The `key-rotation` job rotates every realm's keys on these windows
([#542](https://github.com/qauth-labs/qauth/issues/542)). It runs every hour on
the nodes of the `signer` role, the only role that holds the KEK, for the token
signing, event signing, cookie, data-at-rest, OID4VP response and agent
wrapping keys of each realm:

- Once the active key has served the period less the pre-publication window
  (day 83 by default), the job creates the `next` key and publishes it, and the
  event `key.next_created` records it.
- Once the period has run and the `next` key has been published for the whole
  window (day 90), the job switches: the `next` key becomes `active` and the
  old key `retired`, and the event `key.rotated` records both. A hybrid pair
  moves together, in one transaction, so the JWKS never shows half of it.
- The retired key stays published and verifying for the retention (until day
  104), and longer when a token, cookie or ciphertext it made may live longer.
- A job that was down past a due date creates the `next` key when it runs
  again and waits the whole window before the switch: a missed run never
  shortens the overlap.

Every process reads a realm's key list at most once a minute, so the switch is
written two refresh intervals ahead (two minutes by default): every process
lists the new key as `active`, and verifies with it, before any signer uses it.
Until that moment the old key signs on.

The job takes the job runner's advisory lock and each realm's key lock, and
plans each step again from what is stored, so many nodes and repeated runs
rotate once. A step and its audit event commit together. A step that fails is
logged and left as it was, and the next run retries it.

How long a retired key is kept:

| Key                                      | Kept after the switch                                                                                          |
| ---------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| Token and event signing, OID4VP response | The retention, at least a day: no access or ID token lives longer (`ACCESS_TOKEN_LIFESPAN` is capped at 86400) |
| Cookie                                   | The retention, or the realm's longest browser session (`sso_max_lifespan` or `SESSION_COOKIE_TTL`) if longer   |
| Data at rest, agent wrapping             | For good: a stored secret has no end, and nothing re-seals it under the new key yet                            |

A cookie key's switch waits, too, until the cookie key before it has left its
retention: a process verifies the cookies of one previous cookie key only.

A key variable such as `JWT_PRIVATE_KEY` or `SESSION_COOKIE_SECRET` that still
holds a key the job has retired changes nothing, and each boot warns about it.
Remove the key variables once the store holds the keys
([Upgrades](/operate/upgrades/#upgrading-from-01-to-02)).

### Manual rotation

A manual rotation will be an admin API security operation
([#544](https://github.com/qauth-labs/qauth/issues/544)): it needs the
`qauth:admin:security` scope and a fresh passkey approval, and it follows the
windows above. In this release the admin API rotates one kind of key only: a
provider plugin's client-assertion key, which the provider issued
([below](#a-provider-issued-client-assertion-key)), and whose switch waits for
no window, since the provider holds the key's public half already. For every other key,
`auth-server:keys:create --status next` publishes a next key, and the scheduled
rotation activates it when it is due: once the active key's period has run and
the next key has been published for the whole window.

### Emergency retirement

An emergency retirement will retire a key that may be compromised as soon as
the retirement is approved, without the overlap
([#551](https://github.com/qauth-labs/qauth/issues/551)):

- the key leaves the JWKS at once, and a new key starts signing;
- its `kid` goes on a denylist that every verifier inside the auth server
  checks, whatever a JWKS cache holds, and introspection answers
  `active: false` for a token it signed;
- every session and refresh-token family issued under the key is revoked, with
  back-channel logout;
- a critical admin event and a security event naming the `kid` go out on every
  event route;
- it needs `qauth:admin:security`, a fresh passkey and the second admin where
  the realm requires one. When no second admin can approve in time, the
  break-glass CLI on a host that holds the database credentials and the KEK
  does it.

None of this is in this release. To cut off a signing key that may be
compromised today, replace it through its variable
([below](#replacing-a-signing-key)) and restart **every** node: the old key
leaves the JWKS and stops verifying at once on a restarted node, and within a
minute on one that keeps running. Tokens it signed stop verifying at QAuth's
endpoints. A relying party stops trusting it once its own JWKS cache expires,
at most 5 minutes later if it follows [the JWKS rule](#what-relying-parties-do-with-the-jwks).
Refresh tokens are not signed, so the replacement does not end them. For a
leaked cookie secret, see [Replacing the cookie key](#replacing-the-cookie-key).

### Replacing a signing key

The scheduled rotation replaces a signing key with an overlap. To replace one
at once, as before the key store, put the new key in its variable and restart. At boot, a
key variable that holds a key the store lacks replaces the store's active key
of that algorithm. The old key is retired and leaves the JWKS at once, so
tokens it signed stop verifying. Each node logs a warning with the new and the
retired `kid`.

- Give a new RS256 or ML-DSA-65 key a new `JWT_RS256_KID` or `JWT_MLDSA_KID`,
  or unset the variable to use the key's thumbprint.
- With hybrid signing on, change `JWT_PRIVATE_KEY` and `JWT_MLDSA_PRIVATE_KEY`
  together. Turning hybrid signing on after the upgrade is such a replacement:
  set a new `JWT_PRIVATE_KEY` along with the ML-DSA-65 key.
- A variable that holds a key the store retired changes nothing in the store,
  and each boot warns about it: the store keeps its active key, which signs. So
  a node that still has the old value during a rolling restart boots, and
  warns.

### The browser cookies

The session cookie, the login-CSRF cookie and the wallet-flow cookie are signed
with the realm's `cookie_hmac` key, which the signer hands the browser-facing
role. Each value is `<kid>.<payload>.<mac>`: it names the key that signed it,
and its HMAC-SHA256 covers the cookie's name, the realm id, the `kid` and the
payload, so a value never passes for another cookie or for a cookie of another
realm, even if two realms held the same key. A new cookie is signed with the
realm's current key. A cookie of the previous key, the one the last rotation
retired, still verifies until its retention ends, or, for a key a replacement
retired, until the next replacement. During the two minutes before a rotation
takes effect, a cookie of the new key verifies already. A cookie that
does not verify is cleared; one that names a key the process has not read yet
is left for the next request.

Each process reads a realm's cookie keys from the signer at most once a minute,
and once more, at most every five seconds, when a cookie names a key it has not
read yet. The session cookie's `Max-Age` is the time left until the session's
absolute end. A cookie 0.1 signed with `SESSION_COOKIE_SECRET` does not
verify: its user signs in again
([the upgrade guide](/operate/upgrades/#users-sign-in-once-more-after-the-upgrade-to-v02)).

A process without the signer role gets the cookie keys from the signer service,
which this release cannot call
([#497](https://github.com/qauth-labs/qauth/issues/497)): its browser routes
that read or set a signed cookie answer 503, and `/auth/logout` there ends the
sessions and tokens but leaves the cookie for the next page to clear.

### Replacing the cookie key

You replace the cookie key through `SESSION_COOKIE_SECRET`, as for a signing
key: set a new secret, at least 32 characters, and restart. At boot, each
stored cookie key is opened with the KEK and compared with the variable in
constant time. A secret the store lacks becomes the active cookie key, and the
one it replaces is retired: unlike a replaced signing key, it stays the realm's
previous cookie key and keeps verifying the cookies it signed until the next
replacement, so nobody is signed out. The node that replaces it logs a warning
with the new and the retired `kid`. A variable that holds a cookie key the
store retired changes nothing, and each boot warns about it, so a node that
still has the old value during a rolling restart boots. To tell a new secret
from a retired key, the boot opens every stored cookie key, so a retired one
sealed under a KEK that is no longer configured refuses the boot of any node
whose secret differs from the active key: keep `KEK_PREVIOUS` set after a
change of KEK.

To cut off a leaked cookie secret, replace it twice, restarting after each new
secret: the second replacement drops the leaked key from the previous slot. A
restarted node refuses the cookies it signed at once. A node that keeps
running can accept them for up to about two minutes after the replacement, as
it keeps a realm's cookie keys for up to a minute and the signer it reads them
from keeps its own list for up to a minute too; restart every node to cut that
window.

If `SESSION_COOKIE_SECRET` holds a value from QAuth's own examples
(`.env.example`, or the `.env.docker.example` of earlier releases), anyone can
sign cookies with it: production refuses to start with it. Set a new secret
first, so the boot step replaces the stored key, and only then remove the
variable; removing it alone leaves the stored key as it is.

## Adding a key: `auth-server:keys:create`

On a host that holds the KEK, with the server's environment, one command
creates a key for a realm, purpose and algorithm. The usual case is an RS256
key for a realm that has none. A deployment upgraded from 0.1 without
`JWT_RS256_PRIVATE_KEY` is one: it signs its ID tokens with EdDSA, which the
OpenID Foundation's certification refuses.

```bash
# From a checkout, with the server's environment:
pnpm nx run auth-server:keys:create --purpose=token_signing --algorithm=RS256

# In the auth-server image, from /app:
tsx src/keys-create.ts --purpose token_signing --algorithm RS256

# With Docker Compose:
docker compose exec auth-server tsx src/keys-create.ts --purpose token_signing --algorithm RS256
```

| Flag          | Default               | Meaning                                                                                                                                            |
| ------------- | --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--purpose`   | required              | The key's purpose, such as `token_signing`, `event_signing` or `cookie_hmac`. `trust_anchor` is refused.                                           |
| `--algorithm` | the purpose's default | The algorithm, such as `EdDSA` or `RS256` for `token_signing`. ML-DSA-65 is never created alone: with hybrid signing on, `EdDSA` creates the pair. |
| `--realm`     | `DEFAULT_REALM_NAME`  | The realm that gets the key.                                                                                                                       |
| `--status`    | `active`              | `active`, or `next` for a key that is published before it signs.                                                                                   |
| `--scope`     | none                  | The scope of a purpose that has one per subscription or upstream, such as `webhook_signing`; refused for any other purpose.                        |

It prints each new key as one JSON line, with its `kid`, status and public JWK,
and exits `0`. A usage error exits `2`, and any other error, such as a realm
that already has an active key of that purpose and algorithm, exits `1` with a
message on stderr. It takes the realm's advisory lock, so it does not race a
booting node.

A new active RS256 key signs the realm's ID tokens as soon as each process
reads the realm's key list again, within a minute, and discovery lists `RS256`
in `id_token_signing_alg_values_supported`. Leave `JWT_RS256_PRIVATE_KEY` unset
afterwards: a key in it would replace the one you created at the next boot.

A realm has one active key per purpose and algorithm, so the command cannot
replace one: a second active key is refused. A `next` key is published, and
[the scheduled rotation](#the-scheduled-rotation) makes it active when it is
due.

## A provider-issued client-assertion key

Some upstream providers issue the key a client signs with. Sign in with Apple
is one: the developer downloads a private key (a `.p8` file, ES256) with its
Key ID, and Apple accepts a client secret only when that key signed it. A
provider plugin that authenticates this way (a preset with
`clientAuthentication: { method: 'signed_client_secret' }`,
[Write a preset plugin](/extend/preset-plugins/#what-a-preset-may-set-beyond-a-realms-provider))
needs that key in the realm's key store, as its `upstream_client_assertion`
key, scoped to the plugin's type. QAuth generates every other key itself; this
is the one that comes in from outside, through two admin API operations
([Security operations](/reference/security-operations/)):

| Operation               | Request                                                               | What it does                                                                                        |
| ----------------------- | --------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `plugins.keys.import`   | `POST /admin/v1-rc.0/realms/{realmId}/plugins/{plugin}/keys`          | Imports the key under the provider's key id. The first key signs at once; a second waits as `next`. |
| `plugins.keys.activate` | `POST /admin/v1-rc.0/realms/{realmId}/plugins/{plugin}/keys/activate` | Makes the `next` key sign, and retires the one that signed until then.                              |

Both are security operations (`key-custody`; the import also
`credential-path`): each needs `qauth:admin:security` (the permission
`plugins.security`) and an approval, and `qauth:admin:write` reaches neither.

The key is handled like a generated one:

- It reaches the server only sealed: `secrets.seal` encrypts it for
  `plugins.keys.import`, the member `/privateKey` and the plugin, and the import
  names the sealed value. The approval stores that ciphertext, never the key.
- The signer seals it under the KEK, as it seals every stored key, in the same
  transaction as the call's audit row. No response, approval display, audit
  row, event or log line holds it; they name the key id, its algorithm and its
  status.
- It must be an unencrypted private key (PKCS#8 or SEC 1 PEM) of the algorithm
  the realm's configuration of the plugin asks for, ES256 for Apple: a key of
  another type, curve or size is refused with `400`. So configure the plugin
  first; an import for a plugin whose configuration names no client assertion
  is refused with `409`.
- The key id is the provider's, printable ASCII without spaces, at most 255
  characters, and unique in the realm.
- A deployment that runs on the published development KEK refuses the import:
  a key sealed under a KEK everyone has is not in custody.
- The signer signs with it only for the plugin: `iss` is the assertion issuer
  the configuration names (Apple's Team ID), or the client id, `sub` is the
  client id (Apple's Services ID), and `kid` is the provider's key id. It is
  never published in the realm's JWKS, which serves only token signing keys.

The signer reads the client id and the assertion issuer from what the admin
API stores beside the plugin's configuration at each `plugins.update`, and at
each `plugins.enable` that switches the plugin on, since the signer's process
loads no plugin code. An enable of a plugin that is already on writes
nothing. So after upgrading a plugin whose mapping of its configuration
changed, or a plugin enabled before this release, configure it again.

The operations run on the process that holds the signer role, which holds the
KEK: in a deployment that splits the roles, the admin API of a process without
it answers `503`.

### Sign in with Apple, step by step

1. In the Apple Developer account, note the **Team ID** (ten characters), and
   create or pick the **Services ID** that is the client id. Register the
   realm's callback, `https://<realm host>/upstream/<type>/callback`, as its
   return URL.
2. Under Keys, create a key with Sign in with Apple enabled for the app, and
   download it. Apple offers the `.p8` file once. Note its **Key ID**.
3. Install the Apple plugin and configure it for the realm with the Services ID
   and the Team ID (`plugins.update`, then `plugins.enable`,
   [Installing and enabling a plugin](/extend/auth-method-contract/#installing-and-enabling-a-plugin)).
4. Seal the `.p8` file's contents, then file an approval for the import and
   send it:

   ```http
   POST /admin/v1-rc.0/realms/{realmId}/secrets/seal
   { "operation": "plugins.keys.import", "member": "/privateKey",
     "params": { "plugin": "apple" },
     "value": "-----BEGIN PRIVATE KEY-----\n…\n-----END PRIVATE KEY-----\n" }
   → 200 { "operation": "plugins.keys.import", "member": "/privateKey", "sealed": "v1.…" }

   POST /admin/v1-rc.0/realms/{realmId}/plugins/apple/keys
   QAuth-Approval: {approvalId}
   { "kid": "ABC123DEFG", "privateKey": { "sealed": "v1.…" } }
   → 200 { "kid": "ABC123DEFG", "algorithm": "ES256", "status": "active" }
   ```

5. Keep the downloaded `.p8` file until the import answered `200`: Apple
   offers it once, and a refused import is sent again with the same file.
   Then delete it from wherever it passed through.

`apple` and `ABC123DEFG` stand for the plugin's name and the Key ID Apple
showed.

### Replacing the key

To replace the key without a gap, create a new key at Apple while the old one
still works, and import it as above: it becomes `next`, and the old key keeps
signing. Switch when you are ready. The switch runs as soon as it is
approved: unlike a rotation of a key QAuth generates, it waits for no
pre-publication window, since Apple holds the new key's public half from the
moment it issued it. A wrong, revoked or leaked key is replaced the same way,
at once:

```http
POST /admin/v1-rc.0/realms/{realmId}/plugins/apple/keys/activate
QAuth-Approval: {approvalId}
{ "kid": "XYZ987WVUT" }
→ 200 { "activatedKid": "XYZ987WVUT", "retiredKid": "ABC123DEFG", "activatedAt": "…" }
```

Each process signs with the new key once it reads the realm's key list again,
within a minute. A switch for a key id that is not the plugin's `next` key is
refused with `409`, and so is a third import while a `next` key waits. Revoke
the old key at Apple once every process signs with the new one, a minute after
the switch: a process that has not read the list again still signs with the
old key, and Apple refuses what it signs. A leaked key may be revoked at once,
at the cost of sign-ins through Apple failing on such a process for that
minute.

### Why there is no command or realm-file path

The import exists only in the admin API.
[ADR-019 Decision 11](/reference/records/adr/019-deployment-topology-and-trust-boundaries/)
moves configuration between realms through the realm file, and never copies a
secret value in it: a live realm's secrets are set on the live realm. A
private key is such a value, so a realm file never carries one, and the key is
imported into each realm that uses the plugin. Decision 11 asks for no
command-line import either, and `auth-server:keys:create` creates keys rather
than taking one in: the admin API's import is approved with a passkey, audited
and bound to the plugin and its configuration, which a command on the host
would have to do again.

## What relying parties do with the JWKS

A relying party or resource server that verifies QAuth's tokens itself follows
one rule (ADR-019 Decision 9):

- **Cache the JWKS for at most 5 minutes.** `/.well-known/jwks.json` answers
  `Cache-Control: public, max-age=300`.
- **Fetch it again when a token names a `kid` the cached set lacks, at most
  once a minute.** A token whose `kid` is still unknown after that fetch is
  refused, not retried.
- **Drop every key the JWKS no longer lists.** A key leaves the JWKS when its
  retention ends, or when it is replaced or retired as compromised. A token it
  signed must stop verifying then.

Pick the key by `kid` and `alg` together, never by `kid` alone.
`@qauth-labs/resource-guard` follows the rule by default: its `jwksCacheTtlMs`
is 5 minutes, which is also the least time between two fetches, and each fetch
replaces the whole cached set. The
[OAuth 2.1 flow](/integrate/oauth-flow/#caching-the-jwks) page has the
details.

The 7-day pre-publication and the 14-day retention are far longer than this
cache, so a rotation through the store will change nothing for a relying party
that follows the rule. A key replaced through its variable leaves the JWKS at
once: such a relying party refuses the old key's tokens within 5 minutes.

The token keys sign
[back-channel logout tokens](/integrate/oauth-flow/#back-channel-logout) too,
in the algorithm of the realm's ID tokens, as OpenID Connect Back-Channel
Logout 1.0 §2.4 asks: a relying party verifies them at this JWKS, as it
verifies ID tokens.

## Key formats

### PEM keys: PKCS#8 recommended

Generate every private key with `openssl genpkey`, which writes **PKCS#8** PEM
(first line `-----BEGIN PRIVATE KEY-----`) on every OpenSSL version. The key
boot step reads PKCS#8, and for RSA also **PKCS#1**
(`-----BEGIN RSA PRIVATE KEY-----`), and stores either as PKCS#8. 0.1 reads
PKCS#8 only and refuses a PKCS#1 key at boot, so keep the variable in PKCS#8
for as long as you may roll back to it. To convert a PKCS#1 key:

```bash
openssl pkcs8 -topk8 -nocrypt -in old-rsa-key.pem -out jwt-rs256-private.pem
```

Which format `openssl genrsa` writes depends on your OpenSSL: since 3.0 it
writes PKCS#8 unless you pass `-traditional`; 1.1.x and earlier write PKCS#1.

Public keys, where you supply one, must be **SPKI PEM**
(`-----BEGIN PUBLIC KEY-----`). `openssl pkey -pubout` (used below) always
writes this format.

### EdDSA (Ed25519)

Signs access tokens unconditionally, and ID tokens whenever the realm has no
RS256 key. A fresh realm gets one generated; set a variable only to bring the
key a deployment already signs with, or to replace the stored key.

```bash
openssl genpkey -algorithm Ed25519 -out jwt-ed25519-private.pem
openssl pkey -in jwt-ed25519-private.pem -pubout -out jwt-ed25519-public.pem
```

Set `JWT_PRIVATE_KEY` (or `JWT_PRIVATE_KEY_PATH`) to the private key. The key
step derives the public half itself, with `node:crypto`; `JWT_PUBLIC_KEY` (or
`JWT_PUBLIC_KEY_PATH`) is optional, and the boot stops when it is set and is
not the private key's public half.

Before tokens were signed through the key store, the JWT plugin also imported
the key and could not derive its public half, so a boot without
`JWT_PUBLIC_KEY` failed ([issue #359](https://github.com/qauth-labs/qauth/issues/359)).
The plugin no longer holds a key, so that failure no longer happens.

### RS256 — optional, for OIDF certification

OpenID Foundation Basic/Config OP certification hard-fails an EdDSA-only OP on
its `id_token` signature test, so a realm with an RS256 key signs its ID tokens
with RS256; access tokens are unaffected (always EdDSA). A fresh realm gets one
generated. A deployment that upgraded without `JWT_RS256_PRIVATE_KEY` has none
and keeps signing ID tokens with EdDSA, until you import one with the variable
or [create one](#adding-a-key-auth-serverkeyscreate).

**It must be at least 2048 bits, and the boot checks it.** The key boot step
refuses a shorter `JWT_RS256_PRIVATE_KEY` (RFC 7518 §3.3): the server stops at
startup with an `InvalidConfigurationError` that names the variable and gives
the key's length in its details, and it stores nothing.

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out jwt-rs256-private.pem
openssl pkey -in jwt-rs256-private.pem -pubout -out jwt-rs256-public.pem

# The size, if you want to see it:
openssl rsa -in jwt-rs256-private.pem -noout -text | head -1
# → "Private-Key: (2048 bit, 2 primes)" (or larger)
```

Set `JWT_RS256_PRIVATE_KEY` (or `_PATH`); `JWT_RS256_PUBLIC_KEY` (or `_PATH`)
is optional, as for EdDSA: the key step derives the public half itself. An
optional `JWT_RS256_KID` gives the published RSA JWK a stable `kid`; without
it the key's `kid` is its RFC 7638 thumbprint.

For the full certification flow — deploying, driving the conformance suite,
and the residual-uncertainty checklist — see the
[OIDF OP Certification Runbook](https://github.com/qauth-labs/qauth/blob/main/docs/oidf-op-certification-runbook.md).

### ML-DSA-65 seed — only with hybrid signing

Only used when `HYBRID_SIGNING_ENABLED=true` (default `false` — post-quantum
hybrid signing is opt-in). A fresh realm with hybrid signing on gets the pair
generated; set the variable to import a seed you already have, together with
`JWT_PRIVATE_KEY`. Unlike EdDSA/RS256, this is not a PEM key: QAuth's
canonical private form is the raw **32-byte seed**, base64url-encoded,
unpadded (`libs/server/config/src/lib/schemas/crypto.ts` validates exactly
this shape at startup — wrong length or alphabet fails fast with a clear
message, without printing the seed).

Generate 32 CSPRNG bytes and encode them as unpadded base64url:

```bash
openssl rand 32 | base64 | tr '+/' '-_' | tr -d '=\n'
```

Set the result as `JWT_MLDSA_PRIVATE_KEY` (or point
`JWT_MLDSA_PRIVATE_KEY_PATH` at a file containing it). Hybrid signing also
needs `SIGNING_ALGORITHM_MODE=ed25519+ml-dsa-65`, or the boot fails fast, and a
realm whose active Ed25519 key has no ML-DSA-65 key beside it refuses to boot.
An optional `JWT_MLDSA_KID` names the key in the published JWKS.

**Treat the seed like a private key** — anyone with it can forge the
post-quantum component of a hybrid token.

See the [PQC Verifier Guide](/operate/pqc-verifier-guide/) for what changes
for token verifiers once this is on, and the
[Security Gate Review](/reference/records/security/005-pqc-hybrid-signing-review/) for
the reviewed behavior and the pre-default-on checklist.

## Environment variables

Verified against `libs/server/config/src/lib/schemas/jwt.ts`,
`libs/server/config/src/lib/schemas/crypto.ts`,
`libs/server/config/src/lib/schemas/key-rotation.ts`, the KEK keys of the
configuration registry and the two adapters' settings.

| Variable                          | Default                                               | What it is                                                                       |
| --------------------------------- | ----------------------------------------------------- | -------------------------------------------------------------------------------- |
| `KEK_PROVIDER`                    | `local`                                               | Where the KEK lives: `local`, or an adapter's name, such as `aws-kms` or `vault` |
| `KEK` / `KEK_PATH`                | none; outside production, a published development KEK | The KEK of the `local` provider, as base64 of 32 bytes; the file wins            |
| `KEK_PREVIOUS` / `_PATH`          | none                                                  | The KEK in use before a change of KEK; only opens keys                           |
| `KEK_AWS_KMS_KEY_ID`              | none; required with `aws-kms`                         | The key ARN of a symmetric KMS key                                               |
| `KEK_AWS_REGION`                  | the region the ARN names                              | The key's region; must agree with the ARN                                        |
| `KEK_VAULT_ADDR`                  | none; required with `vault`                           | The `https://` origin of the Vault server                                        |
| `KEK_VAULT_TRANSIT_KEY`           | none; required with `vault`                           | The name of the Transit key that is the KEK                                      |
| `KEK_VAULT_TRANSIT_MOUNT`         | `transit`                                             | The path the Transit engine is mounted at                                        |
| `KEK_VAULT_NAMESPACE`             | none                                                  | The Vault namespace, sent as `X-Vault-Namespace`                                 |
| `KEK_VAULT_CA_CERT_FILE`          | none; Node's own CA certificates                      | A PEM file of the CAs that sign Vault's certificate                              |
| `KEK_VAULT_TOKEN_FILE`            | none                                                  | Token login: a file holding a Vault token                                        |
| `KEK_VAULT_ROLE_ID`               | none                                                  | AppRole login: the role ID                                                       |
| `KEK_VAULT_SECRET_ID_FILE`        | none                                                  | AppRole login: a file holding a secret ID                                        |
| `KEK_VAULT_APPROLE_MOUNT`         | `approle`                                             | The path the AppRole auth method is mounted at                                   |
| `JWT_PRIVATE_KEY` / `_PATH`       | none                                                  | EdDSA: imported into the key store when set                                      |
| `JWT_PUBLIC_KEY` / `_PATH`        | derived from the private key                          | EdDSA: checked when set; verifies tokens without a `kid`                         |
| `JWT_RS256_PRIVATE_KEY` / `_PATH` | none                                                  | RS256: imported when set                                                         |
| `JWT_RS256_PUBLIC_KEY` / `_PATH`  | derived from the private key                          | RS256: checked when set                                                          |
| `JWT_RS256_KID`                   | the key's thumbprint                                  | RS256: the imported key's `kid`                                                  |
| `JWT_MLDSA_PRIVATE_KEY` / `_PATH` | none                                                  | ML-DSA: imported with `JWT_PRIVATE_KEY` as a hybrid pair when set                |
| `JWT_MLDSA_KID`                   | the key's thumbprint                                  | ML-DSA: the imported key's `kid`                                                 |
| `HYBRID_SIGNING_ENABLED`          | `false`                                               | Signs hybrid access tokens                                                       |
| `SIGNING_ALGORITHM_MODE`          | `ed25519`                                             | Must be `ed25519+ml-dsa-65` for hybrid signing                                   |
| `KEY_ROTATION_PERIOD_DAYS`        | `90`                                                  | The days a key serves before the scheduled rotation replaces it                  |
| `KEY_PREPUBLISH_DAYS`             | `7`                                                   | The days a `next` key is published before it signs; at most the period           |
| `KEY_RETIRED_RETENTION_DAYS`      | `14`                                                  | The days a retired key is kept at least                                          |

## See also

- [Upgrades](/operate/upgrades/#upgrading-from-01-to-02) — the upgrade to 0.2
  that imports the key variables, and when to remove them.
- [Topology](/operate/topology/) — where the signer and the KEK sit in a
  deployment.
- [Docker](/operate/docker/) — where these keys get mounted into the stack.
- [Service roles](/operate/service-roles/) — which processes may hold these
  keys once the roles run apart.
- [PQC Verifier Guide](/operate/pqc-verifier-guide/) — the ML-DSA key from a
  verifier's perspective.
