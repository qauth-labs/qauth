---
title: Upgrades
description: How to upgrade QAuth — back up the database, run the new version's migration runner, start the new version — the upgrade from 0.1 to 0.2 with its hosts, keys, sessions and roles, and the history of migration 0011, the destructive ADR-002 identity migration.
sidebar:
  order: 7
lastVerified: '2026-11-08'
---

Every upgrade takes the same three steps: back up the database, run the new
version's migration runner, then start the new version. Migrations only go
forward and downgrades are not supported, so the backup is your only way back
([ADR-018 §5](/reference/records/adr/018-1-0-scope-and-stability/)).

## Upgrade procedure

### 1. Back up the database

```bash
# Adjust host, container and credentials to your deployment.
docker exec qauth-postgres pg_dump -U qauth -d qauth -F c -f /tmp/qauth-pre-upgrade.dump
docker cp qauth-postgres:/tmp/qauth-pre-upgrade.dump ./qauth-pre-upgrade.dump
```

Confirm the dump is not empty. Restoring it later discards every write made
after it was taken.

### 2. Run the migration runner of the new version

The runner is the `migration-runner` image built from
`apps/migration-runner/Dockerfile`. Each release also publishes it, signed, as
`ghcr.io/qauth-labs/qauth/migration-runner` (see
[Published images](/operate/images/)). It holds Node and one program, with the
new version's migrations beside it, and needs only `DATABASE_URL`:

```bash
# Docker Compose: build the new version's image, then run it once.
docker compose build migration-runner
docker compose run --rm migration-runner

# Any other platform: run the image as a one-off job.
docker run --rm -e DATABASE_URL='postgresql://qauth:…@db:5432/qauth' qauth/migration-runner

# From a checkout of the new version, with pnpm installed.
pnpm nx run migration-runner:migrate
```

It applies every pending migration in one transaction and logs each with its
duration:

```text
Applying 2 migrations in one transaction: 0034_webauthn_rp_id_lock, 0035_event_deliveries.
  0034_webauthn_rp_id_lock ran in 14 ms
  0035_event_deliveries ran in 34 ms
Applied 2 migrations in 212 ms. The database is current.
```

It is safe to run twice. A run on a current database prints
`The database is current: all 36 migrations are applied. Nothing to do.` and
exits `0`. The runner holds a Postgres advisory lock while it works, so a second
runner started beside it, for example by every node of a cluster at once, waits
for the first, then finds nothing to do.

| Exit code | Meaning                                                                                                                                                                                          |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `0`       | The database is current: the run applied the pending migrations, or there were none.                                                                                                             |
| `1`       | A migration failed. The error names it, and the whole run rolled back: no migration of the run was applied. With `--check`: migrations are pending.                                              |
| `2`       | Usage error: an unknown flag, `DATABASE_URL` is not set, or the system-client or `DB_USER_*` variables are incomplete or invalid. Nothing was done.                                              |
| `3`       | The run could not start: the database is unreachable, or the migrations folder cannot be read.                                                                                                   |
| `4`       | Every migration is applied, but the system client set by `SYSTEM_CLIENT_REDIRECT_URI` could not be provisioned. The error names why.                                                             |
| `5`       | Every migration is applied, but the grants of the roles' database users named by `DB_USER_*` could not be applied. They are as they were. It wins over `4` when both fail; the errors name both. |

`--check` reports the pending migrations and changes nothing: it takes no lock
and creates nothing, so a read-only database role can run it.

```bash
docker compose run --rm migration-runner --check
```

```text
The database lacks 1 of 36 migrations: 0035_event_deliveries. Run the migration runner without --check to apply them.
```

A failed run changed nothing. Fix the cause the error names, then run the
runner again.

### 3. Start the new version

```bash
docker compose up -d --build auth-server
```

`--build` builds the new version's image first: without it, Compose starts the
image it built for the old version. Rebuild `developer-portal` the same way when
you run it.

At boot the auth server compares the database with the migrations of its own
release. When the database lacks some, the server waits for the migration
runner, up to `DB_MIGRATION_WAIT_MS` (60 seconds by default, `0` to check once),
then exits non-zero with a message that names the missing migrations:

```text
The database lacks 1 migration this release needs: 0035_event_deliveries. Waited 60 s for the migration runner. Run it against this database, then start the server again.
```

So a server started beside the runner, as a platform without job ordering
does, waits for it instead of failing on a missing table.

A database **ahead** of the release does not stop the server: during a rolling
upgrade the old version keeps running on the new schema for a short time. The
server logs a warning with the number of newer migrations and starts.

### Release notes that need more than these steps

Read the release's `CHANGELOG.md` entry before you upgrade. Two upgrades need
more: the upgrade from 0.1 to 0.2, in the next section, and migration 0011 in
QAuth's history, at the end of this page.

## Upgrading from 0.1 to 0.2

:::caution[Back up first. Downgrades are not supported.]
Take the backup of [step 1](#1-back-up-the-database) before anything else.
There is no way back from 0.2 to 0.1 but to restore that backup: every write
made after it is lost. Keep the 0.1 release's environment, its key variables
included: a restored 0.1 deployment needs them again. Keep it apart from the
database backups, as you keep the KEK: the key variables hold the private keys
in the clear, and 0.2 goes on signing with them.
:::

0.2 brings the deployment topology of
[ADR-019](/reference/records/adr/019-deployment-topology-and-trust-boundaries/):
one host and one issuer per realm, keys in an encrypted key store, browser
sessions in Postgres, service roles, and health, readiness and metrics per
process. [Topology](/operate/topology/) describes the result. Most of it needs
no action. This section says what does, in order.

| What changes                                         | What breaks when you do nothing                                                                        |
| ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| The default realm answers on its issuer's host only. | A caller that reaches the server by another name, such as an internal name, gets `421`.                |
| Keys move into a key store, wrapped by a KEK.        | With `NODE_ENV=production`, the server does not start without a KEK.                                   |
| Browser sessions move to Postgres.                   | Every signed-in user signs in once more.                                                               |
| `/health` checks nothing; `/ready` does.             | A probe on `/health` no longer takes a process out of rotation when Postgres or Redis is down.         |
| The metrics leave the public port.                   | A scrape of `/metrics` gets `404`.                                                                     |
| Two private-address switches are removed.            | A deployment that sets `CIMD_ALLOW_PRIVATE_ADDRESSES` or `ID_JAG_ALLOW_PRIVATE_ADDRESSES` won't start. |

### The upgrade, step by step

1. **Back up the database** ([step 1](#1-back-up-the-database)). Keep the 0.1
   environment apart from it, as you keep the KEK.
2. **Make a KEK and keep it apart from the database.** Run
   `openssl rand -base64 32`. Set the output as `KEK`, or put it in a file and
   set `KEK_PATH`. Store a copy where your database backups are not. See
   [The KEK](#the-kek).
3. **Keep `JWT_ISSUER` as it is.** It becomes the default realm's issuer, and
   its host the realm's host, for good. See
   [The issuer becomes permanent](#the-issuer-becomes-permanent).
4. **List your internal host names in `DEFAULT_REALM_ENDPOINT_HOSTS`.** Name
   every host a server-side caller uses to reach the auth server, such as the
   host of the developer portal's `AUTH_SERVER_URL`. See
   [Endpoint hosts](#endpoint-hosts-for-server-side-callers).
5. **Leave the key variables set for the first boot, and do not change
   them.** The first boot imports them into the key store. See
   [The key import](#the-key-import-and-its-boot-warnings).
6. **Unset `CIMD_ALLOW_PRIVATE_ADDRESSES` and `ID_JAG_ALLOW_PRIVATE_ADDRESSES`.**
   If you set either, read
   [The private-address switches are gone](#the-private-address-switches-are-gone).
7. **Move your probes.** Point readiness probes and load balancer health
   checks at `/ready`, and liveness probes at `/health`. Move the Prometheus
   scrape to the internal listener. See
   [Health, readiness and metrics](#health-readiness-and-metrics).
8. **Read the notes of this release below, from
   [Users sign in once more](#users-sign-in-once-more-after-the-upgrade-to-v02)
   on, then run the migration runner** ([step 2](#2-run-the-migration-runner-of-the-new-version)).
   Some migrations pause token requests while they run.
9. **Start 0.2** ([step 3](#3-start-the-new-version)) **and read the boot
   log.** A good first boot logs `default realm ready` and `realm keys ready`,
   and one warning for each key variable that is still set.
10. **Check the deployment.** See [Check the upgrade](#check-the-upgrade).
11. **Remove the old key variables after the first good boot.** See
    [Remove the key variables](#remove-the-key-variables).
12. **Tell your users.** Each user signs in once more, and developers sign in
    to the portal again
    ([the portal's token](#the-developer-portals-token-moves-to-the-developer-apis-audience)).
    Relying parties that verify tokens themselves follow
    [the JWKS rule](/operate/keys/#what-relying-parties-do-with-the-jwks).

With Docker Compose, `docker-compose.yml` already forwards `KEK`, sets
`DEFAULT_REALM_ENDPOINT_HOSTS` to `auth-server`, the portal's name for the
server, and checks `/ready`. Add `KEK` to your `.env`, or set `KEK_PATH` and
mount the file into `auth-server` as a Compose secret, as the comment above
`KEK_PATH` in `docker-compose.yml` shows: without the mount the server does
not start. Set `DEFAULT_REALM_ENDPOINT_HOSTS` only when other callers reach the
server by other names, and list `auth-server` among them.

### New settings

The settings 0.2 adds for hosts, keys, sessions and roles.
[Configuration](/operate/configuration/) lists every key, those of other areas
new in 0.2 among them.

| Setting                              | Default                                          | What it sets                                                                                                                                   |
| ------------------------------------ | ------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `DEFAULT_REALM_ENDPOINT_HOSTS`       | empty                                            | Host names, comma-separated, that server-side callers reach the default realm by. Added as endpoint hosts at boot.                             |
| `WEBAUTHN_RP_ID`                     | the default realm's host, from `JWT_ISSUER`      | The default realm's passkey RP ID. Locked once the realm has a passkey.                                                                        |
| `WEBAUTHN_RP_ID_ALLOW_PARENT_DOMAIN` | `false`                                          | Allows a parent domain of the realm host as the RP ID. The server warns at every boot.                                                         |
| `KEK_PROVIDER`                       | `local`                                          | Where the KEK lives. `local` reads `KEK` or `KEK_PATH`. Another name loads the adapter package `@qauth-labs/keys-<name>`.                      |
| `KEK`                                | none; outside production, a published dev KEK    | The KEK, as the base64 of 32 random bytes. `NODE_ENV=production` refuses to start without a KEK.                                               |
| `KEK_PATH`                           | none                                             | A file holding the KEK. It wins over `KEK`.                                                                                                    |
| `KEK_PREVIOUS`                       | none                                             | The KEK in use before a KEK rotation. Keys wrapped under it still open.                                                                        |
| `KEK_PREVIOUS_PATH`                  | none                                             | A file holding the previous KEK. It wins over `KEK_PREVIOUS`.                                                                                  |
| `KEK_AWS_*`, `KEK_VAULT_*`           | see [Keys](/operate/keys/#environment-variables) | The settings of the two KEK adapter packages.                                                                                                  |
| `SESSION_LAST_SEEN_INTERVAL`         | `60`                                             | How often, at most, in seconds, a browser session's last-seen time is written.                                                                 |
| `SESSION_RETENTION_DAYS`             | `30`                                             | The days an ended browser session is kept before the purge job deletes it.                                                                     |
| `SERVICE_ROLES`                      | `all`                                            | The roles this process runs: `all`, or a list of `web`, `api`, `admin`, `signer` and `delivery`. See [Service roles](/operate/service-roles/). |
| `SIGNER_URL`                         | none                                             | The `https` URL of the signer service, on a process without the `signer` role.                                                                 |
| `INTERNAL_HOST`                      | `127.0.0.1`                                      | The address the internal listener binds to.                                                                                                    |
| `INTERNAL_PORT`                      | `3443`                                           | The port of the internal listener. It must differ from `PORT` and `ADMIN_API_PORT`.                                                            |
| `INTERNAL_TLS_CERT_PATH`             | none                                             | This process's certificate for mutual TLS between the roles.                                                                                   |
| `INTERNAL_TLS_KEY_PATH`              | none                                             | The private key of that certificate.                                                                                                           |
| `INTERNAL_TLS_CA_PATH`               | none                                             | The CA certificates that issue every peer's certificate.                                                                                       |
| `INTERNAL_PEER_ROLES`                | none                                             | A JSON object from a peer certificate's SAN to the role it calls as, or to `metrics` for a scraper.                                            |
| `EGRESS_ALLOWLIST_PATH`              | none                                             | A JSON file of private hosts and ranges that operator- and admin-set destinations may reach, per realm.                                        |

These settings change meaning:

| Setting                                                                                                                                             | In 0.2                                                                                                                                                                                                                                            |
| --------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `JWT_ISSUER`                                                                                                                                        | The default realm's permanent issuer. A later boot with another value refuses to start.                                                                                                                                                           |
| `JWT_PRIVATE_KEY`, `JWT_RS256_PRIVATE_KEY`, `JWT_MLDSA_PRIVATE_KEY`, `SESSION_COOKIE_SECRET`, `OID4VP_VERIFIER_SIGNING_KEY` and their `_PATH` forms | Optional. The key boot step imports them into the key store, where a new value replaces the stored key. `JWT_PRIVATE_KEY` or `JWT_PUBLIC_KEY` also picks the key that verifies 0.1's tokens without a `kid` ([below](#remove-the-key-variables)). |
| `METRICS_ENABLED`                                                                                                                                   | Serves the metrics at `GET /internal/metrics` on the internal listener, never on the public port.                                                                                                                                                 |
| `OID4VP_RESPONSE_KEY_SECRET`                                                                                                                        | Read only to open wallet request states written by 0.1, which expire within 15 minutes.                                                                                                                                                           |

`CIMD_ALLOW_PRIVATE_ADDRESSES` and `ID_JAG_ALLOW_PRIVATE_ADDRESSES` are removed.

### The issuer becomes permanent

At the first boot, `JWT_ISSUER` becomes the issuer of the default realm
(`DEFAULT_REALM_NAME`, `master` by default), and its host the realm's primary
host. Both are permanent: a database trigger refuses to change them. Every
issued token, registered client and enrolled passkey depends on them.

- **The realm row.** 0.1 created the default realm with no issuer. The first
  boot of 0.2 fills in its issuer and host. Existing clients, tokens and
  consents keep working.
- **A later change refuses the boot.** A boot whose `JWT_ISSUER` differs from
  the stored issuer stops with
  `A realm's issuer and its host are permanent: set JWT_ISSUER to "<stored>".`
  The comparison is exact, letter case and port included, after one trailing
  slash is removed.
- **A trailing slash.** The realm stores the issuer without it, and its
  discovery documents and tokens name it that way. Each boot warns
  `JWT_ISSUER ends with a slash: ... remove the slash`. 0.1 named the issuer
  with the slash in its tokens, and 0.2 checks `iss` against the stored form.
  So 0.2 refuses every access token issued before the upgrade: a client gets
  `401` until it uses its refresh token, which still works, or signs in again.
  A relying party that compares `iss` with the slashed form must drop the
  slash. Upgrade such a deployment all at once, not node by node: in a mixed
  fleet each release refuses the other's access tokens until they expire.
- **A path.** `https://example.com/auth` keeps working: the issuer keeps its
  path, and only the host routes requests to the realm. Each boot warns that
  `JWT_ISSUER has a path`. A new realm's issuer is an origin with no path, and
  QAuth needs a [dedicated host](/operate/topology/#a-dedicated-host-never-a-path).
- **A host it refuses.** The host must be a name, not an IP address, because a
  passkey RP ID cannot be one. Plain `http` is accepted for `localhost` and
  `*.localhost` only. Either refusal stops the first boot, and nothing is
  written.

The port is part of the issuer, not of the host: `https://auth.example.com:8443`
has the host `auth.example.com`.

Keep `DEFAULT_REALM_NAME` as it is too: the boot finds the default realm by
that name.

### Endpoint hosts for server-side callers

From 0.2 a request belongs to the realm whose host it names. The server reads
the host from `Host`, or from `X-Forwarded-Host` when the hop that sent it is
listed in `TRUST_PROXY`. The match ignores case and the port. A request for any
other host gets `421 Misdirected Request`, with no cookie and no fallback to the
default realm. Only `/health` and `/ready` answer on every host.

So a server-side caller that reaches the auth server by another name breaks,
unless that name is an **endpoint host** of the realm. List every such name in
`DEFAULT_REALM_ENDPOINT_HOSTS`, comma-separated:

- the host of the developer portal's `AUTH_SERVER_URL` (`auth-server` in the
  Compose file);
- the host a resource server introspects tokens at, or fetches the JWKS from,
  when it is not the issuer's host;
- an internal load balancer's name, or an IP address that a monitor calls.

```bash
DEFAULT_REALM_ENDPOINT_HOSTS=auth-server,auth.internal.example
```

Write bare host names: a port is dropped, and a scheme, path or wildcard
refuses the boot. Each boot adds every listed host the realm lacks, and never
removes one: a shorter list later changes nothing. A host belongs to one realm
only, as one kind, so the boot refuses the issuer's own host, or a host of
another realm.

An endpoint host answers the API routes: token, introspection, revocation,
userinfo, registration, discovery, JWKS, the `/auth/*` API routes and the
account and developer APIs. It refuses the browser-session routes with `421`:
`/oauth/authorize`, `/ui/*`, the Interaction API, `/consents`,
`/auth/link/wallet` and the email verification page (`GET /auth/verify`). A
browser always uses the issuer's host.

A reverse proxy in front of the server must pass the realm host as `Host`, or
set `X-Forwarded-Host` and be listed in `TRUST_PROXY`. A proxy that sends its
upstream's name instead (`proxy_set_header Host auth-server`) makes every
request a `421`. See [Reverse proxy](/operate/reverse-proxy/).

### The KEK

The key store wraps every stored key with a key-encryption key (KEK). The
default provider, `KEK_PROVIDER=local`, reads it from `KEK` or `KEK_PATH`.

**Make one.** The KEK is the base64 of 32 random bytes:

```bash
mkdir -p -m 700 ~/qauth-secrets
(umask 077 && openssl rand -base64 32 > ~/qauth-secrets/qauth-kek)
```

`umask 077` keeps the file its owner's alone from the start. Keep it in a
directory of its own, outside any git checkout and apart from the database
backups. [Keys](/operate/keys/#the-kek) says how a container reads it.

Set `KEK_PATH` to the file, or `KEK` to its content. `KEK_PATH` wins when both
are set, and the server warns when group or others can read the file. Give it
to every process that holds the `signer` role: every process, while
`SERVICE_ROLES` is `all`. A process without that role refuses to boot with a
KEK.

**Keep it apart from the database.** The database holds the stored keys,
wrapped. Whoever holds a database backup and the KEK holds every key. So never
put the KEK in the database backup, and back it up on its own, for example in
your secret manager and once more offline. A restored backup needs the KEK it
was taken under.

**Losing it loses every stored key.** Nothing opens a stored key without the
KEK that wrapped it. The signing keys, the cookie key, the data-at-rest key
and the realm secrets it protects, such as the mail password, are lost with
it: the server can no longer sign a token or a cookie, and `/ready` fails its
`kek` check.

Outside production the server falls back to a published development KEK and
warns. It refuses to import a key variable under it, in every environment.
`NODE_ENV=production` refuses to start without a KEK, and refuses the
development KEK. A key management service can hold the KEK instead, through
an adapter package; choose the provider before the first boot, as
[Keys](/operate/keys/#the-kek) describes.

### The key import and its boot warnings

The first boot of a process that holds the `signer` role imports the key
variables into the default realm's key store, under an advisory lock, so nodes
that start together import once:

| Variable                                | Becomes                                                      |
| --------------------------------------- | ------------------------------------------------------------ |
| `JWT_PRIVATE_KEY` / `_PATH`             | The Ed25519 token signing key                                |
| `JWT_RS256_PRIVATE_KEY` / `_PATH`       | The RS256 token signing key, which then signs ID tokens      |
| `JWT_MLDSA_PRIVATE_KEY` / `_PATH`       | The ML-DSA-65 key of the hybrid pair, with hybrid signing on |
| `SESSION_COOKIE_SECRET`                 | The cookie key                                               |
| `OID4VP_VERIFIER_SIGNING_KEY` / `_PATH` | The wallet verifier's request-signing key                    |

The keys themselves do not change, so the tokens 0.1 signed still verify. The
boot then creates the keys the realm lacks: the event-signing and data-at-rest
keys, and the cookie key when `SESSION_COOKIE_SECRET` is unset. A realm that
imports no signing key gets an Ed25519 and an RS256 one. A realm that imports
only `JWT_PRIVATE_KEY` gets no RS256 key, and keeps signing ID tokens with
EdDSA: add one with
[`auth-server:keys:create`](/operate/keys/#adding-a-key-auth-serverkeyscreate).

Every boot logs one info line, `realm keys ready`, that names each key it
imported or created, by purpose, algorithm and `kid`. Then it warns once for
each key variable still set, for example:

```text
JWT_PRIVATE_KEY is in the realm's key store, which signs the tokens: the variable is read only at boot, where a new key in it replaces the stored key and unpublishes the old one at once. Remove it unless you may roll back to a release that signs with it.
```

The warnings are expected after the upgrade. They stop when you remove the
variables. A variable that holds a **new** key at a later boot replaces the
stored key, and the old key leaves the JWKS at once
([Replacing a signing key](/operate/keys/#replacing-a-signing-key)): do not
change a key variable during the upgrade.

The boot stops, naming the variable, when no KEK is set, when a public key
variable is not the half of its private key, when an RS256 key is shorter than
2048 bits, or when a variable's `kid` already names another stored key.

### Check the upgrade

```bash
ISSUER=https://auth.example.com   # your JWT_ISSUER

curl -fsS "$ISSUER/ready"
curl -fsS "$ISSUER/.well-known/openid-configuration" | grep -o '"issuer":"[^"]*"'
curl -fsS "$ISSUER/.well-known/jwks.json"
```

- `/ready` answers `200`, with every check `ok`.
- Discovery names `JWT_ISSUER`, without a trailing slash.
- The JWKS lists the `token_signing` keys of the `realm keys ready` line, each
  with its `kid`. The line's other keys, such as `cookie_hmac` and
  `data_at_rest`, are never in the JWKS.
  An imported key's `kid` is `JWT_RS256_KID` or `JWT_MLDSA_KID` when set, and
  otherwise the RFC 7638 thumbprint of its public key.
- An access token issued before the upgrade still introspects `active: true`,
  and a refresh token issued before it still rotates. With a slashed
  `JWT_ISSUER`, only the refresh token does
  ([The issuer becomes permanent](#the-issuer-becomes-permanent)).
- Each endpoint host answers. With Compose, from the portal's container:

  ```bash
  docker compose exec developer-portal node -e \
    "fetch('http://auth-server:3000/.well-known/openid-configuration').then((r) => console.log(r.status))"
  ```

  `200` means the host is an endpoint host; `421` means it is missing from
  `DEFAULT_REALM_ENDPOINT_HOSTS`.

### Remove the key variables

Remove the private key variables once all three hold:

- every node runs 0.2;
- the first boot logged `realm keys ready` with each key imported;
- you will not go back to 0.1, which signs with them. A rollback restores the
  backup and needs them again, so keep a copy with the KEK until then.

That is `JWT_PRIVATE_KEY`, `JWT_RS256_PRIVATE_KEY`, `JWT_MLDSA_PRIVATE_KEY`,
`SESSION_COOKIE_SECRET`, `OID4VP_VERIFIER_SIGNING_KEY` and their `_PATH`
forms, with `JWT_RS256_PUBLIC_KEY`, `JWT_RS256_KID` and `JWT_MLDSA_KID`. Keep
the OID4VP certificate chain variables: they are public and name the stored
key.

One public key stays a little longer. An access token issued by 0.1 names no
key (`kid`), and the server verifies such a token only with the Ed25519 key
that `JWT_PRIVATE_KEY` or `JWT_PUBLIC_KEY` holds. So, when you remove
`JWT_PRIVATE_KEY`, keep `JWT_PUBLIC_KEY` set to its public half
(`openssl pkey -in jwt-private.pem -pubout`) until the longest access token
lifetime has passed since the last 0.1 node stopped: `ACCESS_TOKEN_LIFESPAN`,
15 minutes by default, or `DEV_ACCESS_TOKEN_LIFESPAN` for development clients,
8 hours by default. Then remove it too. The next release refuses every token
without a `kid`.

Remove `OID4VP_RESPONSE_KEY_SECRET` 15 minutes after the last 0.1 node stopped,
and `SMTP_PASSWORD` and `RESEND_API_KEY` once every node runs 0.2
([Mail secrets move into the realm](#mail-secrets-move-into-the-realm)).

### Health, readiness and metrics

- **`/health` is liveness.** It answers `200` while the process serves, with
  its service roles, and checks nothing. 0.1 checked Postgres and Redis there
  and answered `503` when one was down.
- **`/ready` is readiness.** It runs the checks of the process's roles
  (`database`, `redis`, `kek`, `outbox`) and answers `200`, or `503` with a
  problem document that names the failing check.
- **The metrics are on the internal listener.** `GET /internal/metrics` on
  `INTERNAL_HOST:INTERNAL_PORT` (`127.0.0.1` and `3443` by default). The public port
  answers `404` to `/metrics`. A single process without the internal TLS files
  serves them in plain HTTP on loopback only; a scraper on another machine
  needs mutual TLS, with its certificate's SAN mapped to `metrics` in
  `INTERNAL_PEER_ROLES`.

Both probes answer on every host and carry no realm data. The Compose file's
health check calls `/ready`; the image's own `HEALTHCHECK` stays on `/health`.
See [Health and readiness](/operate/observability/#health-and-readiness) and
[Who can read the metrics](/operate/observability/#who-can-read-the-metrics).

### The private-address switches are gone

0.2 sends every outbound call through one egress client, which never connects
to a private, loopback or link-local address on its own
([ADR-019 Decision 8](/reference/records/adr/019-deployment-topology-and-trust-boundaries/)).
`CIMD_ALLOW_PRIVATE_ADDRESSES` and `ID_JAG_ALLOW_PRIVATE_ADDRESSES` are
removed. A value that is not blank stops the boot with a message that names the
replacement:

- **`CIMD_ALLOW_PRIVATE_ADDRESSES`** has nothing to replace it. A client's
  metadata document and its `jwks_uri` come from the client, and never reach a
  private address now. A test reaches a local server through the test-only
  `createTestEgressClient`.
- **`ID_JAG_ALLOW_PRIVATE_ADDRESSES`** is replaced by the egress allowlist. A
  trusted issuer's discovery URL on a private address is listed, for the realms
  that trust it, in the JSON file `EGRESS_ALLOWLIST_PATH` names. The `jwks_uri`
  its discovery document names never reaches a private address.

```json
{
  "entries": [
    { "host": "idp.corp.example", "realms": ["master"] },
    { "cidr": "10.20.0.0/16", "realms": ["master"], "note": "partner VPN" }
  ]
}
```

See [Outbound calls and the egress allowlist](/operate/docker/#outbound-calls-and-the-egress-allowlist)
for the file's rules.

### Service roles are optional

`SERVICE_ROLES` defaults to `all`: one process runs every role, as 0.1 did.
Nothing changes until you split the roles. [Service roles](/operate/service-roles/)
says which splits work in this release, and [Topology](/operate/topology/#service-roles-and-mutual-tls)
how they fit together.

### The operator realm

In simple mode, one realm on one host, the default realm is also the
**operator realm**
([ADR-019 Decision 1](/reference/records/adr/019-deployment-topology-and-trust-boundaries/)).
The first boot of 0.2 marks it so. Its admins are the operator's admins, and
the admin console will be a client of it. A one-host deployment needs no
second realm, host or issuer for administration.

Adding a second realm splits the two, in a step called the operator-realm
split:

- The default realm keeps its host and its issuer, which are permanent. Its
  clients, users, tokens and passkeys are untouched.
- The operator realm becomes a realm of its own, on a host of its own, with its
  own DNS name and certificate. Operator admins and service accounts sign in
  there, and the admin console moves to that host.

0.2 has no way to add a second realm, so the split cannot happen yet: the realm
lifecycle operations of the admin API
([#694](https://github.com/qauth-labs/qauth/issues/694)) add realms, and this
guide gives the split's commands with them. Meanwhile, choose the operator
realm's host and keep it free, so that it can get its DNS name and certificate
when the split comes.

### Users sign in once more after the upgrade to v0.2

From v0.2 the auth server keeps browser sessions in Postgres, with Redis as a
cache in front of them
([ADR-019 Decision 3](/reference/records/adr/019-deployment-topology-and-trust-boundaries/)).
The upgrade does not move the sessions an earlier version kept in Redis. A user
who was signed in to the hosted pages (`/ui/login`, the consent screen, wallet
sign-in) is asked to sign in once more. A consent screen open during the
upgrade is refused when it is submitted and shown again after that sign-in.

Nothing else is lost. Access tokens, refresh tokens and stored consents are
untouched, so an application that already holds tokens keeps working without
the user. The old Redis session keys (`session:<id>`, and the per-user lists
`user-browser-sessions:<user id>` that logout read) are no longer read and
expire on their own within `SESSION_COOKIE_TTL`; there is nothing to delete.

The session cookie changes too: v0.2 signs it with the realm's cookie key from
the key store, and the cookie names that key
([#493](https://github.com/qauth-labs/qauth/issues/493)). A cookie an earlier
version signed with `SESSION_COOKIE_SECRET` does not verify, and the new version
clears it. `SESSION_COOKIE_SECRET` becomes optional: at the first boot the key
store imports it as the realm's cookie key, and later a different value in it
replaces that key. See [the key store](/operate/keys/#the-key-store).

During a rolling upgrade the two cookie formats do not mix. A node of the old
version refuses the new cookie, and when the user signs in there it sets a
cookie of the old format, which a node of the new version clears. A browser
whose requests go to old and new nodes in turn is asked to sign in again at
each switch, not once, until the last old node is gone. Send the browser
traffic (`/ui/*`, `/oauth/authorize`, the consent screen) to the new nodes only
as soon as the first one is up, or route each browser to one node for the
duration of the roll (sticky sessions); a single-node deployment, or one
upgraded stop-start, is unaffected.

### The developer portal's token moves to the developer API's audience

The developer portal's token moves to the developer API's audience,
`urn:qauth:aud:developer:v1-rc.0`. ADR-018 §5 would take that in two releases,
expand then contract
([API conventions](/reference/api-conventions/#issuing-a-family-audience)),
but v0.2 carries both steps at once:

- **Accepted** ([#509](https://github.com/qauth-labs/qauth/issues/509)).
  `/api/clients`, `/api/consents`, `/auth/logout` and userinfo accept a
  system-client token whose `aud` is the developer audience.
- **Minted, and the old token retired**
  ([#524](https://github.com/qauth-labs/qauth/issues/524)). As each node of v0.2
  boots, it gives the system client of every realm the developer audience, so
  `POST /auth/login` mints the new token from then on, on every node, since
  each one reads the client's row. The deprecated `/api/clients` and
  `/api/consents` accept only the new token. `/auth/logout` still accepts a
  live old one, whose `aud` is the system client's id, for this release only,
  so a developer whose portal session began before the upgrade can still sign
  out: the call ends their sessions, refresh tokens and codes, and grants
  nothing. An expired old token is refused, and the next release removes the
  grace. The Bearer path of `/oauth/authorize` is
  gone: an `Authorization` header there signs no one in, and a request without
  a browser session goes to the login page.

What an operator sees when v0.2 rolls out:

- **Developers sign in to the portal again.** A portal token minted before the
  first node of v0.2 booted carries the system client's id as its `aud`, and
  every v0.2 node refuses it, except to sign out (a token lives
  `ACCESS_TOKEN_LIFESPAN`, 15 minutes by default). The portal answers the
  refusal by sending the developer to its login page.
- **During a rolling upgrade from v0.1.x, more than once.** A v0.1.x node
  does not accept the new token: it refuses userinfo to it, so a developer
  whose request reaches an old node is signed out of the portal, and a token an
  old node minted is refused by the new ones. Until the roll ends, a developer
  is signed out whenever a request reaches a node of the other version than the
  one that signed them in; a portal session lasts `PORTAL_SESSION_TTL`
  (15 minutes by default). A single-node deployment, or one upgraded
  stop-start, is unaffected.
- **A caller of `/oauth/authorize` with a Bearer token stops getting codes.** No
  shipped component used that path; anything that did must send the user through
  the browser flow, as every other client does.
- There is no migration and nothing to run: the boot step changes one row per
  realm and logs `Gave the system client the developer API audience` when it does.

### The developer and account APIs need their scopes

From this release an operation of the developer API (`/developer/v1-rc.0`) or
the account API (`/account/v1-rc.0`) needs, beside the family's audience, the
family's scope of its class: `qauth:developer:read` or `qauth:developer:write`,
`qauth:account:read` or `qauth:account:write`
([#933](https://github.com/qauth-labs/qauth/issues/933)). A token without it is
refused with 403 `forbidden`. The deprecated `/api/clients` and `/api/consents`
routes need the same scopes as the operations they alias, and attributing a
dynamic registration to a developer (`POST /oauth/register` with the
developer's token) needs `qauth:developer:write`. The developer portal's token
carries both developer scopes, so the portal needs nothing. For this release
only, a portal token that names no scope, which a node of the previous release
mints, counts as carrying both, so a developer whose portal session began
before the upgrade, or on a node not yet upgraded, keeps working during and
after the rolling upgrade. The next release refuses such a token; by then
every one has expired. A client you gave a family
audience in its `audience` (the seed manifest's `clients[].audience`) also
needs the scopes it will use in its `scopes`, and asks for them in `scope`; the
token endpoint issues them only to a client that lists the family's audience,
for a token that names a user. There is no migration and nothing to run.

### Refresh tokens pause while migration 0038 runs

Migration 0038 ([#552](https://github.com/qauth-labs/qauth/issues/552)) records
when each refresh-token family started. It fills the new column for every row
of `refresh_tokens` in one statement, inside the runner's transaction. Before
anything else it locks `authorization_codes` and then `refresh_tokens`, the
order a code redemption takes them in, and holds both until that transaction
commits. While the runner works, every request that reads or writes a refresh
token or an authorization code waits: a code exchange, a refresh,
`POST /auth/login`, minting a code at `/oauth/authorize` or on the consent
screen, and the purge job. Nothing fails; those requests finish once the runner
does, unless your proxy or client gives up first. A database that ran 0038 from
`main` before its locks moved to the start is unaffected: the change only
reorders its locks, and the runner never runs a migration twice.

The pause grows with the number of rows in `refresh_tokens`, rotated and
revoked tokens included. Measured on a 12-vCPU AMD EPYC virtual machine with
47 GB of memory, against a `postgres:18-alpine` container on its default
settings (`shared_buffers` 128 MB, `max_wal_size` 1 GB), with five tokens per
family:

| Rows in `refresh_tokens` | Table size | Whole migration | A token insert waited |
| ------------------------ | ---------- | --------------- | --------------------- |
| 100,000                  | 58 MB      | 5.7 s           | 4.7 s                 |
| 1,000,000                | 588 MB     | 100 s           | 99.8 s                |

Almost all of it is the `UPDATE` (5.5 s and 98.4 s). Taking the locks first
adds no work, so these figures, measured before the locks moved, still hold;
minting a code now waits as long as a token insert. These were default
settings; more `shared_buffers` and a larger `max_wal_size` may shorten the
pause, which we have not measured. To estimate your own, count first:

```sql
SELECT count(*) FROM refresh_tokens;
```

With many rows, run the migration at a quiet hour, and keep the proxy's and
the clients' timeouts above the expected pause.

Migrations 0038 and 0041 both take their locks in a redemption's order: a
redemption spends its code in `authorization_codes`, then stores the refresh
token it buys. So a redemption in flight during the upgrade, on a node of either
version, waits for the runner instead of deadlocking with it.

### Migration 0041 reads `refresh_tokens` once more

Migration 0041 ([#627](https://github.com/qauth-labs/qauth/issues/627)) links
each refresh-token family to the authorization code that started it. It adds a
column that starts empty, so it rewrites no row, but its foreign key and index
each read the whole table while the runner holds the lock 0038 described. It
first locks `authorization_codes` against writes, then `refresh_tokens`, in the
order a redemption takes them, so it cannot deadlock with one. So minting a
code at `/oauth/authorize` or on the consent screen, redeeming one at
`/oauth/token` and a logout wait until the runner commits, on nodes of either
version. On the same virtual machine, against a `postgres:18-alpine` container
with 1,000,000 rows in `refresh_tokens` (531 MB), it took 1.3 s, and a token
insert waited for it. Upgrading from a release before 0038 runs 0038 and 0041
in the one transaction, so the two pauses add up.

The same release records each access token it issues from a code or a refresh
family in Redis, so that a replay can deny-list them. It sets those records'
lifetimes with `EXPIRE` and its `NX` and `GT` options, which need **Redis 7.0
or later**. The bundled Compose file runs Redis 7; check the version of a Redis
you run yourself.

### Migration 0042 holds sign-ins while it reads `authorization_codes`

Migration 0042 ([#549](https://github.com/qauth-labs/qauth/issues/549)) records
the browser session behind each authorization code. It adds a column that
starts empty, so it rewrites no row, but its foreign key and index each read
the whole of `authorization_codes`. It first locks `sessions` against writes,
then `authorization_codes`, in the order a code's mint and a session's
revocation take them, so it cannot deadlock with either. So a sign-in, a
sign-out, minting a code and redeeming one wait until the runner commits, on
nodes of either version. Codes live five minutes and the purge job deletes
expired ones, so the table is usually small and the pause short.

### Admin scopes and the admin audience need an admin grant

From this release the token endpoint issues a `qauth:admin:*` scope only to an
account that holds an admin grant reaching that scope's class, through a client
that lists the admin API's audience, and the admin audience only to an account
that holds an admin grant ([#510](https://github.com/qauth-labs/qauth/issues/510)).
A `client_credentials` token gets neither, and neither do the ID-JAG grants or a
delegated token from token exchange. Migration 0043 adds the empty
`admin_grants` and `admin_roles` tables. Their foreign keys briefly lock
`realms` and then `users` against writes (reads go on), so a realm or account
change waits for the runner's commit. No admin route ships in this release,
so nothing that works today stops working; before you use the admin API, give
each account that will use it a grant. During a rolling upgrade a node of the
previous release still issues those scopes without the check, which reaches no
route either.

### Disabled accounts get the time of migration 0044

Migration 0044 ([#748](https://github.com/qauth-labs/qauth/issues/748)) records
when each account was last disabled, so that enabling it again brings back none
of the sessions and tokens it held. An account that is disabled when the
migration runs gets the time of the migration; every other account starts with
none. Only disabled rows are written, but finding them reads the whole `users`
table while the runner holds the lock the new column takes, so on a large table
sign-ins wait for the runner's commit. Run it when no long transaction holds
`users`: the migration sets no `lock_timeout`, so its `ALTER TABLE` queues
behind any open transaction that read the table, and every sign-in and token
request that reads `users` waits behind it while it queues. During a rolling
upgrade a node of the previous release still accepts the old sessions and
access tokens of an account enabled again, and can start new refresh families
from its old sessions: enable an account that was disabled for a takeover only
after every node runs this release ([Accounts](/operate/accounts/)).

An account that was disabled and enabled again before the upgrade gets no
time, and keeps every session and token the previous release brought back
when it was enabled. For each account you enabled again after a takeover,
once every node runs this release, run `db:disable-user` and then
`db:disable-user --enable`: that records the time now and ends everything the
account holds ([Accounts from before the upgrade](/operate/accounts/#accounts-from-before-the-upgrade)).

### Realm policies move onto the realm row

From this release a realm's policies live on its row in Postgres, and the
environment only seeds a new realm
([ADR-019 Decision 10](/reference/records/adr/019-deployment-topology-and-trust-boundaries/),
[#516](https://github.com/qauth-labs/qauth/issues/516)): the token lifetimes,
the verified-account requirement, the password and brute-force policy, client
registration, the mail sender and the environment ceiling, the fields of
[Realm policies](/reference/realm-policies/). Migration 0046 adds three columns
to `realms` and writes no row, so every realm starts the upgrade with no
policies.

**The first boot fills them.** The default realm's boot step gives every realm
that has no policies the values of the environment the server runs with: each
key whose role is `realm-seed` on [Configuration](/operate/configuration/), or
the field's default where the key is unset. Two settings the row already held
are kept, because the server read them from the row before: the environment
ceiling (`max_environment_laxity`), and the dynamic registration allowlist when
it holds a scope (an empty one gets `DEFAULT_DYNAMIC_REGISTRATION_SCOPES`, as
`/oauth/register` used it). The token lifetime columns were never read, so they
take `ACCESS_TOKEN_LIFESPAN` and `REFRESH_TOKEN_LIFESPAN`. The fill is an
`UPDATE ... WHERE policies_version = 0` per realm: of nodes that start
together, the first one writes and the others find the realm filled. So give
every node the same environment for the first boot after the upgrade; the
first node to boot decides the stored values. The log says
`realm policies filled from the environment` for each realm it filled, and
warns for each value a realm's row kept that differs from the environment's
seed (`... kept its posture.maxEnvironmentLaxity from its row ...`), so a
ceiling or an allowlist that does not follow the environment is named once.

**Later changes of the environment change no realm.** Once a realm has its
policies, its row owns them: a seed key only seeds a realm created later. The
flows move to the stored values one area at a time. In this release these
come from the row:

- The token lifetimes
  ([#527](https://github.com/qauth-labs/qauth/issues/527)):
  `ACCESS_TOKEN_LIFESPAN`, `DEV_ACCESS_TOKEN_LIFESPAN` and
  `REFRESH_TOKEN_LIFESPAN` set the lifetimes of a realm only while it has no
  policies (one a node of the previous release created during a rolling
  upgrade, until a node of this release boots again).
- The verified-account gate, the lowest password score and the failed sign-in
  lockout ([#528](https://github.com/qauth-labs/qauth/issues/528)):
  `REQUIRE_VERIFIED_ACCOUNT`, `PASSWORD_MIN_SCORE` and the four
  `FAILED_LOGIN_*` keys apply to a realm only while it has no policies, and
  each realm's own `accounts`, `password` and `bruteForce` policies apply once
  it has them. In particular, on a deployment that already ran this release,
  setting `REQUIRE_VERIFIED_ACCOUNT=false` no longer lets unverified accounts
  of the existing realms sign in; change the realm's stored policy instead.
- The mail transport and sender
  ([#529](https://github.com/qauth-labs/qauth/issues/529), see
  [Mail secrets move into the realm](#mail-secrets-move-into-the-realm)).
- Client registration
  ([#534](https://github.com/qauth-labs/qauth/issues/534)). `/oauth/register`
  and the clients API no longer write `DEFAULT_DYNAMIC_REGISTRATION_SCOPES`
  into a realm's list. A realm that has its policies is held to its own list,
  even an empty one; a realm with none yet, to the list its fill will hold,
  which the first boot stores. Whether a realm accepts an HTTPS URL as a
  `client_id`, its trust policy and its trusted domains are the realm's
  `registration.cimd` policy, which the authorization, consent and token
  endpoints and the realm's discovery documents read. `CIMD_ENABLED`,
  `CIMD_TRUST_POLICY` and `CIMD_TRUSTED_DOMAINS` seed a new realm only; the
  document cache, size and fetch timeout keys stay the deployment's.
- The environment ceiling, which the server read from the row before.

The verification link's lifetime and resend rule still read the environment.
Until an area has moved, the server still applies its keys to every realm, so
keep them set. At every boot the server names each seed key that is still set,
once:

- for a key whose policy the server reads from the row, a warning such as
  `DEFAULT_DYNAMIC_REGISTRATION_SCOPES only seeds new realms and is ignored`;
- for any other key, an info line that the stored policies ignore it, that
  the server still applies it to every realm until it reads that policy from
  the row, and that the stored value applies from then on.

For a key whose policy the server reads from the row, a second warning says
when the key is stricter than the stored value (`... is stricter than the
stored ...`), or, for a policy with no order such as `SMTP_HOST`, when it holds
another value (`... differs from the stored ...`): the stored value applies, so
store the key's value through the realm's policies if the realm should have it.
Nothing more is logged when they agree.

**A key changed after this upgrade never reaches the stored policies.** The
first boot stored the value each key had then. Change a key whose area has not
moved yet, and the server applies the new value while it reads the area from
the environment; the release that moves the area to the row applies the
stored value instead, whatever the key says by then. A key tightened in the
meantime, such as a lower `EMAIL_VERIFICATION_TOKEN_EXPIRY`, would loosen again
at that upgrade. So change the stored policy along with the key, not the key
alone. The token lifetimes, the sign-in policy and CIMD moved in the same
release as the policies themselves: a deployment that upgrades from 0.1 stores
those keys as they are at its first boot, and applies the stored values from
then on.

A realm's stored policies are changed with the admin API's realm policy
update, `realms.policies.update`
([#517](https://github.com/qauth-labs/qauth/issues/517)), on a process that
runs the admin listener. On a deployment without it, see
[Changing a realm's CIMD policy](/operate/docker/#changing-a-realms-cimd-policy).

**A value the policy schema refuses stops the boot.** The schema is stricter
than some keys were, so the server refuses to start, naming the key and never
its value, when a seed key holds one it refuses: a `CIMD_TRUSTED_DOMAINS` entry
that is a single label (`localhost`) or an IP address, an `EMAIL_FROM_NAME`
longer than 100 characters, a `DEFAULT_DYNAMIC_REGISTRATION_SCOPES` entry with a
character a scope cannot have. Correct the value and start the server again. A
value the fill keeps from a realm's row that the schema refuses, such as a
scope written into the allowlist by hand, stops the first boot too, naming the
realm and the field; a scope listed twice is kept once.

`SMTP_PASSWORD` and `RESEND_API_KEY` are never written to the row: they go to
the realm's secret store (see the next section). During a rolling upgrade a node of the
previous release reads none of the new columns and runs on the environment as
before. A realm such a node creates during the roll has no policies (counter 0)
until a node of this release boots again, since only the boot fills them, so
restart one node of this release once the roll is complete.

### Mail secrets move into the realm

From this release each realm sends its mail through its own transport and from
its own sender: `mail.provider`, `mail.fromAddress`, `mail.fromName` and
`mail.smtp.*` of its policies, read again for every mail
([#529](https://github.com/qauth-labs/qauth/issues/529)). The SMTP password and
the Resend API key are secrets: migration 0049 adds the `realm_secrets` table,
which holds each value encrypted with the realm's data-at-rest key and never
in the clear, and no response, log line, audit record or realm file shows one.
The realm's representation says only whether each is set (`passwordSet`,
`apiKeySet`).

**The first boot stores the environment's secret, once.** After the key boot
step, a node that holds the signer stores `SMTP_PASSWORD` (or
`RESEND_API_KEY`) of the environment in the default realm's secret store, and
records a key the environment does not set as unset, unless the realm's stored
transport needs it (`SMTP_PASSWORD` for `smtp`): that one stays unrecorded,
and the first boot whose environment sets it stores it. The log says
`realm secret seeded from the environment` at `info`. From then on the stored
value is used, and no later boot reads the key for that realm: each boot warns
`SMTP_PASSWORD only seeds the first realm's mail.smtp.password at its first
boot, and is ignored` while the key is still set. Remove both keys from the
environment once every node runs this release; until then a realm that a node
of the previous release created during the roll still sends with them.

**Other realms get the environment's secret where it is theirs.** The first
boot after the upgrade fills every realm's policies from the environment, the
mail transport included. Each realm whose stored transport is the
environment's and needs a secret it has no row for gets the environment's
value at that boot, or at the first later boot that can encrypt it (a realm
with no data-at-rest key yet is logged and tried again). Nothing is recorded
for a realm whose transport needs nothing.

**`SMTP_PASSWORD` goes only to its own server.** No realm whose stored
`mail.smtp.host`, `port` or `user` differs from `SMTP_HOST`, `SMTP_PORT` and
`SMTP_USER` is given `SMTP_PASSWORD`: the boot logs
`SMTP_PASSWORD is not stored in the realm "..."` as an error instead. Point the
environment at the realm's server, or set the realm's password through a policy
update. For the same reason a policy update that selects `smtp`, or changes
`mail.smtp.host`, `port` or `secure`, must give `mail.smtp.password` again.

**A mail transport that lacks a setting no longer stops the boot.**
`EMAIL_PROVIDER=smtp` without `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER` or
`SMTP_PASSWORD`, or `resend` without `RESEND_API_KEY`, used to refuse to start.
Now the realm's policy update refuses such a transport (422
`unprocessable_content`, with one JSON Pointer per refused field), the boot warns
for each setting or secret the default realm's stored transport lacks
(`the realm "master" cannot send mail: its mail.smtp.host is required ...`), and
a mail through it fails, logging the missing path.

**SMTP needs TLS and a public host (breaking).** A realm's smtp transport now
requires STARTTLS when `mail.smtp.secure` is off, checks the server certificate
against the host name, and connects only to a public address its host resolves
to: never `localhost`, a private, loopback, link-local or unique-local address,
or a cloud metadata address. A policy update that names `localhost` or such an
IP address as `mail.smtp.host` is refused. Only the operator can relax this,
for every realm, with two keys no realm policy can change:

- `SMTP_ALLOW_PLAINTEXT=true` lets a transport send without STARTTLS;
- `SMTP_ALLOWED_HOSTS` lists the hosts (names or IP addresses, comma-separated)
  a realm may name and reach although they are not public. A cloud metadata
  address stays refused.

A deployment that sends through a local plaintext relay, such as Mailpit on
`localhost:1025` or a relay container on a private Docker network, sets both
before it upgrades, for example `SMTP_ALLOW_PLAINTEXT=true` and
`SMTP_ALLOWED_HOSTS=localhost`; otherwise its mail fails, and the log names the
refused host. The boot logs an error for every realm whose stored SMTP host is
`localhost`, a non-public IP address not in `SMTP_ALLOWED_HOSTS` or a cloud
metadata address, or a listed relay that starts in the clear
(`mail.smtp.secure` false) while `SMTP_ALLOW_PLAINTEXT` is off
(`the realm "master" cannot send mail: its mail.smtp.host localhost is
localhost or a non-public address, which needs localhost in SMTP_ALLOWED_HOSTS
...`), and serves on. It resolves no host name: a name that resolves to a
private address is named when a mail connects to it.

**The `From` header carries the sender name.** Mail is now sent from
`EMAIL_FROM_NAME <EMAIL_FROM_ADDRESS>` as the realm stores them (`QAuth
<no-reply@example.com>` by default), where it used to carry the address alone.

The admin API's realm policy update, `realms.policies.update`
([#517](https://github.com/qauth-labs/qauth/issues/517)), changes a realm's mail
transport, sender and password; the environment keys no longer do. It takes
the password only sealed with `secrets.seal`, and with an approval. On a
deployment that runs no admin listener, replace a leaked or rotated
`SMTP_PASSWORD` or `RESEND_API_KEY` of the default realm by setting the new
value in the environment, deleting the realm's row for it, and restarting
every node:

```sql
DELETE FROM realm_secrets
 WHERE name = 'mail.smtp.password' -- or 'mail.resend.apiKey'
   AND realm_id = (SELECT id FROM realms WHERE name = 'master'); -- DEFAULT_REALM_NAME
```

The next boot of a node that holds the signer stores the new value, as at the
first boot. Restart every node, not one: a running node keeps the transport it
built for the realm until the realm's policies change, and deleting the row
changes none of them.

### Redirect URIs the consent screen cannot show

From this release the consent screen always says where the authorization code
goes, by the host of the redirect URI, "this device" for a loopback address,
or the app's own scheme
([#593](https://github.com/qauth-labs/qauth/issues/593)). Every registration
path refuses a redirect URI it cannot show: a host that is not a DNS name of
valid labels (an underscore, an empty label, a label with a hyphen at either
end), an IPv6 address that is not loopback, or a scheme longer than 64
characters. A client stored before the upgrade with such a URI breaks:

- **A CIMD client** whose document lists one no longer resolves once the
  server fetches its document again: the consent screen refuses it, and so does
  the token endpoint, where its next refresh answers `invalid_client`. Its
  owner changes the document; nothing on the server side fixes it.
- **A seed manifest** that names one is refused whole, so running
  `db:seed-oauth-clients` again changes no client until the URI is fixed or
  removed from the manifest.
- **A client registered dynamically, through `/api/clients` or by the
  manifest** keeps working for a user whose stored consent covers the
  request, but the consent screen answers a new user, or one whose request
  needs the screen, with `invalid_request` (400).

Before you upgrade, list the clients that break with the new release's
listing command ([#914](https://github.com/qauth-labs/qauth/issues/914)). It
applies the rule the consent screen applies, so it finds every such URI, and it
reads no column newer than migration 0023, so it runs against the 0.1 database
before the migration runner does. Run it from a checkout of the new release:

```bash
DATABASE_URL=postgresql://qauth:pw@db:5432/qauth \
  pnpm nx run infra-db:db:list-unshowable-redirect-uris
```

It lists the clients per realm (`-- --realm=<realm name>` for one realm), each
with the URIs the screen cannot show, why, and who can replace them. It exits
`0` when there are none and `1` when it lists any; Nx reports every other
failure as `1` too, so a script that must tell them apart runs
`pnpm --dir libs/infra/db exec tsx src/scripts/list-unshowable-redirect-uris.ts`,
which exits `2` on a usage error and `3` when it could not run. After the
upgrade, every boot of a node that serves the consent screen (the `web` role)
also names such clients in a `warn` line (`the client "…" of the realm "…"
has a redirect URI the consent screen cannot show …`), up to 20 of them, and
says when there are more.

Replace each URI with one the client can receive its code on, through the
client's own registration path, the seed manifest or, for a CIMD client, its
document, as the listing says for each client.

### Migration 0047 can meet a client registration in a deadlock

Migration 0047 ([#593](https://github.com/qauth-labs/qauth/issues/593)) adds
`oauth_clients.verified_domain`. The runner applies every pending migration in
one transaction, so when 0046 is in the same run it already holds `realms`
(0046 changes that table) when 0047 locks `oauth_clients`. A node of the
previous release that stores a new client at that moment (dynamic
registration, a CIMD client resolved for the first time, `/api/clients`, the
seeder) takes the two tables in the other order: `oauth_clients` for its
insert, then `realms` for the foreign key check. Postgres then aborts one of
the two with `deadlock detected`. If it aborts the client's request, that one
request fails and the client registers again. If it aborts the runner, the
whole run rolls back, nothing is half-applied, and the runner exits with an
error: run it again. A lock taken at the start of 0047 would not change the
order, since `realms` is held by then. To avoid the retry, run the migration
runner when no client is being registered, such as before the first node of
the new release starts and with open registration quiet.

### The operator provisions the system client

From this release the auth server no longer creates the developer portal's
system client as a secret-based client
([#631](https://github.com/qauth-labs/qauth/issues/631),
[ADR-017](/reference/records/adr/017-first-party-login/) phase F0). The operator
provisions it: a `private_key_jwt` client with the portal's public keys, the
first-party profile `web_redirect` and the portal's callback. Give the
migration runner `SYSTEM_CLIENT_REDIRECT_URI` and one of
`SYSTEM_CLIENT_JWKS_URI` and `SYSTEM_CLIENT_JWKS`, with the auth server's
`SYSTEM_CLIENT_ID` and `DEFAULT_REALM_NAME`, and the run that applies the
migrations provisions it too (see
[The system client](/operate/docker/#the-system-client)). The seed manifest's
`system_client` section does the same. The profile also waives the consent
screen
([#633](https://github.com/qauth-labs/qauth/issues/633), ADR-017 Decision 9):
once provisioned, the system client is issued codes at `/oauth/authorize`
without it, unless a request asks for a dangerous scope or `prompt=consent`,
and each such code is recorded as a
[`consent.administrative`](/reference/events/#consentadministrative-v1-rc0)
event.

Nothing breaks if you do not, yet. An existing system client row is kept as
it is, except that a row without the developer API's audience is given it
(see [the developer portal's token](#the-developer-portals-token-moves-to-the-developer-apis-audience)),
and the portal's sign-in keeps working through it; a realm that has none gets a
placeholder that holds no secret and no key, with that audience. The portal's
move to the redirect flow needs the provisioned row.

Migration 0048 adds `oauth_clients.first_party_profile`,
`first_party_policy` and `first_party_reason`, nullable with no default, and
six CHECKs that every existing row passes. The previous release keeps
creating and updating clients on the new schema.

Remove a client's first-party profile only after every node runs this
release. The removal revokes the client's refresh tokens under a lock that a
token write of this release waits for; a node of the previous release does not
take it, so a refresh token it commits while the profile is removed survives
the removal.

### The delivery role reads `realms.issuer`

From this release the [SSF transmitter](/operate/ssf-transmitter/) names a user
in its SETs under the realm's issuer, so the delivery role reads
`realms.issuer` ([#540](https://github.com/qauth-labs/qauth/issues/540)). A
deployment whose delivery role connects as the server's own database user needs
nothing, nor does one whose migration runner grants the roles' users
([below](#each-role-can-connect-as-a-database-user-of-its-own)). One that runs
it as a database user of its own, with the grants of
`eventDeliveryGrantStatements` from `@qauth-labs/infra-db` applied by hand,
gives that user the new column before the new version starts, by applying those
statements again or with the one statement they add:

```sql
GRANT SELECT ("issuer") ON TABLE "realms" TO <delivery_role>;
```

Nothing checks the grants at boot. Without this one, every SSF delivery
attempt fails with `permission denied for table realms` and is retried until
its attempts run out; the delivery role logs `a delivery route threw`.

### Each role can connect as a database user of its own

A split deployment can now give each service role a Postgres user with only
the grants it needs
([#498](https://github.com/qauth-labs/qauth/issues/498); ADR-019 Decisions 8
and 9). Nothing changes until you name the users: with no `DB_USER_*` variable
set, every role connects as the one user, which owns the tables, as before. To
split them, create the users, name them to the migration runner and give each
role's processes their own `DATABASE_URL`, as
[Topology](/operate/topology/#one-user-per-role) shows. Every runner run then
applies the grants after its migrations, so a later release that adds a table
needs no step of yours.

Migration 0055 adds `ssf_subject_events_pending`, a `SECURITY DEFINER` function
the SSF subject sweep calls instead of reading `events`, so the `api` role's
user holds no `SELECT` on the event store. `EXECUTE` on it is revoked from
`PUBLIC`; the grants give it to `api`. The previous release keeps running on
the new schema: it does not call the function.

A process whose only role is `delivery` no longer runs the default realm's boot
step, which creates and updates the realm row; its user may not write
`realms`. A process of any other role runs it, as before.

### Keep a relying party's `client_credentials` to the scopes it needs

A `client_credentials` token names no user, and until this release the grant
issued any scope of a client's `scopes`. So a relying party given the grant to
manage its [SSF stream](/operate/ssf-transmitter/#register-a-receiver) could
also get a token without a user for each scope its users grant it
([#891](https://github.com/qauth-labs/qauth/issues/891)). Migration 0051 adds
`oauth_clients.client_credentials_scopes`, nullable with no default and a CHECK
every existing row passes: the scopes that grant may issue, out of `scopes`.
NULL, every existing client's value, keeps the grant as it was, and the
previous release keeps creating and updating clients on the new schema.
From 0.2.3, a CIMD client is the exception
([#956](https://github.com/qauth-labs/qauth/issues/956)): without a list, the
grant issues it no token, and its `cimd_clients` entry in the seed manifest
sets the list
([Tokens a CIMD client gets as itself](/operate/docker/#tokens-a-cimd-client-gets-as-itself)).

After the upgrade, give every client that signs users in and holds
`client_credentials` the list, an SSF receiver's `["ssf:stream"]`, in its seed
manifest entry, and set it on the stored row (the seeder writes an existing
client only with `--rotate`, which also issues a new secret). A later
`--rotate` refuses an entry without the list for a client that has one, so the
manifest and the row stay in step.

The list takes effect on a node once that node runs this release. Until every
node does, a node of the previous release, which does not read the column,
still issues every scope of `scopes` on `client_credentials`. Setting the list
during the roll does no harm: such a node's writes to the client, a `--rotate`
of its seeder included, do not name the column and leave the list as it is.

Rolling back to an earlier release without restoring the backup lifts every
list, because its token endpoint ignores the column. The column and its values
are kept, and the lists apply again once the nodes run this release again;
restoring the backup from before the upgrade removes them with the column.

### New passwords meet one password policy

From this release `POST /auth/register` checks a new password against the
realm's password policy
([#634](https://github.com/qauth-labs/qauth/issues/634), ADR-017 Decision 8):
at least `password.minLength` characters after NFC normalisation, 15 by
default; not a common word or password, nor the address or the service's or
realm's name, as a whole; and a zxcvbn score of at least `password.minScore`.
A refused password answers `422` `weak_password` with its `reasons`. Existing
passwords keep working and are not checked again.

`password.minLength` is a new field of the realm policies. The first node of
this release to boot gives every realm that lacks it the seed
`PASSWORD_MIN_LENGTH` (15 when unset), as for any field a release adds. A
value below 8 refuses the boot; a value below 15 boots with a warning naming
`PASSWORD_MIN_LENGTH`, since NIST SP 800-63B-4 allows a shorter minimum only
for a password used within multi-factor authentication.

A password set from this release is hashed in Unicode NFC, and its credential
records `password_normalization: "nfc"` in `credential_data`. During a rolling
upgrade a node of the previous release ignores that member: it verifies the
password as typed. For a password typed already in NFC, which is what keyboards
and input methods produce for nearly all text, that is the same password. A
user whose new password contains a character typed in a decomposed form (an
`e` followed by a combining accent, for example) may be refused by a node of
the previous release until every node runs this release, and after a rollback.
A node of the previous release also still registers passwords under the old
rule (the score floor only) while it runs.

### Passwords on a breach list

From this release a realm can check passwords against a breach list
([#635](https://github.com/qauth-labs/qauth/issues/635), ADR-020 §3). The new
realm policy `password.breachListSource` is `off` in every realm after the
upgrade (the first node of this release gives every realm the seed
`PASSWORD_BREACH_LIST_SOURCE`, `off` when unset), so nothing changes until an
operator turns it on. Set `BREACHED_PASSWORD_LIST_PATH` (a file of SHA-1
digests, 40 hex characters a line, with an optional `:count`, at most
5,000,000 of them) for `local`, or
`BREACHED_PASSWORD_RANGE_URL` (an `https` URL whose path ends with `/`, such
as `https://api.pwnedpasswords.com/range/`) for `k_anonymity`; a private
mirror needs an `EGRESS_ALLOWLIST_PATH` entry naming the realms that use it.
Each node loads the local list at boot and again within 30 seconds of the file
changing (a new modification time, size or inode, so a file renamed into place
counts); a reload that fails keeps the list it had. A longer list does not load:
keep a corpus's most common passwords, not the whole corpus, and give each node
about 20 bytes a digest of memory, three times that while a reload builds the
next list. A realm that names a source the
deployment did not set up gets a failed check on every password, which lets
the sign-in through and is counted and recorded: watch
`qauth_breached_password_checks_total{result="failed"}` after turning a
source on.

Once a realm checks, `POST /auth/register` refuses a password on the list.
At sign-in the list is checked, and a new password asked for, only in the
Interaction API: with `INTERACTION_UI_ENABLED` on, a user whose password is on
the list is asked for a new one at their next sign-in, after a code mailed to
their address (or their second factor). The legacy `/ui/login`, which
`/oauth/authorize` still uses while the switch is off (the default), and
`POST /auth/login` check neither the list nor a pending update until they move
onto the sign-in engine ([#709](https://github.com/qauth-labs/qauth/issues/709)).

Migration 0059 adds the `user_required_actions` table, which holds the
`update_password` action the admin API and the account's "this wasn't me" will
ask for (no route writes it yet). During a rolling upgrade a node of the
previous release neither checks the list nor reads that table, and cannot read
a sign-in that a node of this release has marked for a password update: that
sign-in starts again on the older node and completes as before.

A deployment whose migration runner grants the roles' database users
([above](#each-role-can-connect-as-a-database-user-of-its-own)), or whose roles
connect as the one user that owns the tables, needs nothing. One that applies
the grants of each role's user by hand gives them the new table before the new
version starts, by applying the statements of `databaseUserGrantStatements`
from `@qauth-labs/infra-db` again or with the ones they add:

```sql
GRANT SELECT, INSERT, DELETE ON TABLE "user_required_actions" TO <web_role>;
GRANT SELECT, INSERT ON TABLE "user_required_actions" TO <api_role>, <admin_role>;
```

Nothing checks the grants at boot. Without the `web` one, every password
sign-in through the Interaction API is refused as unavailable, with
`permission denied for table user_required_actions` in the log.

### Password reset and the session epoch

With `INTERACTION_UI_ENABLED` on, the Interaction API's password step offers
the owner's password reset
([#642](https://github.com/qauth-labs/qauth/issues/642)). Migration 0062 adds
the `user_session_epochs` table: one row per user, written by the reset in the
transaction that replaces the password. Every browser session created before a
user's last reset, or within a second after it (the margin for the clocks of
two nodes), is ended at its next use. The auth server caches each user's
epoch in Redis for up to 60 seconds; Postgres stays the source of truth, and a
reset overwrites the cached value at once. The migration adds one table and
changes no row of another, so a node of the previous release keeps working on
the new schema during a rolling upgrade: it neither reads nor writes the table,
and so does not end a session a reset made older until it reaches a node of
this release.

A deployment whose migration runner grants the roles' database users, or whose
roles connect as the one user that owns the tables, needs nothing. One that
applies the grants by hand gives the `web` role's user the new table before the
new version starts:

```sql
GRANT SELECT, INSERT, UPDATE ON TABLE "user_session_epochs" TO <web_role>;
```

Without it, every request that reads a browser session (the authorization
endpoint among them) and every Interaction API sign-in fails, with
`permission denied for table user_session_epochs` in the log.

### Tokens record how the user signed in

From this release the ID token and the access token of a browser sign-in carry
`amr` and `auth_time`, and every refresh keeps both
([#662](https://github.com/qauth-labs/qauth/issues/662)). Migration 0065 adds
three empty columns for them: `authorization_codes.amr`,
`refresh_tokens.auth_time` and `refresh_tokens.amr`. It rewrites no row and
reads neither table: its CHECKs are added `NOT VALID`, because every existing
row is empty in the new columns. It first locks `authorization_codes` and then
`refresh_tokens`, in a redemption's order, so minting a code, redeeming one and
a refresh wait until the runner commits, which takes moments. The migration
sets no `lock_timeout`: run it when no long transaction holds either table.

Tokens issued from what existed before the upgrade carry less, until the user
signs in again:

- A browser session from before the upgrade gives its codes `auth_time` but no
  `amr`.
- A refresh family from before the upgrade, and one a node of the previous
  release refreshes during a rolling upgrade, gives its access tokens neither
  claim.

Both fail closed: a resource server that asks for a recent sign-in, or for a
given method, sends the user to sign in again.

### The account API reads sign-in methods and changes passwords

The account API serves `GET /account/v1-rc.0/sign-in-methods` and
`POST /account/v1-rc.0/password/change`
([#1107](https://github.com/qauth-labs/qauth/issues/1107)) on the `api` role.
The read counts the account's unused recovery codes, and the change clears the
account's `update_password` action, as the hosted account page's change does,
so the `api` role's database user gets two grants more. A deployment whose
migration runner grants the roles' database users
([above](#each-role-can-connect-as-a-database-user-of-its-own)), or whose roles
connect as the one user that owns the tables, needs nothing. One that applies
the grants by hand applies the statements of `databaseUserGrantStatements`
from `@qauth-labs/infra-db` again, or these, before the new version starts:

```sql
GRANT SELECT ON TABLE "user_recovery_codes" TO <api_role>;
GRANT DELETE ON TABLE "user_required_actions" TO <api_role>;
```

Nothing checks the grants at boot. Without the first the read answers `500`,
and without the second the change does, with `permission denied` for the table
in the log; the change then writes nothing.

A password set from this release records when it was set, in its credential's
`password_set_at`, which the read answers as `changedAt`. For a password set
before, the time was never recorded, and the read answers `null` until the
password is next set. During a rolling upgrade a node of the previous release
that changes or resets a password set on a node of this release leaves that
time behind, so `changedAt` names the earlier time until the password is set
again.

## Upgrading within 1.x

:::caution[Back up first]
Take the backup of [step 1](#1-back-up-the-database) before every upgrade.
Downgrades are not supported, within 1.x or otherwise: restoring the backup is
the only way back.
:::

This section is a stub until 1.0 ships. From 1.0 on, ADR-018 §5 promises:

- An upgrade within 1.x is the three steps above and nothing else: back up, run
  the new version's migration runner, start the new version.
- No 1.x migration is destructive. None drops or renames a table or column,
  narrows a column's type or deletes rows. A change of shape adds the new form
  beside the old one, so the previous version keeps working on the new schema
  while a rolling upgrade replaces its nodes.
- CI tests an upgrade from every earlier 1.x minor release.

That test runs today, before 1.0, from each release listed in
`upgrade-baselines.json` at the repository root. It starts the release, writes
data through its HTTP API, runs this version's migration runner and nothing
else, and starts this version. Then it checks that tokens issued before the
upgrade still introspect, the refresh token rotates, consents and API keys are
still there, and passwords still sign in. It then starts the old release again
on the migrated database and runs the same smoke tests. Until the 1.0 release
candidate, a failure of that last check is reported but does not fail CI.

## History: the migration 0011 runbook (ADR-002)

This runbook predates the migration runner: where it says
`pnpm nx run infra-db:db:migrate` or `drizzle-kit migrate`, run the migration
runner of Step 2 above. A failed migration is reported the same way, by name,
and rolls back.

QAuth's history contains one **destructive** schema migration you must plan
around: migration **0011** (ADR-002, issue [#230]), which permanently drops
`users.email`, `users.email_normalized`, and `users.password_hash`. Skipping
its precondition doesn't just fail the migration — it can **silently** strip
`email`/`email_verified` claims from existing users, including users whose
email was verified, without an error anywhere.

This section restates the runbook from `CHANGELOG.md`'s `[Unreleased]` section
of the time as an ordered procedure. **`CHANGELOG.md` is the source of record** — if the two
disagree, trust the CHANGELOG and the migration files in
`libs/infra/db/drizzle/`, and file an issue against this page.

[#230]: https://github.com/qauth-labs/qauth/issues/230

> **⚠️ No rollback after migration 0011.** Migration 0011 **drops columns**.
> Dropped columns cannot be reconstructed — password hashes are unrecoverable
> by design, and once `users.email` is gone there is no way to get it back
> from inside the database. **A full database backup taken immediately before
> running the migration is the only undo.** Restoring it discards every write
> made after the backup. Take the backup before Step 4 below, not after
> something looks wrong.

### Which path applies to you

| Your current deployment                                                                                                    | Path                                                                                                                                            |
| -------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| Already running a release at or after the #228/#229 dual-write cutover, not yet past #230 (migration 0011 not yet applied) | **One-hop** — go to [Step 3](#step-3-run-the-backfill-verification)                                                                             |
| Running anything older (pre-#228), or unsure                                                                               | **Two-hop** — go to [Step 1](#step-1-the-two-hop-precondition-pre-229-deployments-only)                                                         |
| A fresh install with no existing users                                                                                     | Migrations apply cleanly with no data to guard; skip to [Step 4](#step-4-back-up-the-database) as a formality, or just run the migration runner |

If you don't know which release you're running, check whether
`pnpm nx run infra-db:db:backfill-identity` exists as a target in your
deployed checkout's `libs/infra/db/project.json`. If it does, you're on the
dual-write release — one-hop. If it doesn't (as on current `main`, see below),
and you haven't already applied migration 0011, you need the two-hop path.

### Step 1: the two-hop precondition (pre-#229 deployments only)

**The backfill tooling has been deleted from the tree.** `db:backfill-identity`
(the nx target, `libs/infra/db/src/scripts/backfill-identity.ts`, and its
implementation under `libs/infra/db/src/lib/backfill/`) was added in #226 and
**removed** in the same commit that added migration 0011
(`29abe4a`, closing #230) — the CHANGELOG entry for that removal reads "#226
backfill machinery retired (git history is the archive...)". Current `main`
has no `db:backfill-identity` target at all — verify with
`pnpm nx show project infra-db --json | grep backfill` against your checkout.

This is what actually **gates** the two-hop path: it is not a runtime guard,
it is that the tool you need has already been deleted from anything at or
after migration 0011. If you're upgrading from before the #228/#229 dual-write
cutover, you cannot get the backfill tool by deploying current `main` — you
must:

1. Deploy a build from the commit range that has the backfill target: at or
   after `62886c9` (#226, "add idempotent ADR-002 identity backfill") and
   before `29abe4a` (#230, "drop legacy users identity columns").

   **Build `00c23f04`** unless you have a reason not to. It is the immediate
   parent of `29abe4a` — the newest state of `main` that still carries the
   backfill tool and migration 0010's dual-write behaviour, and does not yet
   carry migration 0011. Verify what you checked out before deploying it:

   ```bash
   git show 00c23f04:libs/infra/db/project.json | grep backfill-identity   # must match
   git ls-tree 00c23f04 libs/infra/db/drizzle | grep 0011                  # must be EMPTY
   ```

   **No release tag names this commit** — giving the hop a pinnable tag is
   tracked in [#362](https://github.com/qauth-labs/qauth/issues/362). Until
   then a SHA is the only precise instrument available, which is why this page
   gives you one rather than a tag that would be wrong.

   :::danger[`v0.1.0-rc.0` is not a safe starting point]
   The repository's first tag, `v0.1.0-rc.0` (2026-07-25), **postdates**
   migration 0011 and already contains the destructive drop, as every later
   release does. Deploying it as
   the "previous release" of a two-hop upgrade applies 0011 to a database that
   was never backfilled — which is the failure this whole page exists to
   prevent. Confirm for yourself with
   `git ls-tree v0.1.0-rc.0 libs/infra/db/drizzle | grep 0011`.
   :::

2. Run the [Step 3](#step-3-run-the-backfill-verification) backfill against
   that deployment.
3. Only then continue upgrading, release by release, until you reach the
   target release containing migration 0011.

Skip this step entirely if you're already on a release at or after the
dual-write cutover (#228/#229) and haven't applied migration 0011 yet — go
straight to Step 3.

### Step 2: understand the dual-write window (context, no action)

The release between #228 and #230 **dual-writes**: it writes both the legacy
`users.email`/`password_hash` columns and the new `user_credentials` /
`user_attributes` tables in the same transactions, so the two stay in sync.
This is why the CHANGELOG notes that `--refresh` is safe on that release even
though the backfill tool's own `--help` text calls `--refresh`
"PRE-CUTOVER ONLY" — the warning is about running `--refresh` against an
**older**, non-dual-writing release, where it would overwrite already-correct
rows with stale legacy-column data. On the dual-write release itself, the two
sources are equal by construction, so refreshing is a no-op-safe reconciliation.

### Step 3: run the backfill verification

Run this against the dual-write release (#228/#229) — either the one you're
already on (one-hop), or the intermediate one you deployed in Step 1 (two-hop):

```bash
pnpm nx run infra-db:db:backfill-identity -- --refresh
pnpm nx run infra-db:db:backfill-identity -- --verify-only
```

**Both commands must exit `0`.** `--verify-only` confirms every user has a
`(self_reported, email)` `user_attributes` row (among the other identity
rows the backfill populates).

**If `--verify-only` exits non-zero:** do not proceed. Something did not
backfill cleanly — re-run `--refresh` and `--verify-only` again; if it still
fails, this is a data problem to resolve before touching schema, not something
migration 0011's guard will explain further (its guard message is deliberately
terser — see Step 5).

**Why this matters, concretely:** without a clean backfill, existing users —
**including users with a verified email** — silently lose their `email` and
`email_verified` claims on token, refresh, and userinfo responses once you're
past migration 0011. There is no error at request time; the claims are simply
absent, because claim resolution reads exclusively from `user_attributes`
after ADR-002, and nothing populates that table except this backfill (or
normal post-cutover writes). This is the reason this page exists — do not
skip this step because the app "seems to still work" after upgrading. It will
appear to work until a user's client asks for their email.

### Step 4: back up the database

Immediately before running the migration. This is your only undo (see the
warning at the top of this page).

```bash
# Adjust host/container/credentials to your deployment.
docker exec qauth-postgres pg_dump -U qauth -d qauth -F c -f /tmp/qauth-pre-0011.dump
docker cp qauth-postgres:/tmp/qauth-pre-0011.dump ./qauth-pre-0011.dump
```

Confirm the dump file is non-empty and, if you can afford the time, that it
restores cleanly to a scratch database before proceeding.

### Step 5: optional — preflight the migration's own guard

Migration 0011 opens with an in-SQL guard (`libs/infra/db/drizzle/0011_striped_brother_voodoo.sql`)
that runs **before any DDL** in the same file and **aborts the entire
migration atomically** — zero schema changes applied — if it finds:

- any user with a `password_hash` but no matching `user_credentials` row
  (`provider_type = 'password'`), or
- any user with an `email` but no `user_credentials` row at all.

You can run the same two checks yourself first, without touching schema:

```sql
SELECT count(*) FROM users u
WHERE u.password_hash IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM user_credentials uc
    WHERE uc.user_id = u.id AND uc.provider_type = 'password'
  );

SELECT count(*) FROM users u
WHERE u.email IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM user_credentials uc WHERE uc.user_id = u.id
  );
```

Both should return `0`. If either doesn't, **stop** — go back to Step 3; the
migration will abort with the same finding, but finding it here costs you
nothing (this is a read-only `SELECT`, not a migration attempt).

If the guard fires anyway when you run the real migration, the error message
names the count of affected users on each side and tells you to re-run the
Step 3 backfill runbook. **No data is modified when the guard fires** — the
whole file rolls back (drizzle-kit runs each migration file in a transaction),
so it's safe to fix the underlying data and simply retry.

### Step 6: apply migration 0011, before starting the new release

```bash
pnpm nx run infra-db:db:migrate
```

**Ordering matters and is asymmetric.** Apply this migration **before**
starting any instance of the release that expects it — the new binary writes
only the ADR-002 tables (`user_credentials` / `user_attributes`), not the
legacy columns, so an old-schema database fed new-binary traffic accumulates
writes the still-there legacy columns won't reflect. Unlike the direction
above (guarded by migration 0011's own precheck), **this direction has no
in-SQL guard** — nothing stops you from starting the new binary against an
unmigrated database. Sequence your rollout so the migration completes first.

**What you'll see on success:** the migration applies, in this order (reading
straight from `0011_striped_brother_voodoo.sql`):

- `email_verification_tokens` drops its `email_verification_tokens_user_id_users_id_fk`
  foreign-key constraint (the column it references is dropped last, below).
- Four indexes on the legacy columns are dropped:
  `idx_users_realm_email_normalized_unique`, `idx_users_email`,
  `idx_users_realm_email_enabled`, `idx_email_verification_tokens_user_id`.
- `email_verification_tokens.credential_id` is promoted to `NOT NULL`.
- `users.email` is dropped.
- `users.email_normalized` is dropped.
- `users.password_hash` is dropped.
- `email_verification_tokens.user_id` is dropped.

Plus a `NOTICE` if any in-flight email-verification tokens were deleted — see
[Step 7](#step-7-minor-operational-consequences-to-expect) below.

**What you'll see on the guard firing:** a `RAISE EXCEPTION` naming the two
counts above and telling you to deploy the backfill release and re-run
Step 3. `drizzle-kit migrate` reports this as a failed migration; nothing was
applied. Go fix Step 3, then re-run this step.

### Step 7: minor operational consequences to expect

Neither of these blocks the migration; both are one-time and self-healing:

- **In-flight email-verification tokens.** Migration 0011 first re-points any
  verification token minted without a `credential_id` at the user's password
  credential (an idempotent re-run of the #228 backfill), then deletes
  whatever remains unresolvable. An affected user's outstanding verification
  link stops working; they click "resend" once and get a new one. Nothing to
  action operationally — just don't be surprised by a small number of deleted
  rows in the migration's `NOTICE` output.
- **Normalized-case email in old UI strings.** For accounts created before
  #228, a few user-visible strings (the register response, the consent-screen
  address, log lines) switch from the original-case email to its normalized
  lowercase form, because the original-case string lived in the now-dropped
  `users.email` column and only the normalized form survives in
  `user_credentials`. Cosmetic only — sign-in and claim resolution are
  unaffected (email matching was always case-insensitive).

### Step 8: migration 0012 (no precondition, any time after 0011)

A later migration drops two more columns —
`users.email_verified` / `users.email_verified_at`
(`libs/infra/db/drizzle/0012_flat_morlocks.sql`) — but **needs no guard and no
special ordering**. They've had no writers since migration 0011 (verified
state has lived in `user_credentials.credential_data.email_verified` /
`user_attributes.verified` since then), and their one sanctioned reader was a
literal default value, not a real read. Apply it whenever you apply the rest
of that release's migrations — nothing to sequence around.

### Verify after applying 0011

- `pnpm nx run infra-db:db:migrate` exits 0 and the migration log shows 0011
  (and 0012, if applicable) applied.
- Log in as an existing user with a previously-verified email, through a
  client granted the `email` scope, and confirm `email`/`email_verified` are
  present in the ID token, the userinfo response and the access token — this is
  the concrete symptom of a skipped backfill, so check it explicitly rather than
  assuming Step 3 worked. Without the `email` scope all three omit the claims
  by design.
- Spot-check a user created before #228 for the normalized-email cosmetic
  change (Step 7) so it doesn't get reported as a bug later.

## See also

- [Docker](/operate/docker/) — the `migration-runner` service; its
  Troubleshooting section points back here for a migration 0011 failure.
- [Configuration](/operate/configuration/) — `DB_MIGRATION_WAIT_MS`, the auth
  server's wait for missing migrations at boot.
- [Keys](/operate/keys/) — the key store and the KEK that the upgrade to 0.2
  moves the key variables into.
- [Topology](/operate/topology/) — the hosts, roles and proxy rules a 0.2
  deployment follows.
