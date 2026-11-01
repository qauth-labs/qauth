---
title: Service roles
description: Run the auth server as one process, or split it into web, api, admin, signer and delivery processes with SERVICE_ROLES, and keep keys on the signer only.
sidebar:
  order: 12
lastVerified: '2026-11-01'
---

The auth server is one codebase that starts as one or more **service roles**
(ADR-019 Decision 8). `SERVICE_ROLES` picks them. The default, `all`, runs
every role in one process: a single deployment, which needs no change and is
one trust domain. A distributed deployment starts each role on its own nodes,
so that a node that faces browsers or API clients holds no KEK and no private
key.

## The roles

| Role       | What the process registers                                                                                                                                                                                                                                                                          | Jobs                                                                                                                                                                                            |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `web`      | The browser-session endpoints: authorize, the sign-in, consent and wallet pages, the consent list and wallet linking.                                                                                                                                                                               | `interaction-expiry`: audits sign-in interactions that expired; `session-expiry`: marks browser sessions past their end; `session-purge`: deletes ended sessions after `SESSION_RETENTION_DAYS` |
| `api`      | Token, introspection, revocation, userinfo, dynamic registration, discovery, JWKS, the OID4VP endpoints a wallet calls, the account and developer APIs, the SSF transmitter and the legacy `/auth` routes.                                                                                          | `purge-expired`: expired codes, tokens and wallet state; `ssf-subject-sweep`: SSF user subjects whose relation ended                                                                            |
| `admin`    | The [admin listener](#the-admin-listener), the admin API's own, while `ADMIN_API_ENABLED` is on (off by default), on `ADMIN_API_HOST` and `ADMIN_API_PORT` (`127.0.0.1`, port `3002`, by default). No admin operation and no key operation has shipped yet, so it serves only its OpenAPI document. | —                                                                                                                                                                                               |
| `signer`   | The KEK, every private key and the signer. It runs the default realm's key boot step. While the roles are split, it also runs the [internal listener](#the-internal-listener), with mutual TLS.                                                                                                     | Key rotation, when it ships                                                                                                                                                                     |
| `delivery` | The event delivery reader, which sends the SSF streams.                                                                                                                                                                                                                                             | `event-retention`                                                                                                                                                                               |

Every role answers `/health` and `/metrics` for its own process. Write the
roles as a comma-separated list, such as `SERVICE_ROLES=web` or
`SERVICE_ROLES=api,signer,delivery`; `all` stands alone.

A process registers only what its roles use:

- the routes of its roles, from the route manifest
  (`apps/auth-server/src/app/route-manifest.ts`);
- the plugins those routes and roles call;
- the database repositories they read and write, and no other: a process
  without the `api` or `web` role never builds the clients repository, nor
  the users repository unless it holds `admin`, whose listener finds the
  admin's account there;
- the jobs placed on its roles. Run every role on at least one node, or its
  jobs never run.

## Keys stay on the signer

Only a process whose `SERVICE_ROLES` names `signer`, or is `all`, may hold key
material. Any other process refuses to boot, and names the variable, when one
of these is set:

- `KEK`, `KEK_PATH`, `KEK_PREVIOUS`, `KEK_PREVIOUS_PATH`, any other `KEK_*`
  setting of a KEK provider adapter, or `KEK_PROVIDER` naming an adapter rather
  than `local`;
- any `JWT_*_PRIVATE_KEY*` variable: `JWT_PRIVATE_KEY`, `JWT_RS256_PRIVATE_KEY`,
  `JWT_MLDSA_PRIVATE_KEY` and their `_PATH` forms;
- `OID4VP_VERIFIER_SIGNING_KEY` or `OID4VP_VERIFIER_SIGNING_KEY_PATH`.

A process without the signer reaches the signer service over mutual TLS, so it
needs `SIGNER_URL` (an `https` URL) and the internal TLS files
`INTERNAL_TLS_CERT_PATH`, `INTERNAL_TLS_KEY_PATH` and `INTERNAL_TLS_CA_PATH`,
or it refuses to boot. It needs no public key variable: a process with the
`web` or `api` role verifies each realm's tokens with the keys the realm
publishes in its key store (`realm_public_keys`), public material it reads
without a KEK, so its JWKS and discovery are the signer's own. A process that
holds the signer ignores `SIGNER_URL` and warns.

The check is by variable name. It cannot see the credentials a KEK provider
adapter takes from its cloud SDK's own settings or from the machine's identity:
grant the KMS permission to the signer nodes only. One secret is not a key of
the signer yet and stays in the environment of the processes that use it:
`OID4VP_RESPONSE_KEY_SECRET`, which wraps the wallet response keys on `web` and
`api` nodes. `SESSION_COOKIE_SECRET` is no longer one of them: the browser
cookies are signed with the realm's cookie key from the signer (below).

## The internal listener

A process that holds `signer` while the roles are split runs a further HTTP
server, the internal listener, for the other roles' calls to the signer
service (ADR-019 Decision 8). It binds to `INTERNAL_HOST` and `INTERNAL_PORT`
(`127.0.0.1`, port `3443`, by default): set `INTERNAL_HOST` to an address the
other nodes reach. A single process (`SERVICE_ROLES=all`) signs in-process
and runs none.

It serves mutual TLS only, TLS 1.3 and HTTP/1.1:

- `INTERNAL_TLS_CERT_PATH` and `INTERNAL_TLS_KEY_PATH` hold the certificate it
  serves, and `INTERNAL_TLS_CA_PATH` the CA certificates that issue every
  peer's. A client that presents no certificate, or one another CA issued,
  gets no HTTP answer. The CA file must hold only the CA that issues QAuth's
  peers: one that holds a public root CA, as a system bundle does, is refused,
  and one with no certificate marked `CA:TRUE` is warned of. Make the key file
  readable by the server's user only (such as a Kubernetes secret's
  `defaultMode: 0400`): the server warns when its group or others may read it.
- `INTERNAL_PEER_ROLES` maps a subject alternative name (SAN) of a peer's
  certificate to the role the peer calls as, as a JSON object. A key with a
  `:` is a URI SAN, such as a SPIFFE ID, compared exactly; any other key is a
  DNS SAN, compared without regard to case. Wildcards, IP addresses and the
  `signer` role are refused: the signer serves the listener and never calls
  it. A peer whose certificate holds no mapped SAN, or SANs mapped to two
  roles, gets `403` on every path.
- Each internal route admits only the peer roles its module names: a peer of
  another role gets `403` there.
- The listener reads its three files again every five seconds and serves new
  ones with no restart, once a rotation has written both the certificate and
  its key. A mesh's or a SPIFFE agent's certificates are files like any other,
  so either can issue them.
- The handshake checks a peer's certificate once per connection, so each
  request checks again: a request on a connection whose peer certificate has
  expired since, or that was made before the files were last reloaded (a CA
  replaced among them), gets `403`. Every `403` closes its connection, and the
  peer connects again under the files served then.
- It holds at most 1024 connections at once.

The process refuses to start, naming each setting, when the three files or
`INTERNAL_PEER_ROLES` are missing: the signer is never served without mutual
TLS. `INTERNAL_PORT` must differ from `PORT`, and from `ADMIN_API_PORT` where
the admin API runs. Every internal route sits under `/internal/`, and the
public listener serves none of them. The listener is not routed by host: an
internal route takes the realm from the request, not from the `Host` header.

The admin API keeps [its own listener](#the-admin-listener) and its own rule:
a peer certificate grants nothing there.

Until the signer service ships, `web` must sit with the signer: the settings
of the split that works today, with the internal listener, are in
[What a split deployment can do today](#what-a-split-deployment-can-do-today).

## What a split deployment can do today

The internal listener runs, but the signer service it is for is not built
yet (#497): no signer route answers on it. Until it is, a process without the
signer cannot sign anything, and warns at boot:

- a request that needs a signature, an encryption or a cookie secret, such as
  token issuance, an ID-JAG assertion, or a browser page that reads or sets a
  signed cookie (the sign-in, consent and wallet pages), answers `503` with
  `temporarily_unavailable`;
- an event delivery waits: the `delivery` role holds it without spending an
  attempt and offers it again every 30 seconds, until a signer answers;
- a mail of a realm whose transport needs a stored secret (`mail.smtp.password`
  or `mail.resend.apiKey`) is not sent, since the secret is decrypted through
  the signer: the request answers as it would otherwise, and the log names the
  realm. Send such mail from a process that holds the signer.

Token verification (with each realm's published keys), the realm JWKS,
`/ssf/jwks.json`, discovery and the endpoints that sign nothing keep working.
Hybrid signing (`HYBRID_SIGNING_ENABLED=true`) describes what the signer
issues, so every process of a hybrid deployment sets it: a process without the
signer verifies hybrid tokens with the realm's published ML-DSA-65 keys, and
answers `503` when asked to sign one.

The browser cookies are signed with the realm's cookie key, which only the
signer hands out (#493), so the browser-facing role needs a signer as much as
the roles that sign tokens do. So the split that works today keeps `web` with
every signing role, and only `admin`, which signs nothing, apart:

```bash
# The nodes that sign and serve the browser: the KEK and the private keys live
# here only, and the internal listener serves the other nodes over mutual TLS.
SERVICE_ROLES=web,api,signer,delivery
KEK_PATH=/run/secrets/qauth-kek
JWT_PRIVATE_KEY_PATH=/run/secrets/qauth-ed25519.pem
INTERNAL_HOST=0.0.0.0
INTERNAL_TLS_CERT_PATH=/run/secrets/signer.crt
INTERNAL_TLS_KEY_PATH=/run/secrets/signer.key
INTERNAL_TLS_CA_PATH=/run/secrets/internal-ca.crt
INTERNAL_PEER_ROLES={"spiffe://example.org/qauth/admin":"admin"}

# Admin nodes: no KEK, no private key. Their certificate holds the SAN
# spiffe://example.org/qauth/admin, which the signer's nodes map to admin.
SERVICE_ROLES=admin
SIGNER_URL=https://signer.internal:3443
INTERNAL_TLS_CERT_PATH=/run/secrets/admin.crt
INTERNAL_TLS_KEY_PATH=/run/secrets/admin.key
INTERNAL_TLS_CA_PATH=/run/secrets/internal-ca.crt
```

Once the signer service ships (#497), a `web` node without the KEK gets the
cookie keys from it and keeps them in memory, reading them again every minute.

Wallet sign-in builds its signed request on the node that serves
`/ui/wallet-login`, a `web` node, which may not hold the verifier key: a
profile that signs its requests cannot offer wallet sign-in on a split
deployment until the signer service ships. Route browser paths
(`/oauth/authorize`, `/ui/*`, `/consents`, `/auth/link/wallet`, and
`GET /auth/verify`, the email verification page) to the `web` nodes and every
other path to the others at the reverse proxy. `POST /auth/verify` is the
API's and stays on `api`: route `/auth/verify` by method.

The `web` and `api` roles read the session cookie (`api` for `/auth/logout`),
with the realm's cookie key from the signer (#493). Only the browser-facing
role receives the cookie keys from a signer service (ADR-019 Decision 9): on a
process that cannot read them, `/auth/logout` still ends the user's sessions and
tokens, and leaves the request's cookie for the next page to clear.
`SESSION_COOKIE_SECRET` is optional on every process: only the key boot step, on
a process that holds the signer, reads it, to import it into the default realm's
key store or to replace the stored cookie key with it. `NODE_ENV=production`
refuses every value QAuth's examples published, on every process.

With `ENABLE_SWAGGER` on, only a process holding `api` serves the Swagger UI
and its spec under `/docs`.

## The admin listener

A process holding `admin` runs the admin API on a second listener, beside the
public one, while `ADMIN_API_ENABLED` is on. It is off by default until the
first admin operations (#517) and DPoP-bound admin tokens (#520) ship. The
listener binds to loopback, and until #520 a production process refuses an
`ADMIN_API_HOST` that is not loopback (`127.0.0.0/8`, `::1` or `localhost`).
The listener grants nothing for a caller's network position: every admin call
needs an admin token, except `GET /admin/v1-rc.0/openapi.json`
([API conventions](/reference/api-conventions/#the-admin-listener)). The public
listener never serves the admin API. `ADMIN_API_PORT` must differ from `PORT`.

## See also

- [Configuration](/operate/configuration/): every key, `SERVICE_ROLES` among
  the stable ones.
- [Keys](/operate/keys/): the key store and the KEK.
- [Reverse proxy](/operate/reverse-proxy/).
