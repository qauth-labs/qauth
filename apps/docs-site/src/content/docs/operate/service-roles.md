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
| `admin`    | The [admin listener](#the-admin-listener), the admin API's own, while `ADMIN_API_ENABLED` is on (off by default), on `ADMIN_API_HOST` and `ADMIN_API_PORT` (`127.0.0.1`, port `3002`, by default). No admin operation and no key operation has shipped yet, so it serves only its OpenAPI document. | `approval-expiry`: marks approvals for security operations that expired unused, and overwrites their nonce                                                                                      |
| `signer`   | The KEK, every private key and the signer. It runs the default realm's key boot step. While the roles are split, it also runs the [internal listener](#the-internal-listener), with mutual TLS.                                                                                                     | `key-rotation`: rotates the realms' keys on schedule ([Keys](/operate/keys/#the-scheduled-rotation))                                                                                            |
| `delivery` | The event delivery reader, which sends the SSF streams.                                                                                                                                                                                                                                             | `event-retention`                                                                                                                                                                               |

Every role answers `/health` (liveness) and `/ready` (the checks its roles
need) for its own process on the public port, and serves its metrics on the
internal listener ([Health and readiness](/operate/observability/#health-and-readiness)).
Write the roles as a comma-separated list, such as `SERVICE_ROLES=web` or
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

Each role can also connect as a database user of its own, which holds only what
the role's repositories, boot steps and jobs read and write
([#498](https://github.com/qauth-labs/qauth/issues/498)). The migration runner
grants them; [Topology](/operate/topology/#one-user-per-role) shows how. A
process whose only role is `delivery` then skips the default realm's boot step,
since its user may not write `realms`.

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
grant the KMS permission to the signer nodes only. The wallet sign-in holds no
key either: the signer signs its request objects with the realm's OID4VP
request key, which the key boot step imports from
`OID4VP_VERIFIER_SIGNING_KEY` once, and seals each per-request response key
with the realm's `data_at_rest` key (`web` seals, `api` opens). The certificate
chain and its anchors stay public configuration on `web` and `api`.
`OID4VP_RESPONSE_KEY_SECRET` is read only to open the response keys a release
before 0.2 stored with it, which expire within 15 minutes of the upgrade;
remove it once every node runs this release. `SESSION_COOKIE_SECRET` is no
longer a secret of those processes either: the browser cookies are signed with
the realm's cookie key from the signer (below).

## The internal listener

A further HTTP server of the process, the internal listener, serves what only
other parts of the deployment call (ADR-019 Decision 8): a process that holds
`signer` while the roles are split serves the other roles' calls to the signer
service there, and every process serves its metrics there to a scraper while
`METRICS_ENABLED` is on (`GET /internal/metrics`, see
[Observability](/operate/observability/#who-can-read-the-metrics)). It binds
to `INTERNAL_HOST` and `INTERNAL_PORT` (`127.0.0.1`, port `3443`, by default):
set `INTERNAL_HOST` to an address the other nodes and the scraper reach. A
single process (`SERVICE_ROLES=all`) signs in-process and serves the metrics
alone there; without the internal TLS files it serves them in plain HTTP, on a
loopback address only.

With the internal TLS files it serves mutual TLS only, TLS 1.3 and HTTP/1.1:

- `INTERNAL_TLS_CERT_PATH` and `INTERNAL_TLS_KEY_PATH` hold the certificate it
  serves, and `INTERNAL_TLS_CA_PATH` the CA certificates that issue every
  peer's. A client that presents no certificate, or one another CA issued,
  gets no HTTP answer. The CA file must hold only the CA that issues QAuth's
  peers: one that holds a public root CA, as a system bundle does, is refused,
  and one with no certificate marked `CA:TRUE` is warned of. Make the key file
  readable by the server's user only (such as a Kubernetes secret's
  `defaultMode: 0400`): the server warns when its group or others may read it.
- `INTERNAL_PEER_ROLES` maps a subject alternative name (SAN) of a peer's
  certificate to the role the peer calls as, as a JSON object, or to
  `metrics` for a metrics scraper, which may read the metrics and nothing
  else. A key with a `:` is a URI SAN, such as a SPIFFE ID, compared exactly;
  any other key is a DNS SAN, compared without regard to case. Wildcards, IP addresses and the
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

A process whose roles are split refuses to start, naming each setting, when
the three files or `INTERNAL_PEER_ROLES` are missing: neither the signer nor
the metrics are served without mutual TLS there. Map a scraper's SAN to
`metrics`, or set `METRICS_ENABLED=false` on a process no scraper reads. `INTERNAL_PORT` must differ from `PORT`, and from `ADMIN_API_PORT` where
the admin API runs. Every internal route sits under `/internal/`, and the
public listener serves none of them. The listener is not routed by host: an
internal route takes the realm from the request, not from the `Host` header.

The admin API keeps [its own listener](#the-admin-listener) and its own rule:
a peer certificate grants nothing there.

The signer service is the first module the listener serves to the other
roles: [The signer service](#the-signer-service) says how they call it.

## The signer service

A process that holds `signer` while the roles are split serves the signer to
the others on its internal listener (ADR-019 Decision 9), one `POST` route per
operation under `/internal/signer/v1-rc.0/`: signing a JWS, a hybrid token, a
webhook message, a client assertion or an OID4VP request object, encrypting
and decrypting with the realm's `data_at_rest` key, the cookie keys, a key
derived from the cookie key, checking a cookie's MAC, and the realm's
verification keys and JWKS. Every other process calls it through its
remote signer, which has the in-process signer's interface, so the same code
signs either way. A single process (`SERVICE_ROLES=all`) signs in-process and
never calls it.

- **The certificate names the caller.** The signer takes the caller's role
  from the SAN of its client certificate, as `INTERNAL_PEER_ROLES` maps it,
  never from the request, and holds each call to that role's grant. `api`
  signs access tokens, ID tokens, ID-JAGs and client assertions; `web` gets
  the cookie keys and signs the wallet sign-in's request objects; `delivery`
  signs Security Event Tokens, logout tokens and webhook messages; `admin`
  reads public keys and seals the values of its own operations. The signer
  sets each token's `iss` and `kid` itself. A call the role may not make gets
  `403`, and each refusal is logged with the role and the operation and
  counted in `qauth_signer_refusals_total`
  ([Observability](/operate/observability/#metrics-get-internalmetrics)).
- **One role per process.** A process calls as the one role its certificate
  maps to, so one that holds two roles without the signer, such as `web,api`,
  warns at boot: the signer refuses the calls of the other role, and those
  requests answer `503`. Give each role its own process and certificate.
- **The signer's name is pinned.** The caller sends a call only to a server
  whose certificate holds `SIGNER_SAN`, a DNS name or a URI such as
  `spiffe://example.org/qauth/signer`, or `SIGNER_URL`'s host name when it is
  unset. A `SIGNER_URL` that names an IP address needs `SIGNER_SAN`, or the
  process refuses to boot.
- **The cookie key stays with `web`.** Whoever holds a realm's cookie key can
  make a session cookie, so only `web` gets it. `api` needs two things of it,
  and gets them without it: the keys the failure ladder and the emailed
  code's digests are made with, which the signer derives from the cookie key
  with HKDF for one use each and which make no cookie, and, at
  `/auth/logout`, a session cookie's MAC, which the signer checks and answers
  only whether it holds. A process keeps the derived keys in memory and
  reads them again every minute, so a sign-in makes no signer call.
- **Bounded.** A call carries at most 64 KiB of JSON, or 2 MiB for one that
  carries claims, a message or data: the caller refuses a larger one before it
  sends it, and the signer answers `413`. Each peer certificate has 2,000
  tokens a second after a burst of 4,000, a call costing one token and one
  more per 16 KiB of its body, and at most 128 calls in flight (`429` with
  `Retry-After`); the internal listener holds at most 256 connections per peer
  certificate. A role refused for its grant is refused before its body is
  read. Processes that share a certificate share these caps. Every answer is
  `Cache-Control: no-store`, and the warnings of a refused peer are logged at
  most once a minute per peer and operation.
- **Nothing secret in an error.** An error answer and its log line name the
  operation, the role and the error's class, never a claim value, a plaintext
  or key material; a body that is not JSON is refused without being quoted.

The caller gives each attempt 2 seconds. A call that changes nothing on the
signer (a read, a decryption) is tried once more after an outage; a signature
or an encryption is not. After 5 outages in a row, calls answer at once for 5
seconds, then one call at a time tests the signer, and the first answer opens
the way again: a restarted signer is used again with no restart of its
callers. A call that fails answers `503` with `temporarily_unavailable`, so
while the signer is down a request that needs a signature, an encryption or a
cookie key answers `503`: token issuance, an ID-JAG assertion, a browser page
that sets a signed cookie. An event delivery waits meanwhile: the `delivery`
role holds it without spending an attempt and offers it again every 30
seconds.

What reads public keys keeps working through an outage. A process without the
signer reads each realm's verification keys and JWKS from the keys the realm
publishes (`realm_public_keys`), at most once a minute, not from the signer:
token verification, the realm JWKS, `/userinfo` and introspection answer as
before, and `/ssf/jwks.json` and discovery need no signer either. A `web`
process keeps the cookie keys in memory and reads them again every minute,
or as soon as a cookie names a key it does not know yet. The internal TLS
files are read again every five seconds, as the listener reads them, and a
rotated certificate is used for the next calls.

Hybrid signing (`HYBRID_SIGNING_ENABLED=true`) describes what the signer
issues, so every process of a hybrid deployment sets it: a process without the
signer verifies hybrid tokens with the realm's published ML-DSA-65 keys.

A deployment with every role apart:

```bash
# The signer nodes: the KEK and the private keys live here only. Their
# certificate holds the SAN spiffe://example.org/qauth/signer.
SERVICE_ROLES=signer
KEK_PATH=/run/secrets/qauth-kek
JWT_PRIVATE_KEY_PATH=/run/secrets/qauth-ed25519.pem
INTERNAL_HOST=0.0.0.0
INTERNAL_TLS_CERT_PATH=/run/secrets/signer.crt
INTERNAL_TLS_KEY_PATH=/run/secrets/signer.key
INTERNAL_TLS_CA_PATH=/run/secrets/internal-ca.crt
INTERNAL_PEER_ROLES={"spiffe://example.org/qauth/web":"web","spiffe://example.org/qauth/api":"api","spiffe://example.org/qauth/delivery":"delivery","spiffe://example.org/qauth/admin":"admin","spiffe://example.org/prometheus":"metrics"}

# The api nodes: no KEK, no private key, no SESSION_COOKIE_SECRET. Their
# certificate holds spiffe://example.org/qauth/api. The web, delivery and
# admin nodes are alike, each with its role's certificate.
SERVICE_ROLES=api
SIGNER_URL=https://signer.internal:3443
SIGNER_SAN=spiffe://example.org/qauth/signer
INTERNAL_HOST=0.0.0.0
INTERNAL_TLS_CERT_PATH=/run/secrets/api.crt
INTERNAL_TLS_KEY_PATH=/run/secrets/api.key
INTERNAL_TLS_CA_PATH=/run/secrets/internal-ca.crt
INTERNAL_PEER_ROLES={"spiffe://example.org/prometheus":"metrics"}
```

Route browser paths (`/oauth/authorize`, `/ui/*`, `/consents`,
`/auth/link/wallet`, and `GET /auth/verify`, the email verification page) to
the `web` nodes and every other path to the others at the reverse proxy.
`POST /auth/verify` is the API's and stays on `api`: route `/auth/verify` by
method. The pages' stylesheet and fonts, under `/assets/ui/`, are `api`'s too,
like the discovery documents: they are not browser paths, and the pages on the
`web` nodes link them.

### What a process without the signer cannot do

The signer decrypts a realm's mail secret for `api` only (ADR-019 Decision 9):
a mail the `web` role sends, such as an emailed sign-in code, is not sent for
a realm whose transport needs a stored secret (`mail.smtp.password` or
`mail.resend.apiKey`). The request answers as it would otherwise, and the log
names the realm. The `api` role's mail goes out.

`SESSION_COOKIE_SECRET` is optional on every process: only the key boot step,
on a process that holds the signer, reads it, to import it into the default
realm's key store or to replace the stored cookie key with it.
`NODE_ENV=production` refuses every value QAuth's examples published, on every
process.

With `ENABLE_SWAGGER` on, only a process holding `api` serves the Swagger UI
and its spec under `/docs`.

## The admin listener

A process holding `admin` runs the admin API on a second listener, beside the
public one, while `ADMIN_API_ENABLED` is on. It is off by default. The listener
binds to loopback by default.
Every admin call carries a DPoP-bound admin token and a proof for
`ADMIN_API_BASE_URL` followed by the call's path (#520), so where the listener
runs, the boot requires `ADMIN_API_BASE_URL`, the URL clients address the admin
API at, and `DPOP_ENABLED=true`; a process that runs the token endpoint needs
`DPOP_ENABLED=true` too, to issue admin tokens. The listener may then sit on
any address, behind a load balancer that terminates TLS and forwards to
`ADMIN_API_HOST` and `ADMIN_API_PORT`: a proof binds an admin call to its
method and URL, not to its body, so in production `ADMIN_API_BASE_URL` must be
`https`, unless both it and `ADMIN_API_HOST` name loopback, for a listener
reached from the machine alone. It grants nothing for a caller's network position: every
admin call needs a DPoP-bound admin token, except
`GET /admin/v1-rc.0/openapi.json`
([API conventions](/reference/api-conventions/#the-admin-listener)). The public
listener never serves the admin API. `ADMIN_API_PORT` must differ from `PORT`.

## See also

- [Configuration](/operate/configuration/): every key, `SERVICE_ROLES` among
  the stable ones.
- [Keys](/operate/keys/): the key store and the KEK.
- [Reverse proxy](/operate/reverse-proxy/).
