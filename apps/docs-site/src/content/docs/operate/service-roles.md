---
title: Service roles
description: Run the auth server as one process, or split it into web, api, admin, signer and delivery processes with SERVICE_ROLES, and keep keys on the signer only.
sidebar:
  order: 12
lastVerified: '2026-10-26'
---

The auth server is one codebase that starts as one or more **service roles**
(ADR-019 Decision 8). `SERVICE_ROLES` picks them. The default, `all`, runs
every role in one process: a single deployment, which needs no change and is
one trust domain. A distributed deployment starts each role on its own nodes,
so that a node that faces browsers or API clients holds no KEK and no private
key.

## The roles

| Role       | What the process registers                                                                                                                                                                                           | Jobs                                                    |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| `web`      | The browser-session endpoints: authorize, the sign-in, consent and wallet pages, the consent list and wallet linking.                                                                                                | The session purge, when it ships                        |
| `api`      | Token, introspection, revocation, userinfo, dynamic registration, discovery, JWKS, the OID4VP endpoints a wallet calls, the account and developer APIs, the SSF transmitter and the legacy `/auth` routes.           | `purge-expired`: expired codes, tokens and wallet state |
| `admin`    | The admin API's internal listener, on `ADMIN_API_HOST` and `ADMIN_API_PORT` (`127.0.0.1`, port `3002`, by default). No admin operation and no key operation has shipped yet, so it serves only its OpenAPI document. | —                                                       |
| `signer`   | The KEK, every private key and the signer. It runs the default realm's key boot step.                                                                                                                                | Key rotation, when it ships                             |
| `delivery` | The event delivery reader, which sends the SSF streams.                                                                                                                                                              | `event-retention`                                       |

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
grant the KMS permission to the signer nodes only. Two secrets are not keys of
the signer yet and stay in the environment of the processes that use them:
`SESSION_COOKIE_SECRET` (below) and `OID4VP_RESPONSE_KEY_SECRET`, which wraps
the wallet response keys on `web` and `api` nodes.

## What a split deployment can do today

The signer service and the internal listener it answers on are not built yet.
Until they are, a process without the signer cannot sign anything, and warns
at boot:

- a request that needs a signature, an encryption or a cookie secret, such as
  token issuance or an ID-JAG assertion, answers `503` with
  `temporarily_unavailable`;
- an event delivery waits: the `delivery` role holds it without spending an
  attempt and offers it again every 30 seconds, until a signer answers.

Token verification (with each realm's published keys), the realm JWKS,
`/ssf/jwks.json`, discovery and the endpoints that sign nothing keep working.
Hybrid signing (`HYBRID_SIGNING_ENABLED=true`) describes what the signer
issues, so every process of a hybrid deployment sets it: a process without the
signer verifies hybrid tokens with the realm's published ML-DSA-65 keys, and
answers `503` when asked to sign one.

So the split that works today keeps every signing role together:

```bash
# Browser-facing nodes: no KEK, no private key.
SERVICE_ROLES=web
SIGNER_URL=https://signer.internal:3443
INTERNAL_TLS_CERT_PATH=/run/secrets/web.crt
INTERNAL_TLS_KEY_PATH=/run/secrets/web.key
INTERNAL_TLS_CA_PATH=/run/secrets/internal-ca.crt

# The nodes that sign: the KEK and the private keys live here only.
SERVICE_ROLES=api,admin,signer,delivery
KEK_PATH=/run/secrets/qauth-kek
JWT_PRIVATE_KEY_PATH=/run/secrets/qauth-ed25519.pem
```

Wallet sign-in builds its signed request on the node that serves
`/ui/wallet-login`, a `web` node, which may not hold the verifier key: a
profile that signs its requests cannot offer wallet sign-in on a split
deployment until the signer service ships. Route browser paths
(`/oauth/authorize`, `/ui/*`, `/consents`, `/auth/link/wallet`, and
`GET /auth/verify`, the email verification page) to the `web` nodes and every
other path to the others at the reverse proxy. `POST /auth/verify` is the
API's and stays on `api`: route `/auth/verify` by method.

`SESSION_COOKIE_SECRET` is still read from the environment. The `web` and
`api` roles read the session cookie (`api` for `/auth/logout`), so
`NODE_ENV=production` requires it on a process holding either; an `admin`,
`signer` or `delivery` process starts without it. It moves to the signer with
the cookie key, after which only the `web` role receives it.

With `ENABLE_SWAGGER` on, only a process holding `api` serves the Swagger UI
and its spec under `/docs`.

A process holding `admin` runs the admin API on a second listener, beside the
public one, while `ADMIN_API_ENABLED` is on: on loopback by default, so a
single deployment does not expose it. A distributed deployment binds
`ADMIN_API_HOST` to its internal network. The listener grants nothing for a
caller's network position: every admin call needs an admin token
([API conventions](/reference/api-conventions/#the-admin-listener)). The public
listener never serves the admin API. `ADMIN_API_PORT` must differ from `PORT`.

## See also

- [Configuration](/operate/configuration/): every key, `SERVICE_ROLES` among
  the stable ones.
- [Keys](/operate/keys/): the key store and the KEK.
- [Reverse proxy](/operate/reverse-proxy/).
