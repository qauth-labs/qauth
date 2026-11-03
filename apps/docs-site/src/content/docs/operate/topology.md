---
title: Topology
description: How a QAuth deployment is laid out — one host and one issuer per realm on a dedicated host, DNS and TLS per realm, endpoint hosts for server-side callers, service roles and mutual TLS between them, database users, and the reverse proxy in front.
sidebar:
  order: 1
lastVerified: '2026-11-03'
---

This page describes the layout of a QAuth deployment, as
[ADR-019](/reference/records/adr/019-deployment-topology-and-trust-boundaries/)
fixes it. It says what this release does, and marks what a later release adds.
The pages it links to have the details.

A deployment in its simplest form, which this release runs by default:

```text
browser ──https──▶ reverse proxy ──▶ auth server (SERVICE_ROLES=all) ──▶ Postgres, Redis
                   auth.example.com     │
                                        └─ internal listener, 127.0.0.1:3443: /internal/metrics
developer portal ──http://auth-server:3000──▶ auth server   (an endpoint host)
```

## One host and one issuer per realm

Each realm has its own host and its own issuer. The issuer's host is the
realm's **primary host**. Every URL the realm publishes is built from its row
in the database, never from the request: the issuer, the discovery and JWKS
URLs, every endpoint URL, the links in mail, redirect targets, and the cookie
and passkey settings.

- **The default realm** takes its issuer from `JWT_ISSUER` at its first boot,
  and its name from `DEFAULT_REALM_NAME` (`master` by default).
- **The issuer and the primary host are permanent.** Tokens, registered
  clients, enrolled passkeys and federation partners depend on them. A
  database trigger refuses to change them, and a boot whose `JWT_ISSUER`
  differs from the stored issuer refuses to start. Choose the host with care:
  it cannot be fixed later.
- **A host belongs to one realm.** A host is the primary host or an endpoint
  host of exactly one realm. The `realm_hosts` table keeps it, unique across
  every realm and both kinds. A wildcard host is refused.
- **The host is a name.** An IP address cannot be a primary host, because a
  passkey RP ID cannot be one. Plain `http` is accepted for `localhost` and
  `*.localhost` only.

This release runs one realm, the default realm. No route or command adds a
second one yet; the admin API's realm lifecycle operations
([#694](https://github.com/qauth-labs/qauth/issues/694)) will.

## A dedicated host, never a path

QAuth needs a host of its own. It never runs under a path of a shared host,
such as `https://example.com/auth`:

- the browser session lives in a `__Host-` cookie, which must carry `Path=/`
  and no `Domain`, so it belongs to the whole host;
- a passkey is bound to its relying party ID, which is a host, not a path.

Two realms on one host would share one session cookie and one RP ID, so
path-based realms are refused. A deployment upgraded from 0.1 whose
`JWT_ISSUER` has a path keeps working, with a warning at every boot: only the
host routes requests. A new realm's issuer is an origin with no path.

## DNS and TLS per realm

The operator provisions a DNS name and a TLS certificate for every realm host.
QAuth requests no certificate itself: automatic certificates (ACME) are not
part of 1.0. The reverse proxy terminates TLS and reads the certificate and
its key from files. One certificate may cover several realm hosts, or each
host may have its own ([Reverse proxy](/operate/reverse-proxy/#the-reference-configuration)).

Plan the hosts before the first boot. The default realm's host is permanent,
and the operator realm gets a host of its own when a second realm is added
([below](#the-operator-realm)).

## How a request finds its realm

A request belongs to the realm whose primary host or endpoint host equals the
request's host:

- The host comes from `Host` (`:authority` in HTTP/2). `X-Forwarded-Host`
  counts only when the hop that sent it is listed in `TRUST_PROXY`.
- The match is exact, ignores letter case and drops the port.
- A request for any other host gets `421 Misdirected Request`, before any
  route runs: no cookie, no realm data and no fallback to the default realm.
  The body is a problem document, or the OAuth error shape on an OAuth
  endpoint, with the detail `This server does not answer for the requested host`.
- `/health` and `/ready` answer on every host. They carry no realm data.

## Endpoint hosts

A server-side caller often reaches the auth server by another name than the
issuer's host: a container name, an internal load balancer, an IP address. The
operator lists such names as **endpoint hosts** of the realm. For the default
realm that is `DEFAULT_REALM_ENDPOINT_HOSTS`, a comma-separated list:

```bash
# The developer portal's AUTH_SERVER_URL is http://auth-server:3000.
DEFAULT_REALM_ENDPOINT_HOSTS=auth-server
```

- Each boot adds every listed host the realm lacks, and never removes one.
- A host already used by a realm, the issuer's own host included, refuses the
  boot.
- An endpoint host may be an IP address. A port is dropped; a scheme, path or
  wildcard refuses the boot.

An endpoint host answers the API endpoints: token, introspection, revocation,
userinfo, registration, discovery, JWKS, the `/auth/*` API routes, and the
account and developer APIs. It refuses the browser-session endpoints with
`421`: `/oauth/authorize`, `/ui/*`, the Interaction API, `/consents`,
`/auth/link/wallet` and the email verification page. A browser session lives
only on the realm's primary host.

Keep endpoint hosts on the internal network: the reference proxy configuration
answers `421` for them. No route removes an endpoint host yet. To remove one,
delete its row; each node may answer it for 30 seconds more, from its host
cache:

```sql
DELETE FROM realm_hosts WHERE host = 'auth.internal.example' AND kind = 'endpoint';
```

Then take it out of `DEFAULT_REALM_ENDPOINT_HOSTS`, or the next boot adds it
again.

## Service roles and mutual TLS

The auth server is one codebase that starts as one or more service roles,
picked by `SERVICE_ROLES`:

| Role       | Serves                                                                                                        |
| ---------- | ------------------------------------------------------------------------------------------------------------- |
| `web`      | The browser-session endpoints: authorize, the sign-in, consent and wallet pages.                              |
| `api`      | Token, introspection, revocation, userinfo, registration, discovery, JWKS and the account and developer APIs. |
| `admin`    | The admin API, on its own listener.                                                                           |
| `signer`   | The KEK, every private key and the signer.                                                                    |
| `delivery` | Event delivery: the SSF streams.                                                                              |

The default, `all`, runs every role in one process. That is one trust domain:
the key separation below protects keys only once the roles run on separate
nodes. [Service roles](/operate/service-roles/) gives the details.

- **Keys stay on the signer.** Only a process that holds `signer` receives the
  KEK and the private key variables; any other process refuses to boot with
  one. A process without the signer verifies tokens with each realm's published
  keys, which it reads without a KEK.
- **The internal listener.** A second HTTP server of each process, on
  `INTERNAL_HOST` and `INTERNAL_PORT` (`127.0.0.1:3443` by default), serves
  what only other parts of the deployment call: the metrics to a scraper, and
  the signer service to the other roles. It is not routed by host, and the
  public port serves none of its paths.
- **Mutual TLS.** While the roles are split, the internal listener speaks
  mutual TLS 1.3 only, with the certificates in `INTERNAL_TLS_CERT_PATH`,
  `INTERNAL_TLS_KEY_PATH` and `INTERNAL_TLS_CA_PATH`. `INTERNAL_PEER_ROLES`
  maps a peer certificate's SAN, such as a SPIFFE ID, to the role it calls as,
  or to `metrics` for a scraper. A peer without a mapped SAN gets `403`.
- **The signer service.** A process without the signer reaches it at
  `SIGNER_URL`, over mutual TLS. The signer service itself ships with
  [#497](https://github.com/qauth-labs/qauth/issues/497): until then such a
  process answers `503` wherever it would sign, and the browser-facing role
  must sit with the signer.
  [What a split deployment can do today](/operate/service-roles/#what-a-split-deployment-can-do-today)
  gives the split that works now.

Every role shares one Postgres database and one Redis. Refresh-token rotation,
single-use codes and consent revocation never split across databases.

## Database users

ADR-019 gives each role its own Postgres user with only the grants it needs.
Only the signer's user would read the private keys in `realm_keys`.

In this release every role connects with the one `DATABASE_URL`, so every
process can read every table, `realm_keys` included. The key separation
therefore rests on the KEK, which only signer processes hold: the private
keys in `realm_keys` are wrapped under it. The per-role users and the script
that grants them are [#498](https://github.com/qauth-labs/qauth/issues/498).

Some roles already have their grants defined, as statements in
`@qauth-labs/infra-db` an operator can apply to a user of their own:

| Helper                               | For                                                        |
| ------------------------------------ | ---------------------------------------------------------- |
| `eventsWriterGrantStatements`        | A role that writes events, with no read of the event table |
| `eventDeliveryGrantStatements`       | The `delivery` role                                        |
| `eventRetentionGrantStatements`      | The event retention job                                    |
| `adminAuditLogWriterGrantStatements` | A role that writes the admin audit log                     |

QAuth creates no database user: the operator does. A role that connects as a
user of its own needs these grants reapplied when a release adds one, as the
[upgrade guide](/operate/upgrades/#the-delivery-role-reads-realmsissuer) says
for 0.2's delivery role.

## The reverse proxy

QAuth runs behind a reverse proxy, which terminates TLS and enforces the host
and path rules. [Reverse proxy](/operate/reverse-proxy/) states the ten rules
and ships a reference nginx configuration. In short:

- Send each realm's primary host to the auth server, with the realm host as
  `Host`, and answer `421` for any other host. Only `/health` and `/ready`
  answer on every host.
- Route on the normalised path, and refuse encoded separators and `/ui`
  variants with `404`.
- Send `/ui/*` to the ceremony app, strip QAuth's cookies from it both ways,
  and set its security headers.
- At the first hop, overwrite `X-Forwarded-For`, `X-Forwarded-Host` and
  `X-Forwarded-Proto`, and set `TRUST_PROXY` on the auth server to the proxy's
  address.
- Answer `404` on the public side for `/metrics` and `/internal/*`.
- Make the auth server reachable only through the proxy.

The reference ceremony app has not shipped: until it does, the auth server
renders `/ui/*` itself and needs its session cookie there, so the reference
configuration is not yet a working front for browser sign-in.

## The operator realm

The operator realm is the realm whose admins administer the deployment: its
admins manage every realm, by grant, its service accounts automate the admin
API, and the admin console is its client.

In **simple mode**, one realm on one host, the default realm is also the
operator realm. Its first boot marks it so (`realms.is_operator`), and a
one-host deployment needs no second realm, host or issuer for administration.

Adding a second realm splits the two, in the **operator-realm split**. The
default realm keeps its host and its issuer, which are permanent. The operator
realm becomes a realm of its own, on a host of its own, and the operator's
admins and the admin console sign in there. Since no second realm can be added
in this release, the split cannot happen yet; the
[upgrade guide](/operate/upgrades/#the-operator-realm) will give its steps
with the realm lifecycle operations. Keep a host free for the operator realm,
so that it can get its DNS name and certificate then.

## See also

- [Upgrades](/operate/upgrades/#upgrading-from-01-to-02) — moving a 0.1
  deployment onto this topology.
- [Service roles](/operate/service-roles/) — the roles, the internal listener
  and the admin listener.
- [Keys](/operate/keys/) — the key store and the KEK.
- [Reverse proxy](/operate/reverse-proxy/) — the proxy rules and the reference
  configuration.
- [Docker](/operate/docker/) — the Compose stack, which runs one process with
  every role.
