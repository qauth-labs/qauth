# ADR-012: Ownership of Dynamically Registered Clients

**Status:** Accepted
**Date:** 2026-08-31
**Authors:** QAuth Team

## Context

`oauth_clients.developer_id` is the only ownership signal the schema has, and
every developer-facing query is an equality match on it —
`listByDeveloper(developerId)` for the list, `client.developerId !== developerId`
for per-client access, with a `404` rather than a `403` so the API never confirms
a client the caller does not own.

Both self-registration paths created rows with `developer_id: NULL`
(`routes/oauth/register.ts`, `helpers/cimd.ts`). `NULL` satisfies no equality
predicate, so such a client could not be listed, viewed, edited, deleted, or have
its secret regenerated from the developer portal. `README.md` describes CIMD as
the primary client-registration path, so the route the project positions first
produced clients nobody could administer — and nothing in the product said so
(#374).

The question this record settles is not "is that a bug" but **what ownership
should mean for a client that registered itself.**

## Decision

### 1. A DCR registration that carries a developer access token is attributed

`POST /oauth/register` stays open-mode: no `initial_access_token`, no
authentication required. But when the request _does_ carry a verified developer
access token, the client is created owned by that token's `sub`.

The token goes through `requireJwt`'s own verification — this server's issuer
pinned (RFC 9700 mix-up defence), signature checked, revocation honoured — and
the owner is taken from the token's `sub`, so a developer can only ever attribute
a client to themselves. It grants nothing that authenticating to
`POST /api/clients` would not already grant.

A token that does not verify, or whose `sub` is not a user UUID (a
`client_credentials` token's `sub` is a client id), is **rejected** rather than
silently ignored. A caller presenting a token is asking for attribution; quietly
registering an unowned client instead would reproduce the very failure this
record exists to fix — a client the developer believes they own and cannot find.

### 2. An anonymous registration stays unowned, and that is deliberate

A client that registers with no credential has no developer to attribute to.
Inventing one would hand an anonymous caller's client to whoever the server
guessed, which is worse than leaving it unowned.

This is the same trust boundary the codebase draws everywhere else: `environment`
and `max_agent_mode` are pinned to their safe defaults on self-registration
precisely because self-asserted input must not become server-established fact.
`developer_id` is an authorization fact.

### 3. A CIMD client is never portal-manageable

Not merely unowned today — **not ownable**, for a mechanical reason rather than a
philosophical one.

`upsertCimdClient`'s `ON CONFLICT` set refreshes `name`, `description`,
`redirectUris`, `grantTypes`, `responseTypes`, `tokenEndpointAuthMethod`, `jwks`,
`jwksUri`, `isAgent`, `metadata` and `enabled` on **every** re-resolution of the
`client_id` URL. `PATCH /api/clients/{id}` permits `name`, `description`,
`redirectUris`, `scopes`, `grantTypes`, `responseTypes`,
`tokenEndpointAuthMethod` and `enabled`.

Every field a developer could edit — except `scopes` — is overwritten the next
time the document is resolved, bounded by `CIMD_CACHE_DEFAULT_TTL` (300s) and
`CIMD_CACHE_MAX_TTL` (3600s). An adopted CIMD client would accept a developer's
edits and silently revert them within minutes. **Ownership without editability is
a worse lie than no ownership**, so the claim flow #374 floats is rejected on
that ground.

The positive statement matters more than the refusal: **a CIMD client's metadata
document IS its management surface.** Edit the document; the row refreshes on the
next authorize. That is not a workaround, it is the design — the document is the
source of truth, which is exactly why a second, divergent one must not exist.

### 4. The developer-scoped predicate is never widened

`GET /api/clients` must not become `WHERE developer_id = $1 OR developer_id IS
NULL`, and neither must any future developer-scoped query.

QAuth is multi-tenant within a realm, and that equality predicate is the only
tenant boundary on this table. Widening it would return every party's
dynamically registered clients to every developer, defeating the enumeration
defence the route goes out of its way to maintain. If unowned clients ever need
to be visible, that is an **operator** surface with its own role and its own
route — not a relaxed predicate on the developer route. No operator role exists
today (`users` has no role column), so this is a genuinely future concern.

### 5. No backfill

There is nothing to backfill from. Nothing in `oauth_clients` or `audit_logs`
records a developer for a self-registered client — the DCR audit row is written
with `userId: null`. A migration that guessed an owner would fabricate an
authorization fact. No migration is required by this record.

### 6. RFC 7592 is the reversible future path for DCR

RFC 7592 (`registration_access_token` + `registration_client_uri`) is the
standard-blessed management surface for a dynamically registered client, and it
is absent from the tree. It is the right answer for an anonymous DCR client that
later needs managing, and it needs no ownership column: the credential returned
at registration IS the management credential.

Naming it here is deliberate — it keeps decision 2 reversible without inviting a
non-standard claim flow in the meantime.

## Consequences

- A developer who registers through DCR **with** their token gets a client that
  behaves exactly like one created through `POST /api/clients`. Unlike CIMD,
  DCR clients are inserted once and never re-derived, so an edit sticks.
- An anonymous DCR client and every CIMD client remain unmanageable from the
  portal. The product now **says so** — in the API reference beside the list
  endpoint, and in the portal guide — rather than presenting an unexplained empty
  list.
- The developer-facing audit feed (not yet built) inherits this: its empty state
  must distinguish "no activity" from "your clients cannot be attributed". That
  decision is already recorded in the dashboard specification; this record is
  what it should cite for the reason.

## Alternatives considered

| Alternative                                                       | Why not                                                                                                                                 |
| ----------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| Attribute every registration to some inferred owner               | Fabricates an authorization fact from an anonymous request.                                                                             |
| A CIMD claim flow (prove control of the origin, adopt the client) | The adopted client's edits are reverted on the next re-resolution — see decision 3.                                                     |
| Realm-scoped operator visibility instead of ownership             | A real and reasonable feature, but a different surface with a different authorization model. No operator role exists to hold it.        |
| Leave it undocumented                                             | The status quo, and the reason #374 was filed: the gap was invisible precisely because the portal cannot show a client it cannot query. |

## Related

- Issue #374 — the report this record settles
- [ADR-007 §2](./007-mcp-first-positioning.md) — MCP-first positioning; CIMD as the primary registration path
- [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591) — Dynamic Client Registration
- [RFC 7592](https://datatracker.ietf.org/doc/html/rfc7592) — Dynamic Client Registration Management (the unimplemented future path)
