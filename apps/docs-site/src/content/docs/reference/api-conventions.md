---
title: API conventions
description: The rules every route of the admin, account and developer APIs follows — paths, names, errors, paging, concurrency, OpenAPI extensions and versioning.
sidebar:
  order: 3
lastVerified: '2026-10-31'
---

QAuth has three API families: admin, account and developer
([ADR-019](/reference/records/adr/019-deployment-topology-and-trust-boundaries/), Decision 7).
Every route of the three follows the rules on this page. The rules are part of the 1.0 stability
contract ([ADR-018 §5](/reference/records/adr/018-1-0-scope-and-stability/)), so they are fixed
before the families' first route. A test enforces them over the generated OpenAPI document
([Enforcement](#enforcement)).

The Interaction API (`/interaction/v1-rc.0`) reuses these rules, with the differences its own
page lists: its problem documents carry no prose, and its steps keep the names of the step grammar
([Interaction API](/reference/interaction-api/)). The OAuth protocol endpoints do not: they keep
the shapes their specifications define ([Errors](#errors)). The error format of [Errors](#errors)
is not limited to the families: every route that is not an OAuth protocol endpoint answers it.

## The three families

| Family    | Caller    | Path prefix          | Audience                          |
| --------- | --------- | -------------------- | --------------------------------- |
| admin     | Operator  | `/admin/v1-rc.0`     | `urn:qauth:aud:admin:v1-rc.0`     |
| account   | End user  | `/account/v1-rc.0`   | `urn:qauth:aud:account:v1-rc.0`   |
| developer | Developer | `/developer/v1-rc.0` | `urn:qauth:aud:developer:v1-rc.0` |

- The major version is in the path. Until QAuth 1.0.0 it is a release candidate, `v1-rc.<M>`, and
  nothing about it is promised ([Release candidates](#release-candidates)). A new major version is
  served under its own prefix, such as `/admin/v2`, beside the old one ([Versioning](#versioning)).
- Each token carries one audience, and a family accepts only its own. The audience identifiers
  carry a version, as ADR-018 §5 requires for every QAuth-defined identifier, and it is the same
  release candidate as the path's.
- The admin API's scopes are `qauth:admin:read`, `qauth:admin:write` and `qauth:admin:security`,
  in QAuth's reserved `qauth:` scope namespace, intersected with the caller's admin roles. The
  [admin permissions](/reference/admin-permissions/) page lists them with every permission and the
  built-in roles. The account and developer families define no scopes here: their guards check the
  token's audience, and that its subject is an active user or client of the request's realm
  ([Family tokens](#family-tokens)). A route that needs a scope adds it in its own change.

### Family tokens

Every family route is guarded by `requireFamilyToken(family, options)` in
`apps/auth-server/src/app/helpers/family-token.ts`. A token passes when:

- its signature verifies and it has not expired or been revoked, as on every bearer-protected
  route;
- its protected header carries `typ: at+jwt` (RFC 9068 §2.1), whatever
  `requireAccessTokenTyp` is set to;
- its `iss` is one the family accepts. The check is a hook, `IssuerResolver`. By default it
  accepts only the token issuer of the request's realm (ADR-019 Decision 1): `JWT_ISSUER` as
  written for the realm whose issuer it is, and the realm's own issuer for any other realm. The
  admin family's hook accepts the issuer of an enabled realm, and only a token that verifies with
  that realm's keys ([Admin authority](#admin-authority));
- it carries `sub`, `exp` and `jti`, with `sub` and `jti` non-empty strings;
- its `aud` holds exactly one value, the family's audience. A token with several audiences is
  refused even when one of them is the family's;
- on the developer and admin families, it carries no `act` claim. A delegated token (RFC 8693)
  never manages a developer's clients, and never stands for an admin's passkey sign-in: automation
  reaches the admin API as a service account. The account family accepts one, and an account route
  that changes a credential, an identifier, the contact address or a linked account, or deletes the
  account, refuses it itself (ADR-019 Decision 7);
- its subject is one the route admits (the required `subjects` option: `user`, `client` or both)
  and is active in the realm of the request (ADR-019 Decision 1). A `client_credentials` token,
  whose `sub` is its own `client_id`, must name a client of that realm that is enabled and not
  suspended; any other token must name a user of that realm who is enabled;
- it carries every scope the route lists.

A family audience reads the same in every realm. Tokens are signed per realm (#491): a token
verifies only with the keys of the request's realm and, under the default issuer rule, only when
its `iss` is that realm's issuer, so a realm admits its own tokens and refuses every other
realm's. The subject is checked
in the request's realm as well, whatever issuer rule a family uses: a user's token is refused in
every realm but the user's, and a `client_credentials` token in every realm whose client of that
`client_id` is missing, disabled or suspended.

A request that presents no token is refused with 401 `unauthorized` and a challenge that names no
error, `WWW-Authenticate: Bearer realm="OAuth"`. A token that fails, its subject included, is
refused with 401 and `WWW-Authenticate: Bearer error="invalid_token"` (`invalid_access_token`, or
`access_token_expired`). A token that lacks a scope is refused with 403 `forbidden` and
`WWW-Authenticate: Bearer error="insufficient_scope"`, whose `scope` names the scopes the route
needs, as on every route a wider token would let through. All three follow RFC 6750 §3.1, and the
body is a problem document with the code named in parentheses. A request under the `DPoP` scheme
gets a `DPoP` challenge instead (RFC 9449 §7.1). A family route therefore lists 401 in its
`x-qauth-errors`, and 403 when it requires a scope.

What a route does for its subject beyond that, such as reading the user's row again or checking a
role, is its own.

### Admin authority

An admin route decides what the token may do to the realm it names with
`resolveAdminAuthority({ iss, sub, scopes, targetRealmId })` in
`apps/auth-server/src/app/helpers/admin-authority.ts`
([ADR-019](/reference/records/adr/019-deployment-topology-and-trust-boundaries/), Decision 7). It
reads the admin grants and roles from the database on every request, never from token claims, so
a disabled account, a revoked grant or a disabled role counts from the next request, with the
same token.

1. The realm whose issuer is the token's `iss` must be enabled. Otherwise the token is refused
   with 401.
2. The subject must be an enabled account of that realm. Otherwise the token is refused with 401.
3. A token of the operator realm needs a live grant whose target is the requested realm or every
   realm.
4. Any other token is realm-local: the requested realm must be the issuer's own, with a live grant
   on it. The operator realm is never its target.
5. The permissions of the matching grants' roles, intersected with the token's scopes, are the
   permissions the request may use. The operation's own check answers 403 `forbidden` when the one
   it needs is missing.

A realm outside the caller's grants answers 404 `not_found`, exactly as a realm that does not
exist, so the answer never confirms that a realm exists.

Admin grants and custom admin roles live in `admin_grants` and `admin_roles`. A grant names a
built-in role or a custom role, and one realm or every realm. Only an account of the operator realm
holds a grant on every realm or on another realm than its own; the repository and the database
trigger `admin_grants_realm_rule` both refuse anything else. A custom role is defined in one realm
and granted only to that realm's accounts or for that realm. A grant is written live, at the
database's time (the trigger `admin_grants_insert_live`), revoked, never changed (the trigger
`admin_grants_revoke_only`), and a role is disabled, never deleted while a grant names it. A grant
is looked up by its id, or by its account's id, only within a realm: the realm it covers, or its
account's realm. It is revoked only from its account's realm, so a realm sees an operator-realm
admin's grant on it but cannot revoke it. A realm's operator flag, on which the rule rests, is written only by the realms
repository's `setOperator`, which the default realm's boot step calls.

Until each realm has its own issuer, the realm `JWT_ISSUER` names is the only realm whose tokens an
admin route accepts: `RealmIssuerDirectory` maps an issuer to its realm, and `IssuerKeyResolver`
verifies a token with that realm's keys, and both know only the deployment's issuer and today's
signing key.

### The admin listener

The admin API runs on its own internal listener, never on the public one
([ADR-019](/reference/records/adr/019-deployment-topology-and-trust-boundaries/), Decisions 7 and
8). A process that holds the `admin` service role serves it on `ADMIN_API_HOST` and
`ADMIN_API_PORT`, `127.0.0.1`, port `3002`, by default, while `ADMIN_API_ENABLED` is on
([Configuration](/operate/configuration/)). It is off by default until the first admin operations
(#517) and DPoP-bound admin tokens (#520) ship, and until #520 a production process refuses an
`ADMIN_API_HOST` that is not loopback (`127.0.0.0/8`, `::1` or `localhost`). The public listener
answers 404 `not_found` for every admin path, except a CORS preflight (`OPTIONS`), which it
answers as on any other path, naming nothing of the admin API. The admin OpenAPI document is
served on the admin listener only, at `/admin/v1-rc.0/openapi.json`, without a token: it
describes the operations and holds no realm data.

The listener grants nothing for a caller's network position: every other call, from loopback too,
needs an admin token. It never routes by host either. Every admin path names the realm it acts on,
`/admin/v1-rc.0/realms/{realmId}/...`, and the listener refuses to boot a route that does not.

Every admin route runs behind the same stages, in this order
(`apps/auth-server/src/app/admin/pipeline.ts`):

1. The request id, which the server makes for every call, never takes from the caller, echoes in
   the response and carries as `trace_id`.
2. The token guard ([Family tokens](#family-tokens)). The realm whose keys verify the token is
   the one its `iss` names. A call without a valid admin token gets 401 here, before any realm
   is read, and every such refusal reads the same, so the answer says nothing about realms.
3. The DPoP check, which requiring DPoP-bound admin tokens will fill (#520). Until then the
   listener takes only the `Bearer` scheme, and answers the `DPoP` scheme as no credential.
4. The realm, from the path.
5. The authority from grants and scopes ([Admin authority](#admin-authority)). A realm outside
   the caller's grants answers 404 `not_found`.
6. The classification and the permission check ([Security operations](/reference/security-operations/)).
   A caller without a permission the request needs gets 403 `forbidden`, with an
   `insufficient_scope` challenge when the token's scopes, not the caller's roles, are what is
   missing.
7. The approval gate. A request classified `security` runs only with the approval its
   `QAuth-Approval` header names, filed for exactly this request ([Approvals](#approvals)). Every
   other one answers 403 `approval_required` and never runs.
8. The handler, inside one database transaction. The transaction first consumes the approval
   stage 7 checked; a call that finds it used meanwhile answers 403 `approval_required`. The
   handler answers by returning its body: a handler
   that sends or hijacks the reply itself fails, so no answer leaves before its change commits.
   The body is serialized inside the transaction, so one its response schema refuses fails the
   call and its change rolls back.
9. The audit row, in the admin audit log of the realm the request acts on.
10. The error, as a problem document.

A route's own `onRequest`, `preParsing` and `preValidation` hooks would run before stages 6 and
7, so the listener refuses to boot an admin route that has one, in its options or added by its
module: use a `preHandler` hook or the handler. A `preHandler` refuses by throwing, never by
sending the reply; one that sends or hijacks it fails the call.

The listener also has request ceilings of its own, 100 calls a minute each, whatever
`RATE_LIMIT_MAX` and `RATE_LIMIT_WINDOW` say for the public listener, and answers 429
`too_many_requests` beyond them. `RATE_LIMIT_ENABLED` only chooses where the counts live: in
Redis, or in memory while it is off.

- Per client address, the calls the token guard refuses. Past that count, a call from the address
  that presents no token is refused before the token guard, and one whose token the guard refuses
  answers 429. A call that presents a `Bearer` token always reaches the token guard, so a valid
  token is never held back by the refusals of others from the same address.
- Per token subject, every call, right after the token guard.
- Per client address, every call to the OpenAPI document, which needs no token, in a count of its
  own.

The address is the TCP peer: the listener trusts no proxy, whatever `TRUST_PROXY` names for the
public listener. When the server shuts down, the listener takes no new call, lets each call in
flight finish for up to 8 seconds, closes the connections still open, waits up to 1.5 seconds
more for the audit rows of their calls, and closes before the database.

**Audit rows.** Every call that reaches a realm within the caller's grants writes exactly one row
to that realm's chain, reads included. A call that succeeds writes `succeeded` in the
handler's transaction, with the change the handler recorded, its secret fields masked: the row
and the change commit together, or neither does, and the answer is serialized before they do, so
the answer and the row always agree. A call refused after that point, such as one
without the permission or the approval, or whose body does not parse, writes `denied`; one that
fails on the server, its handler or commit included, writes `failed`. Both are written in a new
transaction, with no diff. A `denied` or `failed` row that cannot be written is logged, not
retried, and the call has no row; its answer is the same refusal or failure. A
call refused before it reaches a realm within its grants writes no row: one without a valid
token, one over a request limit, and one that names a realm outside its grants, which is logged
with the caller instead, so a stranger cannot add rows to another realm's chain.

### Approvals

A security operation runs only with a fresh approval bound to that exact request (ADR-019
Decision 7). The approval engine lives in `apps/auth-server/src/app/admin/approvals/`.

1. The client calls the operation and gets 403 `approval_required`.
2. It files an approval: `POST /admin/v1-rc.0/realms/{realmId}/approvals` with the operation's id,
   its path parameters other than `realmId`, its query and its body, and an optional `reason`. The
   answer, 201, is the approval, `pending`, with `approvalUrl`: the approval page, on the auth
   server of the realm the requester's account lives in, built from that realm's row. Its path is
   `/approvals/{realmId}/{approvalId}`, naming the realm the approval acts on, where the page finds
   it: an operator-realm admin's approval for a tenant realm lives in the tenant realm.
3. An approver confirms on that page with a factor, or declines. There is no admin route for it.
   The passkey factor is the only one a deployment will use. Neither it nor the approval page has
   shipped yet, so no code a deployment runs gives an approval; the one factor that exists is for
   tests, and is built only in a test run (`VITEST` set or `NODE_ENV=test`), never under
   `NODE_ENV=production`.
4. The client reads the approval, `GET /admin/v1-rc.0/realms/{realmId}/approvals/{approvalId}`,
   until its `status` is `approved`.
5. It repeats the original call, unchanged, with the header `QAuth-Approval: <approvalId>`. The
   admin pipeline checks the approval and consumes it in the transaction of the operation, so the
   operation runs once with it, under the requester's own authorization at that moment.

**What an approval binds.** The server keeps the canonical request: the operation id, the method,
every path parameter, the query and the body, each as the operation's route parses it, the realm
and the requester, serialized with the JSON Canonicalization Scheme (RFC 8785). `request_hash` is
its SHA-256 without the server's nonce; the gate recomputes it from the retried call and refuses
the call when it differs, so a changed body, path parameter, query, realm or requester finds no
approval. `op_hash` is its SHA-256 with the nonce, and the challenge an approver's factor signs is
derived from it, so an approval given for one filing approves nothing else.

**What a security operation's route and handler must do.** The admin listener refuses to boot a
security operation's route that cannot be bound this way: it needs a renderer, one method, a Zod
object schema for its path parameters naming every parameter of its URL, and a Zod body schema
under every method that carries a body; and every admin operation has exactly one route. Its
handler reads only the parsed path parameters, query and body, whose schemas are deterministic,
and makes an effect outside the database (a KMS or KEK call, a mail, an outbound request) only
through an outbox written in its transaction or after the commit, since an operation that rolls
back leaves its approval usable. The rules in full are on the
[Security operations](/reference/security-operations/#rules) page.

**Who approves.** A human requester's own fresh step-up is its first approval, and only the
requester gives it. An approval needs that one approval today. The engine already counts a
required second approval only from a different account that holds `approvals.approve` on the
realm; the two-admin rule (#521) will make a second admin mandatory where a realm asks for it, and
add the rest of ADR-019's eligibility rules (the approver held the security scope before the
request, no account or credential change in the 7 days before it, a passkey that is not the
requester's). Service accounts (#522) have no passkey: a human admin will approve in their place.
Until they ship, every admin API caller is a human account.

**Who reads.** Filing (`approvals.create`) and withdrawing (`approvals.cancel`) take the
classification of the operation the approval is for: the caller needs every permission it
declares, and `qauth:admin:security`. Reading (`approvals.get`) needs `approvals.read`, and only
the requester, an account that gave one of its approvals and an account that may still give one
read an approval. Anyone else gets 404 `not_found`, exactly as for an id that does not exist. An
approval's representation holds the operation's path parameters and query, never its body. Its `reason`, `params` and `query` are raw values, not display text; a page shows `display` instead, which is `null` once the approval is no longer open.

**How an approval ends.** It expires 5 minutes after it is filed, a constant. It is `consumed`
once the operation commits on it; an operation that fails or rolls back leaves it `approved`
until then. The requester withdraws it with
`POST /admin/v1-rc.0/realms/{realmId}/approvals/{approvalId}/cancel`, whose `If-Match` names the
version the approval's `ETag` gave (428 without one, 412 for another version, 409 for an approval
that is no longer open). An approver may decline it instead (`denied`). A consumed, expired,
cancelled or denied approval approves nothing. A consumed, cancelled or denied approval no longer
keeps the operation's body, which may hold a secret: its two hashes are what the audit log binds
to. No job removes approvals: one that expires unused keeps its body until the next approval is filed in its realm, which drops it.

**What the approver is shown.** The operation, rendered from the stored request, never from text
the requester wrote: every security operation registers a renderer, which returns typed display
data, never HTML, and the admin listener refuses to boot a security operation without one. The
requester's reason is shown apart, as quoted text. Every string is length-capped, and a control,
bidirectional, format or other default-ignorable character in it is shown escaped (`\u{202E}`), as
is a private-use or unassigned code point and every space but U+0020, a
backslash doubled and a combining mark past the third on one character escaped, so the text can
neither hide nor reorder what the page shows, nor pass for an escape. Every reader of an approval
gets its display data, so a renderer must never show a secret value of the request: nothing checks it.

**Audit rows.** Every state change writes the admin audit log of the approval's realm: filing and
withdrawing write the rows of `approvals.create` and `approvals.cancel`; approving and declining
write `approvals.approve` and `approvals.deny`, the first with the credential that approved; the
operation's own `succeeded` row lists the approvals it ran on and carries the approval's
`op_hash` as its request digest. A factor that refuses an approver's answer writes a `denied` row
of `approvals.approve`.

### Issuing a family audience

- A client gets a family audience only when an operator lists it in the client's `audience`. The
  client names it with the RFC 8707 `resource` parameter, at `/oauth/authorize` and at
  `/oauth/token`, and the token's `aud` is that value. A client that does not list it is refused
  with `invalid_target`, on every grant and before any consent screen. A client resolved from a
  Client ID Metadata Document or registered at `/oauth/register` lists none, whatever its row
  holds.
- On a user's grant (authorization code and refresh token) a family audience is issued only when a
  `resource` names it, in the request or bound to the code, so the consent the user gave covers
  it: a client's default audience leaves it out. A `client_credentials` token keeps the client's
  default.
- The admin audience is also issued only to an account whose live admin grants give a
  permission; otherwise the request is refused with `invalid_target`.
- An admin scope (`qauth:admin:read`, `qauth:admin:write`, `qauth:admin:security`) is issued only
  when the client lists the admin audience and the account holds a live admin grant whose role has
  a permission of that scope's class. Otherwise the token is issued without it, and the response's
  `scope` says so (RFC 6749 §3.3); when nothing is left of the scopes asked for, the request is
  refused with `invalid_scope`. No other scope of the reserved `qauth:` namespace is ever issued.
  Grants are read at every issuance, so the next refresh after a revocation no longer carries what
  the grant gave.
- Neither the admin audience nor an admin scope ever reaches a `client_credentials` token, which
  names no account, an ID-JAG that QAuth mints for another authorization server, or a token of the
  jwt-bearer grant, whose authority comes from another identity provider, or a delegated token of
  token exchange: an admin acts as itself, never through an agent, so a token exchange that names
  the admin audience is refused with `invalid_target` whatever grants the user holds. The token
  `/auth/login` mints leaves the admin audience out, whatever the system client lists.
- The legacy Bearer path of `/oauth/authorize` never issues one: a request on it that names a
  family audience, or a client whose default audience holds one, is refused with `access_denied`.
- A family audience never makes a client authoritative at introspection: QAuth is the only
  resource server for it, so a client introspects a family token only when the token is its own.
- `urn:qauth:aud:` is reserved for the audiences QAuth defines, in any letter case, by the rule the
  reserved `qauth:` scopes follow: self-registration never obtains one. Dynamic registration and a
  Client ID Metadata Document ignore it in an `audience` or `resource` member, and register or
  resolve the client with the rest; neither stores those members. The seed manifest refuses it in
  a `cimd_clients` entry, the one place it would be stored. The rule is `isReservedAudience` in
  `@qauth-labs/shared-validation`.
- The developer portal's token keeps the system client's id as its audience in this release.
  `/api/clients`, `/api/consents`, `/auth/logout` and the Bearer path of `/oauth/authorize`
  (`assertManagementToken`), and userinfo, accept a system-client token with the developer
  audience too, and #524 starts minting it. Expand, then contract (ADR-018 §5): every node accepts the
  token before any node mints it.

No route is served under these prefixes yet. The developer routes at `/api/clients` and
`/api/consents` and the account routes at `/consents` move under them, and their old paths are then
listed in [Deprecations](#deprecations).

## Names

- JSON members are `camelCase`: `createdAt`, `nextCursor`, `ownerId`.
- A member that carries a registered OAuth or OpenID Connect metadata value keeps its registered
  name: `redirect_uris`, `token_endpoint_auth_method`, `client_id`. The allowed names are listed,
  by IANA registry, in `apps/auth-server/src/app/api-conventions/registered-names.ts`. A name is
  added there only when a representation carries that registered value.
- `trace_id` in a problem document is the one other exception. ADR-019 Decision 7 fixed its name.
- Query and path parameters are `camelCase` too: `limit`, `cursor`, `realmId`.

## Ids and times

- `id`, and every reference to a resource by its id (`realmId`, `ownerId`), is an opaque UUID
  string. A client does not parse it or sort by it.
- A time is an RFC 3339 string in UTC, such as `2026-10-22T09:30:00Z`, never an epoch number. Its
  member name ends in `At`: `createdAt`, `updatedAt`, `expiresAt`.

## Requests and responses

- A request body is `application/json`, except a `PATCH` body ([Updates](#updates)).
- A request with an unknown member is refused with 400 `validation_error`. Request objects are
  closed (`additionalProperties: false`).
- A client ignores response members it does not know and enum values it does not know. Both may be
  added in a minor release.

## Paging

Every list pages by cursor.

| Query parameter | Meaning                                                                                |
| --------------- | -------------------------------------------------------------------------------------- |
| `limit`         | Items per page: an integer from 1 to 200, default 50. A larger value is refused (400). |
| `cursor`        | The `nextCursor` of the previous page. Opaque: a client never builds or changes one.   |

The response is an object with exactly two members:

```json
{
  "items": [{ "id": "0b9f7d4e-5c1a-4f7e-9d2b-3a6c8e1f0a42", "createdAt": "2026-10-22T09:30:00Z" }],
  "nextCursor": "eyJwb3NpdGlvbiI6NDJ9"
}
```

- `nextCursor` is `null` on the last page.
- There is no offset, page number or total. A cursor stays correct while rows are added between two
  calls; an offset does not.
- A cursor that does not parse, or that belongs to another list, is refused with 400
  `invalid_cursor`.
- A `limit` above 200 is refused, not clamped, so a short page is never mistaken for the end of the
  list.
- The cursor-based event API uses the same shape.

The query schema and the response schema are shared: `pageQuerySchema` and `pageSchema(item)` in
`apps/auth-server/src/app/api-conventions/paging.ts`.

## Concurrency

Updates use optimistic concurrency (RFC 9110 §13.1.1).

- A read of one resource returns an `ETag`. It is a strong validator: a client compares it only for
  equality.
- `PATCH` and `PUT` require `If-Match` with that value.
- An update without `If-Match` is refused with 428 `precondition_required` (RFC 6585 §3).
- An update whose `If-Match` is stale is refused with 412 `precondition_failed`. The client reads
  the resource again and retries on the new representation.
- A successful update returns the new representation and its new `ETag`.

## Updates

- `PATCH` takes a JSON Merge Patch (RFC 7396), sent as `application/merge-patch+json`.
- A member set to `null` is removed, or reset to its default. A member left out keeps its value. An
  array is replaced whole.
- The patch itself is a request body: an unknown member is refused with 400 `validation_error`.
- The merged result is checked against the resource's schema. A result that fails is refused with
  422 `unprocessable_content`, and `errors` names each failing field.

## Errors

Every route that is not an OAuth protocol endpoint answers an error with an RFC 9457 problem details
document, sent as `application/problem+json` (ADR-019 Decision 7, decided 2026-10-11).

```json
{
  "type": "https://docs.qauth.dev/reference/problem-types/#validation-error",
  "title": "Validation error",
  "status": 400,
  "detail": "The request is not valid.",
  "instance": "/developer/v1-rc.0/clients",
  "code": "validation_error",
  "trace_id": "req-7f3a",
  "errors": [{ "pointer": "/limit", "message": "Too big: expected number to be <=200" }]
}
```

| Member     | Meaning                                                                                                                                   |
| ---------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `type`     | The problem type: a URI under [Problem types](/reference/problem-types/), one per code. Not for branching.                                |
| `title`    | The problem type's title, the same for every occurrence. Not for branching.                                                               |
| `status`   | The HTTP status, repeated.                                                                                                                |
| `detail`   | A sentence for a person, when there is one. Never on a 5xx. Not for branching.                                                            |
| `instance` | The path of the request, without its query.                                                                                               |
| `code`     | A stable, machine-readable name for the error, from [Problem types](/reference/problem-types/).                                           |
| `trace_id` | The id under which QAuth logged the request. An operator finds the failure by it.                                                         |
| `errors`   | Present on a validation failure. One entry per field: `pointer`, an RFC 6901 JSON Pointer into the body or the parameters, and `message`. |

- A client branches on `code` and the status, never on `title` or `detail`, whose wording may
  change.
- A minor release may add codes. A client treats a code it does not know by its HTTP status.
- A 401 or 403 from a bearer-protected route also carries a `WWW-Authenticate` challenge (RFC 6750
  §3; the `DPoP` scheme of RFC 9449 §7.1 when the request used it): `invalid_token` for a token
  that was presented and is not valid (`invalid_access_token`, `access_token_expired`), and no
  error code for a request that presented none (`unauthorized`, RFC 6750 §3.1). A 403 says `insufficient_scope`, with the `scope`, only when a token with that
  scope would be let through; a refusal no scope can lift, such as the developer client limit,
  carries a challenge with no error code, so a client does not go back for a wider token.
- A weak password's feedback is a list of `errors` under the pointer `/password`.
- The shared schema is `Problem` (`#/components/schemas/Problem` in the OpenAPI document), and a
  route declares its error responses with `problemResponses(...)` from
  `apps/auth-server/src/app/api-conventions/problem.ts`.

**OAuth protocol endpoints keep the shape their specification defines,** because the clients and
libraries written to that specification parse it. These are the authorization, token, revocation,
introspection, device authorization, dynamic registration and userinfo endpoints, the FiPA
authorization challenge endpoint and the wallet-facing OID4VP endpoints. They answer
`application/json` with `error`, and `error_description` where there is something to say, and no
other member: the token endpoint answers with the `error` of RFC 6749 §5.2, dynamic registration
with that of RFC 7591 §3.2.2, and a bearer-protected endpoint with the `WWW-Authenticate` challenge
of RFC 6750 §3 as well. Their schema in the OpenAPI document is `OAuthError`. Each route says which
format it answers in its `config.errorFormat`: `oauth` on these endpoints, unset (`problem`)
everywhere else.

### Error codes

The codes, with each one's problem type, status and title, are listed on
[Problem types](/reference/problem-types/). They are inside the 1.0 promise: a published code keeps
its meaning within a major version. Each is sent with the status listed for it. An error that has
no code of its own is sent with the code of its status, and a status with no code of its own with
`bad_request` (any 4xx) or `internal_error` (any 5xx), so those two are the only codes sent with
more than one status. Codes are lower-case `snake_case`, like the `error` values of OAuth.

Which code each domain error class of `@qauth-labs/shared-errors` answers, and which OAuth `error`
it answers on a protocol endpoint, is set once, in
`apps/auth-server/src/app/api-conventions/error-classes.ts`, as is the code of each error class a
route or a server library defines itself, such as the Shared Signals Framework transmitter's. A
test fails when a class has no entry, and a test keeps the problem types page equal to
`PROBLEM_CODES` in `apps/auth-server/src/app/api-conventions/problem.ts`.

## OpenAPI

Each family is published as OpenAPI 3.1. Every operation of a family carries:

- an `operationId` of the form `<resource>.<verb>`, unique in the document. The resource may have
  several segments: `realms.get`, `realms.list`, `realms.policies.update`. The verbs are `list`,
  `get`, `create`, `update` (`PATCH`), `replace` (`PUT`) and `delete`; any other verb names an
  action, such as `keys.rotate`;
- a security requirement. No family operation is anonymous;
- the five extensions below;
- error responses that reference the shared `Problem` schema, as `application/problem+json`.

Every other operation of the server lists its error responses too: a route names the statuses it
answers by design in `x-qauth-errors`, and the document adds 421, 429 and 500, which any operation
of a realm may answer (`/health` only 429), each referencing `Problem`, or `OAuthError` on an OAuth
protocol endpoint.

| Extension            | Values                             | Meaning                                                                                                                                                                                                                                                              |
| -------------------- | ---------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `x-qauth-class`      | `read`, `write`, `security`        | What the operation does. On the admin API it is the strictest class among the operation's permissions, and each permission needs its own class's scope: `qauth:admin:read`, `qauth:admin:write` or `qauth:admin:security`. `security` is used on the admin API only. |
| `x-qauth-permission` | a permission id, or a list of them | The permission the caller needs, such as `realms.read`. A list means the request decides which, for example a policy patch whose fields need `realms.policies.write`, `realms.policies.security` or both.                                                            |
| `x-qauth-effects`    | a list of effect tags              | Why an admin operation is a security operation ("defined by effect", ADR-019 Decision 7). Present and not empty exactly on security operations. The tags form a closed list, on [Security operations](/reference/security-operations/).                              |
| `x-qauth-two-admin`  | `recommended`                      | Set on every security operation: the admin console recommends a second admin's approval. A realm chooses where it is mandatory; that is realm policy, not part of the document.                                                                                      |
| `x-qauth-stability`  | `stable`, `experimental`           | Where the operation stands under ADR-018 §5. Required on every operation of the server, not only the families.                                                                                                                                                       |

On the admin API every id in `x-qauth-permission` is a permission of the
[admin catalog](/reference/admin-permissions/), and not a retired one, and `x-qauth-class` is the
strictest class among them (`read` < `write` < `security`). With one permission the operation
needs that class's scope. With a list, the request decides which scopes it needs: a policy patch
that changes only a write field needs `qauth:admin:write`, one that changes a security field needs
`qauth:admin:security`, and one that changes both needs both. The class still names the strictest
case, so a security operation never hides behind a write class and always carries its effects and
the two-admin marker.

Every admin operation is defined once, in the admin operation registry
([Security operations](/reference/security-operations/)), with its class, effects and permissions.
The document's `operationId` must name a registered operation, and its `x-qauth-class`,
`x-qauth-permission` and `x-qauth-effects` must be the registry's; the conventions check fails
otherwise. A route of the admin listener names its operation in its route config (`operation`) and
takes these members from the registry (`operationSchemaExtensions`), and the listener refuses to
boot a route that names no registered operation or whose members differ.

A request-dependent operation classifies each request (`classify`). By effect, a policy change
that lengthens an access-token, refresh-token or session lifetime or the key rotation interval, or
shortens or switches off audit-event retention, is `posture-loosening` and needs the security
class; shortening a lifetime or lengthening retention is a write. A field `classify` has no rule
for fails closed only when `classify` takes a merge patch's changed fields from the body with
`mergePatchLeafPaths(body)` and classifies them with `classifyByField`, which throws on a field its
table does not hold; a request-dependent merge-patch operation uses that pattern, since a
`classify` that reads only the fields it expects never sees the others.

An operation that reads the current state to classify (`loadState`) names the version of what it
read (`stateVersion`), which the route sends quoted as its `ETag`. The listener puts the version on
the classification and answers `428` when the request has no `If-Match` and `412` when it names
another version. The route still declares `If-Match` required in its header schema, so the
OpenAPI document says so; the listener checks for it before validation, so a request without it
gets `428`, not the `400` of a failed schema. The handler's write must be conditional on `classification.stateVersion` (an update that
matches the stored version, `412` when none does), or load, classify and write in one transaction
under `SELECT … FOR UPDATE`: otherwise a change made between the classification and the write runs
under a classification of other state.

A route declares all of it in its schema, and `@fastify/swagger` copies it onto the operation. On
the admin API the operation is defined once in the registry, and the route names it in its config
and spreads the registry's members into its schema:

```ts
// helpers/admin-operations.ts, listed in ADMIN_OPERATIONS
export const REALM_POLICIES_UPDATE = defineOperation({
  id: 'realms.policies.update',
  class: 'security',
  effects: ['credential-path', 'token-content', 'posture-loosening', 'administration'],
  permissions: ['realms.policies.write', 'realms.policies.security'],
  description: "Change a realm's policies.",
  loadState: loadRealmPolicies,
  stateVersion: (policies) => policies.version,
  classify: classifyByField({
    changedFields: (request) => mergePatchLeafPaths(request.body),
    fields: POLICY_FIELDS,
    unchanged: WRITE,
  }),
});

// the route, on the admin listener
fastify.patch(
  '/admin/v1-rc.0/realms/:realmId/policies',
  {
    config: { operation: REALM_POLICIES_UPDATE.id },
    schema: {
      // operationId, x-qauth-class, x-qauth-permission, x-qauth-effects and
      // x-qauth-two-admin, from the registry
      ...operationSchemaExtensions(REALM_POLICIES_UPDATE),
      security: [{ bearerAuth: [] }],
      'x-qauth-stability': 'stable',
      consumes: ['application/merge-patch+json'],
      params: z.object({ realmId: z.uuid() }),
      // Required, so the OpenAPI document says so. A request without it gets
      // 428 from the listener, which checks before validation, not 400.
      headers: z.looseObject({ 'if-match': z.string() }),
      body: realmPoliciesPatchSchema,
      response: { 200: realmSchema, ...problemResponses(400, 401, 403, 404, 412, 422, 428) },
    },
  },
  handler
);
```

## Versioning

Inside a major version, changes are additive only:

- new endpoints;
- new optional request members;
- new response members.

Clients ignore unknown response members and unknown enum values. Requests with unknown members are
refused.

These are breaking changes, and only a new major version makes them:

- removing or renaming a member;
- changing a type;
- tightening validation;
- changing a status code;
- removing an endpoint.

**Deprecation.** A deprecation is announced in a minor release. The operation gets
`deprecated: true` in the OpenAPI document and its responses carry the `Deprecation` header (RFC
9745). A `Sunset` header (RFC 8594) is added once a date exists. Removal comes no sooner than 12
months after the announcement, and only in a new major release (ADR-018 §5).

**Major versions.** `v1` stays served for at least 12 months after `v2` ships, and until the next
major release.

### Release candidates

Before QAuth 1.0.0 nothing is promised, so no path or audience says `v1` yet. Each family is
served under `v1-rc.<M>`, today `v1-rc.0`, and so is the Interaction API. A breaking change before
1.0.0 raises `<M>`, so a prefix never names two contracts. The release that ships 1.0.0 serves
`v1`, and from then on the rules above apply. The same rule covers every QAuth-defined versioned
identifier (ADR-018 §5).

**Experimental operations.** An experimental operation sits behind a switch and carries
`x-qauth-stability: experimental`. It is absent from the published document while the switch is
off, and it may change in a minor release without a deprecation window (ADR-018 §5).

### Deprecations

| Operation | Replacement | Deprecated in | Sunset |
| --------- | ----------- | ------------- | ------ |
| —         | —           | —             | —      |

No operation is deprecated yet. When the account and developer routes move under their prefixes,
their old paths are listed here.

## Enforcement

- `apps/auth-server/src/app/api-conventions/openapi-conventions.ts` checks every operation under a
  family prefix: the `operationId`, the security requirement, the five extensions (an admin
  operation's permissions come from the admin catalog, and its class is the strictest class among
  them), the names, the id and time formats,
  closed request objects, the problem schema on error responses, cursor paging, Merge Patch
  bodies, and `If-Match` with its 412 and 428 answers. Its test runs the check
  over `stable-surface/openapi.json` and `apps/docs-site/public/openapi.json`. CI's stable-surface
  check regenerates both files and fails when they differ from the committed copies, so the check
  reads what the server serves.
- The stable-surface check also fails on an untagged operation, on a switch-gated operation that is
  not `experimental`, and on a break that no approval covers. Its rules are in
  [`stable-surface/README.md`](https://github.com/qauth-labs/qauth/blob/main/stable-surface/README.md).
- The error handler (`apps/auth-server/src/app/plugins/error-handler.ts`) builds the problem
  documents. Its tests, and the assembled-app tests in `error-handler-wiring.test.ts` and
  `error-format.integration.test.ts`, assert both formats on the wire.
