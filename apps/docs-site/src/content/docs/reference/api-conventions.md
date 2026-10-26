---
title: API conventions
description: The rules every route of the admin, account and developer APIs follows — paths, names, errors, paging, concurrency, OpenAPI extensions and versioning.
sidebar:
  order: 3
lastVerified: '2026-10-25'
---

QAuth has three API families: admin, account and developer
([ADR-019](/reference/records/adr/019-deployment-topology-and-trust-boundaries/), Decision 7).
Every route of the three follows the rules on this page. The rules are part of the 1.0 stability
contract ([ADR-018 §5](/reference/records/adr/018-1-0-scope-and-stability/)), so they are fixed
before the families' first route. A test enforces them over the generated OpenAPI document
([Enforcement](#enforcement)).

The Interaction API (`/interaction/v1-rc.0`) reuses these rules. The OAuth protocol endpoints do
not: they keep the shapes their specifications define ([Errors](#errors)). The error format of
[Errors](#errors) is not limited to the families: every route that is not an OAuth protocol
endpoint answers it.

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
  written for the realm whose issuer it is, and the realm's own issuer for any other realm;
- it carries `sub`, `exp` and `jti`, with `sub` and `jti` non-empty strings;
- its `aud` holds exactly one value, the family's audience. A token with several audiences is
  refused even when one of them is the family's;
- on the developer family, it carries no `act` claim: a delegated token (RFC 8693) never manages a
  developer's clients;
- its subject is one the route admits (the required `subjects` option: `user`, `client` or both)
  and is active in the realm of the request (ADR-019 Decision 1). A `client_credentials` token,
  whose `sub` is its own `client_id`, must name a client of that realm that is enabled and not
  suspended; any other token must name a user of that realm who is enabled;
- it carries every scope the route lists.

A family audience reads the same in every realm. Every token still carries `JWT_ISSUER` until
tokens are signed per realm (#491), so under the default issuer rule only the realm whose issuer
that is admits a token, and any other realm refuses every token until then. The subject is checked
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
| `x-qauth-effects`    | a list of effect tags              | Why an admin operation is a security operation ("defined by effect", ADR-019 Decision 7). Present and not empty exactly on security operations.                                                                                                                      |
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

A route declares all of it in its schema, and `@fastify/swagger` copies it onto the operation:

```ts
fastify.patch(
  '/admin/v1-rc.0/realms/:realmId/policies',
  {
    schema: {
      operationId: 'realms.policies.update',
      security: [{ bearerAuth: [] }],
      'x-qauth-class': 'security',
      'x-qauth-permission': ['realms.policies.write', 'realms.policies.security'],
      'x-qauth-effects': ['credential-path'],
      'x-qauth-two-admin': 'recommended',
      'x-qauth-stability': 'stable',
      consumes: ['application/merge-patch+json'],
      params: z.object({ realmId: z.uuid() }),
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
