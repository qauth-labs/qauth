---
title: API conventions
description: The rules every route of the admin, account and developer APIs follows — paths, names, errors, paging, concurrency, OpenAPI extensions and versioning.
sidebar:
  order: 3
lastVerified: '2026-10-22'
---

QAuth has three API families: admin, account and developer
([ADR-019](/reference/records/adr/019-deployment-topology-and-trust-boundaries/), Decision 7).
Every route of the three follows the rules on this page. The rules are part of the 1.0 stability
contract ([ADR-018 §5](/reference/records/adr/018-1-0-scope-and-stability/)), so they are fixed
before the families' first route. A test enforces them over the generated OpenAPI document
([Enforcement](#enforcement)).

The Interaction API (`/interaction/v1`) reuses these rules. The OAuth protocol endpoints do not:
they keep the shapes their specifications define ([Errors](#errors)).

## The three families

| Family    | Caller    | Path prefix     | Audience                     |
| --------- | --------- | --------------- | ---------------------------- |
| admin     | Operator  | `/admin/v1`     | `urn:qauth:aud:admin:v1`     |
| account   | End user  | `/account/v1`   | `urn:qauth:aud:account:v1`   |
| developer | Developer | `/developer/v1` | `urn:qauth:aud:developer:v1` |

- The major version is in the path. A new major version is served under its own prefix, such as
  `/admin/v2`, beside the old one ([Versioning](#versioning)).
- Each token carries one audience, and a family accepts only its own. The audience identifiers
  carry a version, as ADR-018 §5 requires for every QAuth-defined identifier.
- The admin API's scopes are `admin:read`, `admin:write` and `admin:security`. The account and
  developer families define no scopes here: their guards check the audience and the subject. A
  route that needs a scope adds it in its own change.

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
  "type": "about:blank",
  "title": "Bad Request",
  "status": 400,
  "detail": "The request is not valid.",
  "code": "validation_error",
  "trace_id": "req-7f3a",
  "errors": [{ "pointer": "/limit", "message": "Too big: expected number to be <=200" }]
}
```

| Member     | Meaning                                                                                                            |
| ---------- | ------------------------------------------------------------------------------------------------------------------ |
| `type`     | `about:blank` today, so `title` is the HTTP status phrase (RFC 9457 §4.2.1). A code may get its own type URI.      |
| `title`    | The status phrase. Not for branching.                                                                              |
| `status`   | The HTTP status, repeated.                                                                                         |
| `detail`   | A sentence for a person, when there is one. Never on a 5xx. Not for branching.                                     |
| `instance` | Optional. A URI for this occurrence.                                                                               |
| `code`     | A stable, machine-readable name for the error, from the list below.                                                |
| `trace_id` | The id under which QAuth logged the request. An operator finds the failure by it.                                  |
| `errors`   | Optional. One entry per field: `pointer`, an RFC 6901 JSON Pointer into the body or the parameters, and `message`. |

- A client branches on `code` and the status, never on `title` or `detail`, whose wording may
  change.
- A minor release may add codes. A client treats a code it does not know by its HTTP status.
- A 401 from a bearer-protected route also carries the `WWW-Authenticate: Bearer` challenge of RFC
  6750 §3.
- The shared schema is `Problem` (`#/components/schemas/Problem` in the OpenAPI document), and a
  route declares its error responses with `problemResponses(...)` from
  `apps/auth-server/src/app/api-conventions/problem.ts`.

**OAuth protocol endpoints keep the shape their specification defines,** because the clients and
libraries written to that specification parse it. These are the authorization, token, revocation,
introspection, device authorization, dynamic registration and userinfo endpoints, the FiPA
authorization challenge endpoint and the wallet-facing OID4VP endpoints. For example, the token
endpoint answers with the `error` and `error_description` of RFC 6749 §5.2, and a bearer-protected
endpoint answers with the `WWW-Authenticate` challenge of RFC 6750 §3.

The routes under the family prefixes answer problem documents. The other routes that are not OAuth
protocol endpoints (`/auth/*`, `/api/*`, `/consents`) still answer the earlier
`{ "error", "statusCode", "code" }` body until their conversion (#513).

### Error codes

The codes are inside the 1.0 promise: a published code keeps its meaning within a major version.
Each is sent with one status. An error that has no code of its own is sent with the code of its
status. Codes are lower-case `snake_case`, like the `error` values of OAuth. The earlier body of the
routes that #513 converts names the same errors in upper case (`VALIDATION_ERROR`).

| Code                          | Status | Meaning                                                                                                                             |
| ----------------------------- | ------ | ----------------------------------------------------------------------------------------------------------------------------------- |
| `bad_request`                 | 400    | The request is malformed and no more specific code applies.                                                                         |
| `validation_error`            | 400    | The request does not match the schema of the operation. `errors` names each field.                                                  |
| `invalid_cursor`              | 400    | The `cursor` does not parse, or it belongs to another list.                                                                         |
| `invalid_token`               | 400    | A one-time token in the request, such as an email verification token, is not valid.                                                 |
| `unauthorized`                | 401    | The request carries no valid credentials.                                                                                           |
| `jwt_expired`                 | 401    | The access token has expired.                                                                                                       |
| `jwt_invalid`                 | 401    | The access token is not valid.                                                                                                      |
| `invalid_credentials`         | 401    | The identifier or the credential is wrong. The answer does not say which.                                                           |
| `forbidden`                   | 403    | The caller is authenticated but may not perform the operation.                                                                      |
| `email_not_verified`          | 403    | The account must verify its email address first.                                                                                    |
| `not_found`                   | 404    | The resource does not exist, or the caller may not know that it exists.                                                             |
| `method_not_allowed`          | 405    | The resource does not support the method.                                                                                           |
| `conflict`                    | 409    | The request conflicts with the current state of the resource.                                                                       |
| `unique_constraint_violation` | 409    | A resource with the same unique value already exists.                                                                               |
| `email_already_verified`      | 409    | The email address is already verified.                                                                                              |
| `token_already_used`          | 409    | The one-time token has already been used.                                                                                           |
| `token_expired`               | 410    | The one-time token has expired.                                                                                                     |
| `precondition_failed`         | 412    | The `If-Match` value does not match the current `ETag` of the resource.                                                             |
| `content_too_large`           | 413    | The request body is larger than the server accepts.                                                                                 |
| `unsupported_media_type`      | 415    | The media type of the request body is not one the operation accepts.                                                                |
| `unprocessable_content`       | 422    | The request is well formed, but its content cannot be applied, such as a merge patch whose result fails the schema of the resource. |
| `weak_password`               | 422    | The new password is too weak. `errors` carries the feedback under `/password`.                                                      |
| `precondition_required`       | 428    | The update needs an `If-Match` header.                                                                                              |
| `too_many_requests`           | 429    | The caller has sent too many requests. `Retry-After` says when to try again.                                                        |
| `internal_error`              | 500    | The server failed. `trace_id` finds the failure in the server log.                                                                  |
| `service_unavailable`         | 503    | The server cannot answer now, for example while a dependency is down.                                                               |

`PROBLEM_CODES` in `apps/auth-server/src/app/api-conventions/problem.ts` is the source of this
table, and a test fails when the two differ.

## OpenAPI

Each family is published as OpenAPI 3.1. Every operation of a family carries:

- an `operationId` of the form `<resource>.<verb>`, unique in the document. The resource may have
  several segments: `realms.get`, `realms.list`, `realms.policies.update`. The verbs are `list`,
  `get`, `create`, `update` (`PATCH`), `replace` (`PUT`) and `delete`; any other verb names an
  action, such as `keys.rotate`;
- a security requirement. No family operation is anonymous;
- the five extensions below;
- error responses that reference the shared `Problem` schema, as `application/problem+json`.

| Extension            | Values                             | Meaning                                                                                                                                                                                                   |
| -------------------- | ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `x-qauth-class`      | `read`, `write`, `security`        | What the operation does. On the admin API the class names the scope it needs: `admin:read`, `admin:write` or `admin:security`. `security` is used on the admin API only.                                  |
| `x-qauth-permission` | a permission id, or a list of them | The permission the caller needs, such as `realms.read`. A list means the request decides which, for example a policy patch whose fields need `realms.policies.write`, `realms.policies.security` or both. |
| `x-qauth-effects`    | a list of effect tags              | Why an admin operation is a security operation ("defined by effect", ADR-019 Decision 7). Present and not empty exactly on security operations.                                                           |
| `x-qauth-two-admin`  | `recommended`                      | Set on every security operation: the admin console recommends a second admin's approval. A realm chooses where it is mandatory; that is realm policy, not part of the document.                           |
| `x-qauth-stability`  | `stable`, `experimental`           | Where the operation stands under ADR-018 §5. Required on every operation of the server, not only the families.                                                                                            |

A route declares all of it in its schema, and `@fastify/swagger` copies it onto the operation:

```ts
fastify.patch(
  '/admin/v1/realms/:realmId/policies',
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
  family prefix: the `operationId`, the security requirement, the five extensions, the names, the
  id and time formats, closed request objects, the problem schema on error responses, cursor
  paging, Merge Patch bodies, and `If-Match` with its 412 and 428 answers. Its test runs the check
  over `stable-surface/openapi.json` and `apps/docs-site/public/openapi.json`. CI's stable-surface
  check regenerates both files and fails when they differ from the committed copies, so the check
  reads what the server serves.
- The stable-surface check also fails on an untagged operation, on a switch-gated operation that is
  not `experimental`, and on a break that no approval covers. Its rules are in
  [`stable-surface/README.md`](https://github.com/qauth-labs/qauth/blob/main/stable-surface/README.md).
- The error handler (`apps/auth-server/src/app/plugins/error-handler.ts`) builds the problem
  documents. Its tests, and the assembled-app tests in `error-handler-wiring.test.ts` and
  `error-format.integration.test.ts`, assert both formats on the wire.
