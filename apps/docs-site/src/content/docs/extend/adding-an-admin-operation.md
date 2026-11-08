---
title: Adding an admin operation
description: The five steps of a new admin API operation — register its permission, define it, classify it, render it for the approver, audit it — with realms.get and realms.policies.update as the worked example.
sidebar:
  order: 7
lastVerified: '2026-11-08'
---

Every operation of the admin API goes through the same pipeline: the DPoP-bound admin token, the
caller's grants on the realm, the operation's classification, the approval gate for a security
operation, the handler in one transaction, and the audit row
([ADR-019](/reference/records/adr/019-deployment-topology-and-trust-boundaries/), Decision 7). A
new operation does not add a stage. It adds five things, in this order:

1. [Register the permission](#1-register-the-permission) it needs.
2. [Define the operation](#2-define-the-operation): its id, class, effects and permissions, and
   its route.
3. [Classify](#3-classify) each request, when what it needs depends on the request.
4. [Render](#4-render) it for the approver, when it is a security operation.
5. [Audit](#5-audit) the change its handler makes.

The two realm operations are the reference, and every later admin operation follows them:

| Operation                | Route                                            | Class    | Permissions                                                        |
| ------------------------ | ------------------------------------------------ | -------- | ------------------------------------------------------------------ |
| `realms.get`             | `GET /admin/v1-rc.0/realms/{realmId}`            | read     | `realms.read`                                                      |
| `realms.policies.update` | `PATCH /admin/v1-rc.0/realms/{realmId}/policies` | security | `realms.policies.write`, `realms.policies.security`, `realms.read` |

Both are listed with their effects on [Security operations](/reference/security-operations/#operations),
which is generated from the registry. Their code is in `apps/auth-server/src/app/admin/realms/`:
`operations.ts` holds the definitions, `routes.ts` the routes, and `realms.test.ts` and
`apps/auth-server/src/app/admin-realms.integration.test.ts` their tests.

Operation ids and permission ids are part of the published contract: a client names them, an
approval stores them, and an audit row keeps them. Choose them as you would a route.

## 1. Register the permission

A permission is `<resource>.<action>` with one class: `read`, `write` or `security`. The catalog is
`apps/auth-server/src/app/helpers/admin-permissions.ts`; the
[permissions page](/reference/admin-permissions/#permissions) is generated from it. The built-in
roles follow the catalog by class (`apps/auth-server/src/app/helpers/admin-roles.ts`): `viewer`
gets every read permission, `editor` every read and write permission, `security-admin` all of
them. The token's scopes are checked by class too: a `write` permission needs
`qauth:admin:write`, a `security` one `qauth:admin:security`.

Reuse a permission when the new operation acts on the same resource the same way. The realm
operations needed none of their own: `realms.read`, `realms.policies.write` and
`realms.policies.security` were in the catalog before them. An operation whose change can be
either a write or a security change, field by field, declares both, and each request needs only
the ones its change needs ([Classify](#3-classify)). An operation that answers the resource also
needs its read permission: the scopes are independent, so `realms.policies.update`, which answers
the realm, needs `realms.read` on every request. Filing or withdrawing an approval needs the
security permissions the operation declares; the rest is checked when the call runs with it.

## 2. Define the operation

An area keeps its definitions in `admin/<area>/operations.ts` and adds them to `ADMIN_OPERATIONS`
in `apps/auth-server/src/app/helpers/admin-operations.ts`. A definition says:

- `id`, `class`, `effects` and `permissions`: its declaration, what it needs at most. A security
  operation names the [effects](/reference/security-operations/#effects) that make it one.
- `description`: one sentence, shown on the generated pages and in OpenAPI.
- `loadState` and `stateVersion`, for an operation on a resource with a version: the resource as
  the request finds it, and the version a client names in `If-Match`. The pipeline answers 428
  without `If-Match` and 412 when it names another version, before the handler runs.
- `secretMembers`: the JSON Pointers of the body members that carry a secret. The body schema
  holds each to a sealed value, and the handler opens it with `openRequestSealedValue`
  (`apps/auth-server/src/app/admin/secrets/sealed-values.ts`), for its own operation only.
- `classify` and `render`, when they apply (steps 3 and 4).

An id the registry reserves (`apps/auth-server/src/app/helpers/admin-operations-reserved.ts`) must
be registered with at least its reserved class and effects; a request-dependent one also passes
its security cases at boot.

A definition module imports values only from
`apps/auth-server/src/app/helpers/admin-classification.ts`, and types from the registry: the
registry imports the module, so importing the registry or the pipeline back would read them before
they exist. That is also why `loadState` reads the realm from `request.adminPipeline.authority`.

The route names its operation and carries the registry's OpenAPI extensions:

```ts
typed.patch(
  `${REALM_PATH}/policies`,
  {
    config: { operation: operations.updatePolicies.id },
    preHandler: requireMergePatch,
    schema: {
      ...operationSchemaExtensions(operations.updatePolicies), // operationId, x-qauth-class, …
      'x-qauth-stability': 'experimental',
      'x-qauth-errors': [400, 401, 403, 404, 412, 415, 422, 428],
      security: [{ [ADMIN_SECURITY_SCHEME]: [] }],
      // params, headers, body, response …
    },
  },
  handler
);
```

The area's route module goes into `ADMIN_ROUTE_MODULES` in
`apps/auth-server/src/app/admin/listener.ts`. A route that names no operation, or one the registry
does not hold, stops the boot. The API conventions check
(`apps/auth-server/src/app/api-conventions/openapi-conventions.ts`) holds every admin operation of
the OpenAPI document to the registry; each area's unit test runs it over its routes.

## 3. Classify

An operation without `classify` needs its declaration on every request. One whose need depends on
the request, such as a merge patch that may touch a write field or a security field, has a
`classify(request, state)`: a pure, synchronous function of frozen copies of the request and of
`loadState`'s result. Its answer must stay within the declaration. When it throws, or answers
anything else, the request fails closed: it needs the whole declaration.

A merge-patch operation builds `classify` from the field table of `classifyByField`, with
`mergePatchLeafPaths` as the fields the body changes. A member the table does not hold fails the
request closed. `realms.policies.update` builds its table from the realm policy annotations
([Realm policies](/reference/realm-policies/)), and judges each change on the merged document,
never on the patch alone: `null` gives a field its default, which may be looser than the stored
value, so a `null` that loosens is a security change. A secret field is a security change whatever
the patch does with it. A patch that shortens the access-token lifetime is a write; one that
lowers the password score is a security change; a patch of both needs both permissions, both
scopes and one approval. Every patch needs `realms.read` besides.

`loadState` runs once the caller is known to hold at least one of the operation's permissions:
a caller who holds none is refused with 403 before anything is read, so it learns nothing of the
resource. `loadState` may refuse what it cannot judge: `realms.policies.update` answers 422,
naming each field, when the merged document fails the policy schema, such as a
`bruteForce.lockoutSeconds` above a day, so an invalid patch is never filed for an approval.

## 4. Render

A security operation runs only with an approval, and the approver decides from what `render`
shows: a title and a list of fields, each a `label` and a `value`, with the `before` it replaces
for a change. It gets the filed request and, for an operation with `loadState`, the state the
approval was filed against, which the approval is bound to: a call after the state moved does not
run on it. Never show a secret: `realms.policies.update` shows a secret field only as whether it
was set and whether the patch sets or clears it. The display caps the number and the length of
the fields (`apps/auth-server/src/app/admin/approvals/display.ts`), and shows the requester's
reason beside them as quoted text, never as part of the rendering.

## 5. Audit

The handler does its work through `adminTransaction(request)`, the transaction its audit row
commits in, and records what it changed with `recordAdminChange(request, change)`: the resource's
state `before` and `after`, and an annotation `secret` on each member that holds one. The audit
log stores the diff with each secret masked (`***`), and never its value. A call records one
change. A call the pipeline refuses, or a handler that fails, gets its `denied` or `failed` row
with no diff, and its transaction is rolled back.

`realms.policies.update` writes through the policy store in that transaction, conditional on the
version it was classified against, with a guard that refuses a stored change that would need more
than the request was authorized for. Its audit row holds the changed fields before and after and
the policy version.

## Tests

Each operation gets a unit test of its definition, classification, renderer, body schema and
representation, with the API conventions check over its routes, and an integration test against
real Postgres and Redis that runs it through every stage with the test approval factor. The realm
operations' suites are the model.
