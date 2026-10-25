---
title: Admin permissions
description: The admin scopes, every permission of the admin API with its class, and the built-in admin roles, generated from the registry in apps/auth-server.
sidebar:
  order: 6
lastVerified: '2026-10-25'
---

<!-- Generated from apps/auth-server/src/app/helpers/admin-permissions.ts by its tests. Do not edit by hand: change the registry and run `pnpm nx test auth-server -- -u`. -->

The admin API authorizes a request by scope and by role
([ADR-019](/reference/records/adr/019-deployment-topology-and-trust-boundaries/), Decision 7).
A role grants permissions. The token's scopes decide which classes of those permissions this
token may use. This page lists the scopes, every permission and the built-in roles. It is
generated from the registry in `apps/auth-server/src/app/helpers/admin-permissions.ts`.

## Scopes

| Scope            | Allows               | Meaning                                                                                                                                                |
| ---------------- | -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `admin:read`     | read permissions     | Reads configuration and state. Changes nothing.                                                                                                        |
| `admin:write`    | write permissions    | Changes display data and operational settings, with none of the effects of a security operation.                                                       |
| `admin:security` | security permissions | Performs a security operation, defined by its effect in ADR-019 Decision 7, such as changing what can authenticate an account or what a token asserts. |

- The three scopes are independent. No scope implies another: `admin:write` does not satisfy a
  read permission, and `admin:security` satisfies neither a read nor a write permission.
- A request that needs a write permission and a security permission needs both scopes.
- Scopes are matched exactly and case-sensitively (RFC 6749 §3.3).
- Every scope that starts with `admin:`, in any case, is reserved for the admin API. Dynamic
  registration refuses one with `invalid_client_metadata`, a Client ID Metadata Document that
  asks for one is refused, a realm's dynamic registration allowlist cannot hold one, and
  discovery never lists one.

## How a request is authorized

A permission is effective for a request when both hold:

1. one of the caller's admin roles grants it, and
2. the token carries the scope of its class.

So a token with only `admin:write` never uses a security permission, whatever role the caller
holds. An admin API operation names the permission it needs in its `x-qauth-permission`
extension ([API conventions](/reference/api-conventions/#openapi)). An operation whose request
decides whether it is a security operation, such as a policy patch, names a write permission and
a security permission, and a request that touches both needs both.

## Permissions

| Permission                 | Class    | Scope            | Resource          | Description                                                                                                                     |
| -------------------------- | -------- | ---------------- | ----------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `realms.read`              | read     | `admin:read`     | `realms`          | Read a realm's representation, with its settings and policies.                                                                  |
| `realms.export`            | read     | `admin:read`     | `realms`          | Export a realm's configuration as a realm file, which holds no secret value.                                                    |
| `realms.import.plan`       | read     | `admin:read`     | `realms`          | Compute the dry-run plan of a realm-file import: every change it would make and the permissions each needs. It applies nothing. |
| `realms.policies.write`    | write    | `admin:write`    | `realms.policies` | Change a realm policy whose change is not a security operation, such as a token lifespan.                                       |
| `realms.policies.security` | security | `admin:security` | `realms.policies` | Change a realm policy whose change is a security operation, such as loosening the sign-in methods or the password policy.       |
| `approvals.read`           | read     | `admin:read`     | `approvals`       | Read the approval requests of security operations and where each one stands.                                                    |
| `approvals.approve`        | security | `admin:security` | `approvals`       | Approve another admin's security operation, with a fresh passkey.                                                               |

A permission has exactly one class. A permission that performs a security operation has an id of
its own and the class `security`; it never shares an id with a write permission, so no custom
role reaches a security operation through `admin:write`.

## Built-in roles

| Role             | Classes               | Permissions                                                                                                                                      | Description                                                     |
| ---------------- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------- |
| `viewer`         | read                  | `realms.read`, `realms.export`, `realms.import.plan`, `approvals.read`                                                                           | Reads everything an admin can read.                             |
| `editor`         | read, write           | `realms.read`, `realms.export`, `realms.import.plan`, `realms.policies.write`, `approvals.read`                                                  | Reads, and makes every change that is not a security operation. |
| `security-admin` | read, write, security | `realms.read`, `realms.export`, `realms.import.plan`, `realms.policies.write`, `realms.policies.security`, `approvals.read`, `approvals.approve` | Reads, makes every change, and performs security operations.    |

- Built-in roles are defined in code, by class, and cannot be edited. A permission added to the
  catalog joins every built-in role of its class.
- A custom role lists permission ids from the table above. An unknown id is refused, and so is a
  retired one.
- Admin roles are not the realm's application roles, which reach tokens as claims
  ([ADR-020](/reference/records/adr/020-ui-surfaces-and-acceptance-criteria/), fork D).

## Retired permissions

No permission has been retired.

## Stability

The permission ids are part of the admin API's contract
([ADR-018 §5](/reference/records/adr/018-1-0-scope-and-stability/)), because custom roles store
them.

- An id, once published, is never renamed and never reused for another meaning.
- A permission that is no longer needed is retired, not removed: it is listed under
  [Retired permissions](#retired-permissions), it grants nothing, and its id stays taken.
- A release may add permissions. A new permission joins the built-in roles of its class.
