---
title: Admin permissions
description: The admin scopes, every permission of the admin API with its class, and the built-in admin roles, generated from the registry in apps/auth-server.
sidebar:
  order: 6
lastVerified: '2026-10-26'
---

<!-- Generated from apps/auth-server/src/app/helpers/admin-permissions.ts by its tests. Do not edit by hand: change the registry and run `pnpm nx test auth-server -- -u`. -->

The admin API is to authorize each request by scope and by role
([ADR-019](/reference/records/adr/019-deployment-topology-and-trust-boundaries/), Decision 7).
A role grants permissions. The token's scopes decide which classes of those permissions this
token may use. This page lists the scopes, every permission and the built-in roles, and states
the rule the admin API will enforce. No admin API route reads the catalog yet, so the rule
protects nothing today; the `qauth:` scope namespace is already reserved, as listed below. The page is
generated from the registry in `apps/auth-server/src/app/helpers/admin-permissions.ts`.

## Scopes

| Scope                  | Allows               | Meaning                                                                                                                                                |
| ---------------------- | -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `qauth:admin:read`     | read permissions     | Reads configuration and state. Changes nothing.                                                                                                        |
| `qauth:admin:write`    | write permissions    | Changes display data and operational settings, with none of the effects of a security operation.                                                       |
| `qauth:admin:security` | security permissions | Performs a security operation, defined by its effect in ADR-019 Decision 7, such as changing what can authenticate an account or what a token asserts. |

- The three scopes are independent. No scope implies another: `qauth:admin:write` does not
  satisfy a read permission, and `qauth:admin:security` satisfies neither a read nor a write
  permission.
- A request that needs a write permission and a security permission needs both scopes.
- Scopes are matched exactly and case-sensitively (RFC 6749 §3.3).
- Every scope in the `qauth:` namespace, in any case, is QAuth's. A realm's dynamic
  registration allowlist cannot hold one, so dynamic registration drops one like any other scope
  outside the allowlist, and the developer API refuses one with `invalid_client_metadata`. A
  Client ID Metadata Document's `scope` is never stored, so one there is ignored. Discovery
  never lists one. Other servers' scopes such as `admin:org` are ordinary scopes.

## How a request is authorized

Under the rule the admin API will enforce, a permission is effective for a request when both
hold:

1. one of the caller's admin roles grants it, and
2. the token carries the scope of its class.

So a token with only `qauth:admin:write` never uses a security permission, whatever role the caller
holds. An admin API operation names the permission it needs in its `x-qauth-permission`
extension ([API conventions](/reference/api-conventions/#openapi)). An operation whose request
decides whether it is a security operation, such as a policy patch, names a write permission and
a security permission, and a request that touches both needs both.

The caller's roles come from its admin grants, which name a role and a realm, or every realm. They
are read from the database on every request, never from the token, so a revoked grant counts from
the next request ([Admin authority](/reference/api-conventions/#admin-authority)). The token
endpoint already applies the scope side: it issues an admin scope only to an account whose live
grants reach that scope's class, through a client that lists the admin API's audience.

## Permissions

| Permission                 | Class    | Scope                  | Resource          | Description                                                                                                                     |
| -------------------------- | -------- | ---------------------- | ----------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `realms.read`              | read     | `qauth:admin:read`     | `realms`          | Read a realm's representation, with its settings and policies.                                                                  |
| `realms.export`            | read     | `qauth:admin:read`     | `realms`          | Export a realm's configuration as a realm file, which holds no secret value.                                                    |
| `realms.import.plan`       | read     | `qauth:admin:read`     | `realms`          | Compute the dry-run plan of a realm-file import: every change it would make and the permissions each needs. It applies nothing. |
| `realms.policies.write`    | write    | `qauth:admin:write`    | `realms.policies` | Change a realm policy whose change is not a security operation, such as a token lifespan.                                       |
| `realms.policies.security` | security | `qauth:admin:security` | `realms.policies` | Change a realm policy whose change is a security operation, such as loosening the sign-in methods or the password policy.       |
| `approvals.read`           | read     | `qauth:admin:read`     | `approvals`       | Read the approval requests of security operations and where each one stands.                                                    |
| `approvals.approve`        | security | `qauth:admin:security` | `approvals`       | Approve another admin's security operation, with a fresh passkey.                                                               |

A permission has exactly one class. A permission that performs a security operation has an id of
its own and the class `security`; it never shares an id with a write permission, so no custom
role reaches a security operation through `qauth:admin:write`.

## Built-in roles

| Role             | Classes               | Permissions                                                                                                                                      | Description                                                     |
| ---------------- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------- |
| `viewer`         | read                  | `realms.read`, `realms.export`, `realms.import.plan`, `approvals.read`                                                                           | Reads everything an admin can read.                             |
| `editor`         | read, write           | `realms.read`, `realms.export`, `realms.import.plan`, `realms.policies.write`, `approvals.read`                                                  | Reads, and makes every change that is not a security operation. |
| `security-admin` | read, write, security | `realms.read`, `realms.export`, `realms.import.plan`, `realms.policies.write`, `realms.policies.security`, `approvals.read`, `approvals.approve` | Reads, makes every change, and performs security operations.    |

- Built-in roles are defined in code, by class, and cannot be edited. A permission added to the
  catalog joins every built-in role of its class.
- A custom role lists permission ids from the table above. An unknown id is refused, and so is a
  retired one. Its name is lower-case ASCII words joined by single hyphens, such as
  `realm-auditor`, and never reads as a built-in role's name.
- A custom role is defined in one realm, and granted only to that realm's accounts or for that
  realm. Disabling it takes its permissions from every grant at the next request.
- Admin roles are not the realm's application roles, which reach tokens as claims
  ([ADR-020](/reference/records/adr/020-ui-surfaces-and-acceptance-criteria/), fork D).

## Retired permissions

No permission has been retired.

## Stability

The permission ids will be part of the admin API's contract, because custom roles store them.
Like every QAuth-defined identifier, they are promised from 1.0.0 on
([ADR-018 §5](/reference/records/adr/018-1-0-scope-and-stability/)); until then a release may still
rename one, and says so in its changelog. From 1.0.0:

- An id is never renamed and never reused for another meaning.
- A permission that is no longer needed is retired, not removed: it is listed under
  [Retired permissions](#retired-permissions), it grants nothing, and its id stays taken.
- A release may add permissions. A new permission joins the built-in roles of its class.

The stable-surface check compares the catalog's JSON Schema
(`apps/docs-site/public/schemas/admin-permissions.json`) with the latest release: a removed permission, or one whose
class changed, is a break it reports.
