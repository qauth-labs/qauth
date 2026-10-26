---
title: Security operations
description: What makes an admin operation a security operation, the effect tags, every admin operation with its class and effects, and the reserved operation ids, generated from the registry in apps/auth-server.
sidebar:
  order: 7
lastVerified: '2026-10-26'
---

<!-- Generated from apps/auth-server/src/app/helpers/admin-operations.ts by its tests. Do not edit by hand: change the registry and run `pnpm nx test auth-server -- -u`. -->

An admin API operation needs `qauth:admin:security` because of what it does, not because of
the screen it sits on ([ADR-019](/reference/records/adr/019-deployment-topology-and-trust-boundaries/),
Decision 7). Each admin operation is defined once, in the registry in `apps/auth-server/src/app/helpers/admin-operations.ts`, with
its class, the effects that make it a security operation and the
[permissions](/reference/admin-permissions/) it needs. This page is generated from that registry.
No admin API route exists yet, so the rules below protect nothing today: they are in place for the
admin listener and its operations.

## Effects

| Effect                 | An operation with it                                                                          |
| ---------------------- | --------------------------------------------------------------------------------------------- |
| `credential-path`      | Changes which credentials, links or addresses can authenticate or recover an account.         |
| `token-content`        | Changes what a token asserts or who receives it.                                              |
| `issue-for-other`      | Issues a token or session for someone other than the caller.                                  |
| `administration`       | Changes who administers.                                                                      |
| `import`               | Imports a realm file, or promotes a sandbox configuration, whose diff holds any other effect. |
| `federation-operator`  | Acts as a federation operator.                                                                |
| `key-custody`          | Rotates a key, rotates the KEK or retires a key.                                              |
| `realm-lifecycle`      | Deletes a realm or transfers its ownership.                                                   |
| `authority-tree-power` | Revokes by agent or disables a transmitter.                                                   |
| `posture-loosening`    | Loosens the environment posture.                                                              |
| `bulk-revocation`      | Revokes sessions or refresh-token families in bulk.                                           |

The list is closed. A definition that names another value is refused, and a request whose
classification names one counts as a security operation. The tags are published on each admin
operation of the OpenAPI document as `x-qauth-effects`
([API conventions](/reference/api-conventions/#openapi)).

## Rules

- An operation is of class `security` if and only if it has at least one effect. The registry
  refuses a `read` or `write` operation with an effect, and a `security` operation with none.
- Its class is the strictest class among its permissions (`read` < `write` < `security`). So an
  operation with an effect needs a `security` permission, which only `qauth:admin:security` lets a
  token use: no role reaches it through `qauth:admin:write`.
- An operation whose request decides what it needs, such as a policy patch or a realm-file import,
  declares the strictest case (class `security`, every effect it may have and every permission it
  may need) and a `classify` function. `classify` is pure: it reads copies of the request's
  method, path parameters, query and body, and the operation's current state, and returns the
  class, the effects and the permissions that request needs, within the declaration.
- The admin pipeline classifies every request after validation and before the handler. The
  handler receives the classification and cannot lower it, and every later stage reads the same
  one. The path parameters, query and body it classified are frozen: a stage that changes them
  fails the request.
- Fail closed: when `classify` throws, meets a field it has no rule for, or returns an unknown
  member, effect, class or permission, or more than the operation declares, the request needs the
  operation as declared: `security`, with every declared effect and permission.
- At boot, the admin listener refuses a route that names no registered operation, and one whose
  `operationId`, `x-qauth-class`, `x-qauth-permission`, `x-qauth-effects` or
  `x-qauth-two-admin` differs from the registry. The classification stage is registered before
  every route, and checks each route again on its first request. In CI, the API conventions check
  fails when an admin operation of the OpenAPI document disagrees with the registry.

These are not security operations:

- Sending a set-up or reset link to the contact address already on the account. The link reaches
  only the person a self-service reset reaches. Copying the link is a security operation.
- Brand strings and links. They are display data, under `qauth:admin:write`.
- Anything outside the admin API. The developer API's changes to a client the caller owns
  ([ADR-012](/reference/records/adr/012-dynamic-client-ownership/)) and the account API's changes
  to the caller's own account keep their own rules.

## Operations

No admin operation is registered yet.

## Reserved operations

Other areas register the operations below, and the Registered column says which are registered.
When one is registered, the registry refuses it unless it is a security operation that carries at
least the effects listed, and refuses an id that differs from one only in case. An operation may
carry more effects. Only an operation marked "per request" may decide per request what it needs,
with `classify`, and it lists every effect it may have; every other one needs its declaration on
every request. Each entry is listed under each of its effects. The table lives in
`apps/auth-server/src/app/helpers/admin-operations-reserved.ts`.

### `credential-path`

| Operation                          | Effects                                                                   | Per request | Registered | Source                              | Description                                                                                                                                                                 |
| ---------------------------------- | ------------------------------------------------------------------------- | ----------- | ---------- | ----------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `users.links.copy`                 | `credential-path`                                                         | no          | no         | ADR-019 Decision 7, ADR-020 §3      | Copy a one-time set-up or reset link, returned once to the admin who copies it.                                                                                             |
| `users.identifiers.update`         | `credential-path`                                                         | no          | no         | ADR-019 Decision 7, ADR-020 §3      | Change an account's identifier or contact address.                                                                                                                          |
| `users.passkeys.delete`            | `credential-path`                                                         | no          | no         | ADR-019 Decision 7, ADR-020 §3      | Remove a passkey from an account.                                                                                                                                           |
| `users.totp.delete`                | `credential-path`                                                         | no          | no         | ADR-019 Decision 7, ADR-020 §3      | Remove an account's TOTP.                                                                                                                                                   |
| `users.recoveryCodes.delete`       | `credential-path`                                                         | no          | no         | ADR-019 Decision 7                  | Remove an account's recovery codes.                                                                                                                                         |
| `users.linkedAccounts.delete`      | `credential-path`                                                         | no          | no         | ADR-019 Decision 7                  | Unlink an upstream or wallet account from an account.                                                                                                                       |
| `users.idJagSubjects.create`       | `credential-path`                                                         | no          | no         | ADR-019 Decision 7, ADR-011 gate 14 | Link an enterprise ID-JAG subject to an account, the one link an admin may make.                                                                                            |
| `upstreamProviders.create`         | `credential-path`                                                         | no          | no         | ADR-019 Decision 7, #714            | Add an upstream identity provider.                                                                                                                                          |
| `upstreamProviders.update`         | `credential-path`                                                         | no          | no         | ADR-019 Decision 7, #714            | Change an upstream identity provider.                                                                                                                                       |
| `upstreamProviders.disable`        | `credential-path`                                                         | no          | no         | ADR-019 Decision 7, #714            | Disable an upstream identity provider.                                                                                                                                      |
| `upstreamProviders.delete`         | `credential-path`                                                         | no          | no         | ADR-019 Decision 7, #714            | Remove an upstream identity provider.                                                                                                                                       |
| `upstreamProviders.mappers.create` | `credential-path`                                                         | no          | no         | ADR-019 Decision 7, #714            | Add a mapper to an upstream provider's claims.                                                                                                                              |
| `upstreamProviders.mappers.update` | `credential-path`                                                         | no          | no         | ADR-019 Decision 7, #714            | Change a mapper of an upstream provider's claims.                                                                                                                           |
| `upstreamProviders.mappers.delete` | `credential-path`                                                         | no          | no         | ADR-019 Decision 7, #714            | Remove a mapper of an upstream provider's claims.                                                                                                                           |
| `trustedIssuers.create`            | `credential-path`                                                         | no          | no         | ADR-019 Decision 7                  | Trust a credential issuer for wallet sign-in.                                                                                                                               |
| `trustedIssuers.update`            | `credential-path`                                                         | no          | no         | ADR-019 Decision 7                  | Change a trusted credential issuer.                                                                                                                                         |
| `trustedIssuers.delete`            | `credential-path`                                                         | no          | no         | ADR-019 Decision 7                  | Stop trusting a credential issuer.                                                                                                                                          |
| `plugins.enable`                   | `credential-path`                                                         | no          | no         | ADR-019 Decision 7, #600            | Enable an AuthMethod plugin in a realm.                                                                                                                                     |
| `plugins.update`                   | `credential-path`                                                         | no          | no         | ADR-019 Decision 7, #600            | Change an AuthMethod plugin's configuration in a realm.                                                                                                                     |
| `realms.policies.update`           | `credential-path`, `token-content`, `posture-loosening`, `administration` | yes         | no         | ADR-019 Decision 7, #514, #517      | Change realm policies: the mail transport and sender, the sign-in, password and brute-force policy, the registration policy, the environment ceiling and the two-admin set. |

### `token-content`

| Operation                | Effects                                                                   | Per request | Registered | Source                         | Description                                                                                                                                                                 |
| ------------------------ | ------------------------------------------------------------------------- | ----------- | ---------- | ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `realms.policies.update` | `credential-path`, `token-content`, `posture-loosening`, `administration` | yes         | no         | ADR-019 Decision 7, #514, #517 | Change realm policies: the mail transport and sender, the sign-in, password and brute-force policy, the registration policy, the environment ceiling and the two-admin set. |
| `clients.create`         | `token-content`                                                           | no          | no         | ADR-019 Decision 7, #518, #632 | Register a client, with its redirect URIs, authentication method and trust.                                                                                                 |
| `clients.update`         | `token-content`, `posture-loosening`                                      | yes         | no         | ADR-019 Decision 7, #518, #632 | Change a client: its redirect URIs, authentication method, first-party trust, verified domain, PKCE or DPoP, environment or agent-type fields.                              |
| `clients.delete`         | `token-content`                                                           | no          | no         | ADR-019 Decision 7, #518, #632 | Delete a client.                                                                                                                                                            |
| `scopes.create`          | `token-content`                                                           | no          | no         | ADR-019 Decision 7, ADR-020 §3 | Add a scope to the catalog.                                                                                                                                                 |
| `scopes.update`          | `token-content`                                                           | no          | no         | ADR-019 Decision 7, ADR-020 §3 | Change a scope of the catalog.                                                                                                                                              |
| `scopes.delete`          | `token-content`                                                           | no          | no         | ADR-019 Decision 7, ADR-020 §3 | Remove a scope from the catalog.                                                                                                                                            |
| `mappers.create`         | `token-content`                                                           | no          | no         | ADR-019 Decision 7             | Add a token mapper.                                                                                                                                                         |
| `mappers.update`         | `token-content`                                                           | no          | no         | ADR-019 Decision 7             | Change a token mapper.                                                                                                                                                      |
| `mappers.delete`         | `token-content`                                                           | no          | no         | ADR-019 Decision 7             | Remove a token mapper.                                                                                                                                                      |
| `resourceServers.create` | `token-content`                                                           | no          | no         | ADR-019 Decision 7             | Register a resource server and its audience.                                                                                                                                |
| `resourceServers.update` | `token-content`                                                           | no          | no         | ADR-019 Decision 7             | Change a resource server or its audience.                                                                                                                                   |
| `resourceServers.delete` | `token-content`                                                           | no          | no         | ADR-019 Decision 7             | Remove a resource server and its audience.                                                                                                                                  |
| `users.roles.assign`     | `token-content`                                                           | no          | no         | ADR-019 Decision 7, #683       | Assign a role to an account.                                                                                                                                                |
| `users.roles.remove`     | `token-content`                                                           | no          | no         | ADR-019 Decision 7, #683       | Remove a role from an account.                                                                                                                                              |
| `groups.members.add`     | `token-content`                                                           | no          | no         | ADR-019 Decision 7, #683       | Add an account to a group.                                                                                                                                                  |
| `groups.members.remove`  | `token-content`                                                           | no          | no         | ADR-019 Decision 7, #683       | Remove an account from a group.                                                                                                                                             |
| `webhooks.create`        | `token-content`                                                           | no          | no         | #537                           | Add a webhook subscription.                                                                                                                                                 |
| `webhooks.update`        | `token-content`                                                           | no          | no         | #537                           | Change a webhook subscription.                                                                                                                                              |
| `webhooks.delete`        | `token-content`                                                           | no          | no         | #537                           | Remove a webhook subscription.                                                                                                                                              |
| `webhooks.rotateSecret`  | `token-content`                                                           | no          | no         | #537                           | Rotate a webhook subscription's signing secret.                                                                                                                             |
| `webhooks.test`          | `token-content`                                                           | no          | no         | #537                           | Send a test event to a webhook subscription's destination.                                                                                                                  |
| `ssfStreams.create`      | `token-content`                                                           | no          | no         | #537                           | Add a Shared Signals stream.                                                                                                                                                |
| `ssfStreams.update`      | `token-content`                                                           | no          | no         | #537                           | Change a Shared Signals stream's destination.                                                                                                                               |
| `ssfStreams.delete`      | `token-content`                                                           | no          | no         | #537                           | Remove a Shared Signals stream.                                                                                                                                             |

### `issue-for-other`

| Operation                     | Effects           | Per request | Registered | Source                   | Description                                                   |
| ----------------------------- | ----------------- | ----------- | ---------- | ------------------------ | ------------------------------------------------------------- |
| `users.actChainTokens.create` | `issue-for-other` | no          | no         | ADR-019 Decision 7, #523 | Issue an act-chain token to an admin who acts for an account. |

### `administration`

| Operation                | Effects                                                                   | Per request | Registered | Source                         | Description                                                                                                                                                                 |
| ------------------------ | ------------------------------------------------------------------------- | ----------- | ---------- | ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `realms.policies.update` | `credential-path`, `token-content`, `posture-loosening`, `administration` | yes         | no         | ADR-019 Decision 7, #514, #517 | Change realm policies: the mail transport and sender, the sign-in, password and brute-force policy, the registration policy, the environment ceiling and the two-admin set. |
| `admins.create`          | `administration`                                                          | no          | no         | ADR-019 Decision 7, #679       | Create an admin account.                                                                                                                                                    |
| `admins.delete`          | `administration`                                                          | no          | no         | ADR-019 Decision 7, #679       | Remove an admin account.                                                                                                                                                    |
| `adminGrants.create`     | `administration`                                                          | no          | no         | ADR-019 Decision 7, #679       | Grant an admin role to an account in a realm.                                                                                                                               |
| `adminGrants.delete`     | `administration`                                                          | no          | no         | ADR-019 Decision 7, #679       | Remove an admin role from an account.                                                                                                                                       |
| `adminRoles.create`      | `administration`                                                          | no          | no         | ADR-019 Decision 7, #679       | Create a custom admin role.                                                                                                                                                 |
| `adminRoles.update`      | `administration`                                                          | no          | no         | ADR-019 Decision 7, #679       | Change the permissions of a custom admin role.                                                                                                                              |
| `adminRoles.delete`      | `administration`                                                          | no          | no         | ADR-019 Decision 7, #679       | Delete a custom admin role.                                                                                                                                                 |
| `serviceAccounts.create` | `administration`                                                          | no          | no         | ADR-019 Decision 7, #679       | Create a service account for the admin API.                                                                                                                                 |
| `serviceAccounts.delete` | `administration`                                                          | no          | no         | ADR-019 Decision 7, #679       | Remove a service account.                                                                                                                                                   |

### `import`

| Operation              | Effects  | Per request | Registered | Source                                 | Description                                       |
| ---------------------- | -------- | ----------- | ---------- | -------------------------------------- | ------------------------------------------------- |
| `realms.imports.apply` | `import` | yes         | no         | ADR-019 Decisions 7 and 11, #531, #555 | Apply a realm-file import or a sandbox promotion. |

### `federation-operator`

| Operation                               | Effects                              | Per request | Registered | Source                         | Description                                                             |
| --------------------------------------- | ------------------------------------ | ----------- | ---------- | ------------------------------ | ----------------------------------------------------------------------- |
| `federation.entityConfiguration.update` | `federation-operator`                | no          | no         | ADR-019 Decision 7, ADR-020 §3 | Change the realm's federation entity configuration and authority hints. |
| `federation.subordinates.create`        | `federation-operator`                | no          | no         | ADR-019 Decision 7, ADR-020 §3 | Add a federation subordinate.                                           |
| `federation.subordinates.update`        | `federation-operator`                | no          | no         | ADR-019 Decision 7, ADR-020 §3 | Change a federation subordinate.                                        |
| `federation.subordinates.delete`        | `federation-operator`                | no          | no         | ADR-019 Decision 7, ADR-020 §3 | Remove a federation subordinate.                                        |
| `federation.metadataPolicy.update`      | `federation-operator`                | no          | no         | ADR-019 Decision 7, ADR-020 §3 | Change the federation metadata policy and its constraints.              |
| `federation.trustMarks.create`          | `federation-operator`                | no          | no         | ADR-019 Decision 7, ADR-020 §3 | Issue a trust mark.                                                     |
| `federation.trustMarks.delete`          | `federation-operator`                | no          | no         | ADR-019 Decision 7, ADR-020 §3 | Revoke a trust mark.                                                    |
| `federation.registrations.approve`      | `federation-operator`                | no          | no         | ADR-019 Decision 7, #731       | Approve an explicit federation registration.                            |
| `federation.keys.rotate`                | `federation-operator`, `key-custody` | no          | no         | ADR-019 Decision 7, ADR-020 §3 | Rotate the federation keys.                                             |

### `key-custody`

| Operation                | Effects                              | Per request | Registered | Source                         | Description                                      |
| ------------------------ | ------------------------------------ | ----------- | ---------- | ------------------------------ | ------------------------------------------------ |
| `federation.keys.rotate` | `federation-operator`, `key-custody` | no          | no         | ADR-019 Decision 7, ADR-020 §3 | Rotate the federation keys.                      |
| `keys.rotate`            | `key-custody`                        | no          | no         | ADR-019 Decision 9, #544       | Rotate a realm's key before its rotation is due. |
| `keys.retire`            | `key-custody`                        | no          | no         | ADR-019 Decision 9             | Retire a key, which leaves the JWKS at once.     |
| `kek.rotate`             | `key-custody`                        | no          | no         | ADR-019 Decision 9, #545       | Rotate the KEK and re-wrap every stored key.     |

### `realm-lifecycle`

| Operation                   | Effects           | Per request | Registered | Source             | Description                   |
| --------------------------- | ----------------- | ----------- | ---------- | ------------------ | ----------------------------- |
| `realms.delete`             | `realm-lifecycle` | no          | no         | ADR-019 Decision 7 | Delete a realm.               |
| `realms.ownership.transfer` | `realm-lifecycle` | no          | no         | ADR-019 Decision 7 | Transfer a realm's ownership. |

### `authority-tree-power`

| Operation              | Effects                | Per request | Registered | Source                      | Description                                                              |
| ---------------------- | ---------------------- | ----------- | ---------- | --------------------------- | ------------------------------------------------------------------------ |
| `agents.revoke`        | `authority-tree-power` | no          | no         | ADR-019 Decision 7, ADR-014 | Revoke by agent: end every grant and token of an agent's authority tree. |
| `transmitters.disable` | `authority-tree-power` | no          | no         | ADR-019 Decision 7, ADR-014 | Disable a registered transmitter.                                        |

### `posture-loosening`

| Operation                | Effects                                                                   | Per request | Registered | Source                         | Description                                                                                                                                                                 |
| ------------------------ | ------------------------------------------------------------------------- | ----------- | ---------- | ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `realms.policies.update` | `credential-path`, `token-content`, `posture-loosening`, `administration` | yes         | no         | ADR-019 Decision 7, #514, #517 | Change realm policies: the mail transport and sender, the sign-in, password and brute-force policy, the registration policy, the environment ceiling and the two-admin set. |
| `clients.update`         | `token-content`, `posture-loosening`                                      | yes         | no         | ADR-019 Decision 7, #518, #632 | Change a client: its redirect URIs, authentication method, first-party trust, verified domain, PKCE or DPoP, environment or agent-type fields.                              |

### `bulk-revocation`

| Operation                    | Effects           | Per request | Registered | Source           | Description                                                |
| ---------------------------- | ----------------- | ----------- | ---------- | ---------------- | ---------------------------------------------------------- |
| `clients.sessions.revokeAll` | `bulk-revocation` | no          | no         | ADR-020 §3, #625 | Revoke every session and refresh-token family of a client. |
| `realms.sessions.revokeAll`  | `bulk-revocation` | no          | no         | ADR-020 §3, #550 | Revoke sessions of a realm in bulk.                        |

## Stability

The effect tags and the operation ids will be part of the admin API's contract. Like every
QAuth-defined identifier, they are promised from 1.0.0 on
([ADR-018 §5](/reference/records/adr/018-1-0-scope-and-stability/)); until then a release may still
rename one, and says so in its changelog. A reserved entry may be renamed by the change that
registers its operation, but never weakened.
