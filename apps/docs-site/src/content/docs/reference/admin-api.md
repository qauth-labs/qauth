---
title: Admin API
description: Every operation of the admin API, /admin/v1-rc.0, with its operation id, and where the OpenAPI document of each API family is served and published.
sidebar:
  order: 4
lastVerified: '2026-11-16'
---

The admin API manages a realm: its policies, its clients and resource servers, its accounts, its
AuthMethod plugins, and the approvals of its security operations
([ADR-019](/reference/records/adr/019-deployment-topology-and-trust-boundaries/), Decision 7). It
is served on the admin listener only, never on the public one. Every operation needs a DPoP-bound
admin access token, and a Bearer token is refused. The [API conventions](/reference/api-conventions/)
say how a request is authorized, which operations need an approval, and how errors, lists and
versions work.

The admin API is experimental. The admin listener runs only while `ADMIN_API_ENABLED` is on, and
it is off by default. Every operation is tagged `x-qauth-stability: experimental`, so it may change
in a minor release without a deprecation window
([Experimental features](/reference/experimental-features/)).

## The documents

Each API family has an OpenAPI 3.1 document of its own (#525), served by the listener that serves
the family:

| Family    | Served at                                             | Published as                                                              |
| --------- | ----------------------------------------------------- | ------------------------------------------------------------------------- |
| admin     | `GET /admin/v1-rc.0/openapi.json`, the admin listener | [`openapi-admin.json`](https://docs.qauth.dev/openapi-admin.json)         |
| account   | `GET /account/v1-rc.0/openapi.json`                   | [`openapi-account.json`](https://docs.qauth.dev/openapi-account.json)     |
| developer | `GET /developer/v1-rc.0/openapi.json`                 | [`openapi-developer.json`](https://docs.qauth.dev/openapi-developer.json) |

A document lists the operations of its family that the server serves. An operation whose switch is
off is not in it. The docs site publishes the documents of a server with every experimental switch
on, so they list every operation and tag each experimental one. Each document has its own `info`,
with the contract version (`v1-rc.0`) as `info.version`, a server entry, and the security schemes
its operations take: `bearerAuth` and `dpopAuth` on the account and developer APIs, and `dpopAuth`
alone on the admin API. The documents are unauthenticated and cacheable.

The account API's whole contract, with the operations still to come, is a separate document:
[Account API](/reference/account-api/).

An admin operation carries the extensions of the
[API conventions](/reference/api-conventions/#openapi). `x-qauth-class` is `read`, `write` or
`security`. `x-qauth-permission` names the permissions it needs, listed on
[Admin permissions](/reference/admin-permissions/). A security operation also names its effects in
`x-qauth-effects` ([Security operations](/reference/security-operations/)) and carries
`x-qauth-two-admin: recommended`.

## Realms

| Operation                                               | `operationId`             | What it does                                                                                         |
| ------------------------------------------------------- | ------------------------- | ---------------------------------------------------------------------------------------------------- |
| `GET /admin/v1-rc.0/realms/{realmId}`                   | `realms.get`              | Read a realm and its policies.                                                                       |
| `PATCH /admin/v1-rc.0/realms/{realmId}/policies`        | `realms.policies.update`  | Change a realm's policies ([Realm policies](/reference/realm-policies/)).                            |
| `POST /admin/v1-rc.0/realms/{realmId}/policies/preview` | `realms.policies.preview` | Preview a change of a realm's policies: what it changes and which approval it needs. Writes nothing. |

`realms.get` and `realms.policies.update` are the reference operations. A new admin operation is
built on them ([Adding an admin operation](/extend/adding-an-admin-operation/)).

## Approvals

| Operation                                                            | `operationId`      | What it does                                              |
| -------------------------------------------------------------------- | ------------------ | --------------------------------------------------------- |
| `POST /admin/v1-rc.0/realms/{realmId}/approvals`                     | `approvals.create` | File an approval for one request of a security operation. |
| `GET /admin/v1-rc.0/realms/{realmId}/approvals/{approvalId}`         | `approvals.get`    | Read an approval request.                                 |
| `POST /admin/v1-rc.0/realms/{realmId}/approvals/{approvalId}/cancel` | `approvals.cancel` | Withdraw an approval request the caller filed.            |

The [API conventions](/reference/api-conventions/) say how an approval is filed, approved and used.

## Clients

| Operation                                                         | `operationId`     | What it does                                  |
| ----------------------------------------------------------------- | ----------------- | --------------------------------------------- |
| `GET /admin/v1-rc.0/realms/{realmId}/clients`                     | `clients.list`    | List the clients of a realm.                  |
| `POST /admin/v1-rc.0/realms/{realmId}/clients`                    | `clients.create`  | Register a client.                            |
| `GET /admin/v1-rc.0/realms/{realmId}/clients/{clientId}`          | `clients.get`     | Read a client.                                |
| `PATCH /admin/v1-rc.0/realms/{realmId}/clients/{clientId}`        | `clients.update`  | Change a client.                              |
| `DELETE /admin/v1-rc.0/realms/{realmId}/clients/{clientId}`       | `clients.delete`  | Delete a client.                              |
| `POST /admin/v1-rc.0/realms/{realmId}/clients/{clientId}/preview` | `clients.preview` | Preview a change of a client. Writes nothing. |
| `POST /admin/v1-rc.0/realms/{realmId}/clients/{clientId}/enable`  | `clients.enable`  | Enable a client.                              |
| `POST /admin/v1-rc.0/realms/{realmId}/clients/{clientId}/disable` | `clients.disable` | Suspend a client.                             |

[Clients](/operate/clients/) explains each one, and which changes need an approval.

## Resource servers

| Operation                                                                          | `operationId`             | What it does                                           |
| ---------------------------------------------------------------------------------- | ------------------------- | ------------------------------------------------------ |
| `GET /admin/v1-rc.0/realms/{realmId}/resource-servers`                             | `resourceServers.list`    | List the resource servers of a realm.                  |
| `POST /admin/v1-rc.0/realms/{realmId}/resource-servers`                            | `resourceServers.create`  | Register a resource server.                            |
| `GET /admin/v1-rc.0/realms/{realmId}/resource-servers/{resourceServerId}`          | `resourceServers.get`     | Read a resource server.                                |
| `PATCH /admin/v1-rc.0/realms/{realmId}/resource-servers/{resourceServerId}`        | `resourceServers.update`  | Change a resource server.                              |
| `DELETE /admin/v1-rc.0/realms/{realmId}/resource-servers/{resourceServerId}`       | `resourceServers.delete`  | Delete a resource server.                              |
| `POST /admin/v1-rc.0/realms/{realmId}/resource-servers/{resourceServerId}/preview` | `resourceServers.preview` | Preview a change of a resource server. Writes nothing. |

## Accounts

| Operation                                                          | `operationId`  | What it does                       |
| ------------------------------------------------------------------ | -------------- | ---------------------------------- |
| `POST /admin/v1-rc.0/realms/{realmId}/users/{userId}/verification` | `users.verify` | Verify an account as the operator. |
| `DELETE /admin/v1-rc.0/realms/{realmId}/users/{userId}`            | `users.delete` | Delete an account.                 |

[Accounts](/operate/accounts/) explains both.

## AuthMethod plugins and secrets

| Operation                                                             | `operationId`           | What it does                                                               |
| --------------------------------------------------------------------- | ----------------------- | -------------------------------------------------------------------------- |
| `GET /admin/v1-rc.0/realms/{realmId}/plugins`                         | `plugins.list`          | List the installed AuthMethod plugins and the realm's state of each.       |
| `GET /admin/v1-rc.0/realms/{realmId}/plugins/{plugin}`                | `plugins.get`           | Read an installed AuthMethod plugin and the realm's state of it.           |
| `POST /admin/v1-rc.0/realms/{realmId}/plugins/{plugin}/config`        | `plugins.update`        | Replace an AuthMethod plugin's configuration in the realm.                 |
| `POST /admin/v1-rc.0/realms/{realmId}/plugins/{plugin}/enable`        | `plugins.enable`        | Enable an AuthMethod plugin in the realm.                                  |
| `POST /admin/v1-rc.0/realms/{realmId}/plugins/{plugin}/disable`       | `plugins.disable`       | Disable an AuthMethod plugin in the realm.                                 |
| `POST /admin/v1-rc.0/realms/{realmId}/plugins/{plugin}/keys`          | `plugins.keys.import`   | Import a provider-issued private key as the plugin's client-assertion key. |
| `POST /admin/v1-rc.0/realms/{realmId}/plugins/{plugin}/keys/activate` | `plugins.keys.activate` | Switch the plugin's client assertions to its next key.                     |
| `POST /admin/v1-rc.0/realms/{realmId}/secrets/seal`                   | `secrets.seal`          | Seal a value for a security operation's secret member in the realm.        |

[The AuthMethod contract](/extend/auth-method-contract/) explains the plugins and the sealed
secrets, and [Keys](/operate/keys/) the plugin keys.
