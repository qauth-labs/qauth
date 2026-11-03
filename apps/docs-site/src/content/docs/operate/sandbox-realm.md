---
title: Sandbox realm
description: The paired sandbox realm of a live realm — what it shares with the live realm, what it does not, and the rules the database holds.
sidebar:
  order: 14
lastVerified: '2026-11-03'
---

A live realm can have one **paired sandbox realm**. The sandbox is a realm in its own right, with
its own host, issuer, keys and passkey RP ID. Its environment ceiling is `staging`, so the developer
portal's flow test console works there while the live realm stays at `production`. The design is
[ADR-019 Decision 11](/reference/records/adr/019-deployment-topology-and-trust-boundaries/) and
[ADR-020 §4](/reference/records/adr/020-ui-surfaces-and-acceptance-criteria/).

## What the sandbox shares, and what it does not

The sandbox runs in the same deployment as its live realm. It shares what the deployment holds:

| Shared with the live realm            | Why                                                                                                                          |
| ------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| The database                          | Every realm's rows live in one database; each row names its realm, and every read is scoped to one.                          |
| The KEK                               | The sandbox's keys are wrapped with the deployment's key-encryption key, as every realm's are ([Keys](/operate/keys/)).      |
| The signer role                       | The same signer process holds both realms' keys and signs for each with that realm's own keys.                               |
| The trust domain                      | Whoever operates the deployment operates the sandbox. A sandbox is for testing configuration, not for isolating an attacker. |
| The deployment's environment switches | Process-wide variables, such as the listeners and the KEK provider, apply to every realm.                                    |

It shares nothing that belongs to a realm:

| Its own                   | What that means                                                                                                                                                                                                                      |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Host                      | The sandbox has a primary host of its own. Hosts are unique across all realms, the sandbox twins included, so the sandbox's host is never the live realm's. You provision its DNS and TLS like any realm host.                       |
| Issuer                    | Its issuer is on its own host and is permanent, as every realm's is. Discovery and the JWKS at the sandbox host describe the sandbox.                                                                                                |
| Keys                      | It gets its own token signing keys (RS256 as well, as a new realm does), cookie key, event signing key and data-at-rest key when it is created. No key of the live realm is copied or shared.                                        |
| Passkey RP ID             | Its RP ID is its own host. A passkey enrolled for the live realm does not work in the sandbox.                                                                                                                                       |
| Users and sessions        | It starts with no users. A user of the live realm cannot sign in to the sandbox: realm isolation keeps every account in the realm that created it. Create test users in the sandbox.                                                 |
| Clients, consents, grants | It starts with none. Register the clients you test with in the sandbox.                                                                                                                                                              |
| Policies                  | It is seeded from the environment's defaults, like any new realm, and copies nothing from the live realm. Two values differ from the seeds: the environment ceiling is `staging`, and the mail transport is `mock`, which only logs. |
| Secrets                   | None is copied. Live secrets stay on the live realm.                                                                                                                                                                                 |
| Upstream providers        | Configure them with test accounts of the provider. That is configuration, not code.                                                                                                                                                  |

## The environment ceiling

A sandbox's ceiling (`posture.maxEnvironmentLaxity`, see
[Environment-aware authorization](/operate/environment-authorization/)) is `staging` when it is
created. A client is always held to the stricter of its own environment and the ceiling, so:

- a sandbox client set to `development` runs with the `staging` profile: PKCE required, https
  redirect URIs only, no static API keys, refresh-token rotation, lenient rate limits;
- a sandbox client set to `staging` or `production` keeps its own profile.

The ceiling can be tightened to `production`, and set back to `staging`. It can never be
`development`: the database refuses the value whoever writes it, and the server's realm policy
update answers a request for it with `422` and the problem type
[`sandbox_ceiling`](/reference/problem-types/#sandbox-ceiling). The admin API operation that updates
a realm's policies, which calls that update, is #517.

## Tokens

A token the sandbox issues names the sandbox's issuer and is signed with the sandbox's keys. A
resource server of the live realm checks the issuer, as every resource server must, so it refuses a
sandbox token. No claim marks a token as a sandbox token: a same-issuer sandbox flag was rejected,
because every resource server would have to check it, and one that forgot would accept sandbox
tokens.

## Rules the database holds

Migration 0056 adds `realms.sandbox_of_realm_id`, which names a sandbox's live realm. The rules
hold for every writer, a hand-written SQL statement included:

| Rule                                                                               | Held by                                                 |
| ---------------------------------------------------------------------------------- | ------------------------------------------------------- |
| A live realm has at most one sandbox.                                              | the unique index `idx_realms_sandbox_of_realm_id`       |
| A realm is not its own sandbox.                                                    | the CHECK `realms_sandbox_not_self`                     |
| A sandbox has no sandbox.                                                          | the trigger `realms_sandbox_pairing`                    |
| A sandbox's live realm exists before the sandbox, not later in the same statement. | the trigger, and the foreign key                        |
| The operator realm is no sandbox and has none.                                     | the CHECK `realms_sandbox_not_operator` and the trigger |
| The pairing is set when the sandbox is created and never changes.                  | the trigger                                             |
| A sandbox's ceiling is never `development`.                                        | the CHECK `realms_sandbox_ceiling`                      |
| A live realm cannot be deleted while its sandbox exists. Delete the sandbox first. | the foreign key, `ON DELETE RESTRICT`                   |

Because the operator realm has no sandbox, a deployment in single-realm simple mode, where the
default realm is also the operator realm, has none either. A sandbox needs a live realm of its own,
next to the operator realm
([ADR-019 Decision 1](/reference/records/adr/019-deployment-topology-and-trust-boundaries/)).

One check reads rows other than the one written: moving the operator flag onto a realm looks for
that realm's sandbox. In a `REPEATABLE READ` transaction it looks in the transaction's snapshot,
which a sandbox committed in the meantime is not in. Move the operator flag by hand only under
`READ COMMITTED`, as the server does, under its realm provisioning lock.

## Creating a sandbox

The server creates a sandbox in one transaction: the realm and its primary host from the issuer you
choose, the pairing and the `staging` ceiling, its policies with the test mail transport, and its
keys. Either all of it is stored, or none of it.

The admin API operation that creates a sandbox and reads the pairing comes with the realm lifecycle
operations (#694). Creating a realm is a security operation. Until that operation ships, a sandbox
is created only from the server's code (`createSandboxRealm`). The admin API's realm representation
(#517) is to show the pairing as two read-only fields: `sandboxOf`, the live realm's id on a sandbox,
and `sandbox`, the sandbox's id on a live realm; each is `null` otherwise. The server already reads
both (`sandboxPairingOf`).

Moving settings from the sandbox to the live realm goes through the realm file's diff, where fields
that describe the sandbox's environment (its ceiling, `http` redirect URIs, test upstreams, test
webhook receivers) move only when selected one by one. That comes with the realm file import.
