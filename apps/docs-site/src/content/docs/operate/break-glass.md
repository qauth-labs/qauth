---
title: Break-glass
description: Enrol the first admin, or a new one when no second admin can approve, and retire a compromised signing key, from the host that holds the database credentials and the KEK.
sidebar:
  order: 17
lastVerified: '2026-11-15'
---

The **break-glass CLI** is the way in when no admin can act
([ADR-019 Decision 7](/reference/records/adr/019-deployment-topology-and-trust-boundaries/),
[#602](https://github.com/qauth-labs/qauth/issues/602)). It has two
commands and no other:

- `enrol-admin` creates an admin account with no password and no credential,
  its admin grant, and a one-time enrolment URL, printed once;
- `retire-key` retires a token-signing key that may be compromised, as
  [`keys:retire`](/operate/keys/#emergency-retirement) does.

No command sets a password or imports a key. Whoever holds the host, the
database credentials and the KEK stands outside the two-admin rule, so every
run that changes anything is recorded and announced before the change
([What is recorded](#what-is-recorded)).

## Before you run it

Run it on a host that holds the database credentials and the KEK, with the
server's own environment:

- `DATABASE_URL`, naming a role that may write the realm's accounts, admin
  grants, enrolments, keys, refresh tokens, the admin audit log and the
  events: the owner's, not one service role's in a split deployment
  ([Service roles](/operate/service-roles/));
- the KEK: `KEK`, `KEK_PATH`, or a key service adapter's settings
  ([Keys](/operate/keys/));
- for `retire-key`, Redis (`REDIS_URL` or `REDIS_HOST` and its settings),
  through which the realm's sessions end.

It starts only when `DATABASE_URL` is set and the KEK opens a stored key: it
unwraps one stored key per KEK reference in use, zeroes it at once, and stops
with exit code 4 when the provider reports itself unusable, an unwrap fails,
or the database holds no key yet. A first server boot creates the keys, so
start the server once before you enrol the first admin.

The process registers no route and opens no listening port. It makes no HTTP
call: it connects to the database, and for `retire-key` to Redis.

Run it once every node runs the release that ships it. A node of an earlier
release does not know the `admin.break_glass_used` event.

```console
# From a checkout, with the server's environment:
pnpm nx run auth-server:break-glass -- enrol-admin --realm=operator --role=security-admin

# In the auth-server image, from /app:
tsx src/break-glass.ts enrol-admin --realm operator --role security-admin
```

## The first admin

A new deployment has no admin, and nothing but this command creates one.
Enrol the first in the operator realm
([Topology](/operate/topology/#the-operator-realm)), or in the realm it
administers:

```console
pnpm nx run auth-server:break-glass -- enrol-admin --realm=operator --role=security-admin
```

| Flag           | What it sets                                                                                                        |
| -------------- | ------------------------------------------------------------------------------------------------------------------- |
| `--realm`      | The realm the account lives in. Its grant covers that realm only. The realm must be enabled and have an issuer.     |
| `--role`       | A built-in admin role: `viewer`, `editor` or `security-admin`. Only `security-admin` approves another admin's work. |
| `--expires-in` | Minutes until the URL expires, 1 to 1440. Default: 60.                                                              |

In one transaction the command writes its record, then the account (a user
of the realm with no password and no credential), the enrolment, and the
grant, whose creator is no account. It prints the account's id and the
enrolment URL:

```text
Enrolled admin account 0193… in realm operator (0193…) with the role security-admin, run 6f1c… by ops on db-host-1.
Enrolment URL, valid once until 2026-11-15T13:04:05.000Z. It is shown only now and stored nowhere: hand it to the new admin only, over a channel you trust.

  https://auth.example.com/ui/admin-enrolment#token=…

The account cannot approve another admin's request before 2026-11-22T12:04:05.000Z (7 days). …
```

The URL starts at the realm's issuer, from the realm row. Its token is 32
random bytes. The database keeps only their SHA-256 hash, the token works
once and expires after an hour by default, and it travels in the URL's
fragment, which a browser sends to no server, proxy log or `Referer`. Whoever
opens the URL first registers the account's first passkey, so hand it to the
new admin only, and run the command again if it leaks or expires: each run
creates a new account. An account whose URL expired unused cannot sign in, as
it holds no credential.

:::caution[The enrolment page ships separately]
The page that turns the URL into the account's first passkey is the
Interaction API's enrolment step
([#621](https://github.com/qauth-labs/qauth/issues/621)). Until it ships, the
URL opens no page: the command creates the account, the grant and the token,
and the account cannot sign in.
:::

## A realm with no second admin

Where a realm makes an operation a mandatory two-admin operation and no
other admin may approve, the operation fails closed
([Security operations](/reference/security-operations/)). The ways out are,
in order: another eligible admin approves; an admin that changed its own
credentials, identifier or contact address approves once 7 days have passed;
or the host's holder enrols a new admin with this command.

```console
pnpm nx run auth-server:break-glass -- enrol-admin --realm=acme --role=security-admin
```

The new admin approves only after [the 7-day wait](#the-7-day-wait). Until
then the operation still fails closed, so plan for a week. The command is not
a way to approve an operation: it creates an approver, which waits like any
new admin.

An emergency key retirement waits for nobody. It never needs an approver
from this command.

## Retire a key in an emergency

```console
pnpm nx run auth-server:break-glass -- retire-key --realm=acme --kid=<kid> --confirm
```

It runs the emergency retirement of
[Keys](/operate/keys/#emergency-retirement) and nothing else: the key and its
hybrid partner leave the JWKS and go on the denylist, a new key signs, the
realm's refresh token families and sessions used since the key began to sign
are revoked. `--realm` and `--confirm` are required. A key retired already is
recorded again and its sessions are ended again, as with `keys:retire`. Exit
code 3 means the key is retired, or may be, but its sessions were not all
ended: run the command again.

## The 7-day wait

An admin the command enrols cannot approve another admin's request for 7
days. The two-admin rule refuses an approver whose account was created, or
which was granted a role, in the 7 days before the request it would approve
(ADR-019 Decision 7). The account and its grant are created at the run, so
the account approves only a request made 7 days or more after it. The
command prints that moment. An admin that changes its own credentials,
identifier or contact address waits 7 days from the change too.

## What is recorded

Before a run changes anything, and in the transaction of the change, it
writes:

- **an admin audit row of the realm**, with the actor kind
  `break_glass_operator` and the operating-system user as its actor, the
  operation `breakGlass.enrolAdmin` or `breakGlass.retireKey`, the class
  `security`, and a diff whose `after` holds the run: the command, its
  arguments (a secret one masked; no option of the two commands is one), the
  operating-system user's name and uid, and the host name. For
  `enrol-admin` it names the account, the role and the realm of the grant
  and the enrolment's expiry; for `retire-key` the kid and the digest of the
  retirement, which is the row's request digest too. The row's trace id is
  the run id the command prints;
- **a critical `admin.break_glass_used` event**
  ([Events](/reference/events/#adminbreak_glass_used-v1-rc0)), naming the
  command, with the operating-system user as its `operator_cli` actor. It is
  an admin event of the realm, in the realm's admin chain, and every event
  route of the realm carries it, as it carries every admin event: among them
  every SSF stream of the realm that requested
  `urn:qauth:secevent:break-glass-used:v1-rc.0`
  ([SSF events](/reference/ssf-events/)).

If either cannot be written, the run aborts with nothing changed. The change
then writes its own record: `retire-key` the `keys.retire` row and a
`key.emergency_retired` event per retired key. The token of an enrolment is
in no record.

A run refused before any change writes nothing: an unknown realm or kid, a
disabled realm, a realm with no issuer, a usage error, a KEK that opens no
stored key, or no `DATABASE_URL`.

## Exit codes

| Code | Meaning                                                                                                  |
| ---- | -------------------------------------------------------------------------------------------------------- |
| 0    | Done.                                                                                                    |
| 1    | Refused or failed, with nothing changed: the message says why.                                           |
| 2    | A usage error, or no `DATABASE_URL`.                                                                     |
| 3    | `retire-key` only: the key is retired, or may be, but its sessions were not all ended. Run it again.     |
| 4    | The KEK does not open a stored key: the provider is unusable, an unwrap failed, or no key is stored yet. |
