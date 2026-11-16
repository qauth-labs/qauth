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
call of its own: it connects to the database, for `retire-key` to Redis, and
to the key service when a KEK adapter holds the KEK there.

Run it once every node runs the release that ships it. A node of an earlier
release does not know the `admin.break_glass_used` event.

Run it with `tsx` directly, in an interactive shell. `enrol-admin` prints a
live token, so keep its output out of everything that stores it:

- **Not as an Nx task.** Nx keeps every task's terminal output on disk, so
  there is no Nx target for the CLI, and `enrol-admin` refuses to run under
  one (exit code 2).
- **Not as a one-off container or job** whose output goes to a log driver or
  a log store: `docker exec -it` into a running container, or a shell on the
  host, prints only to your terminal.
- **Not through `script`, `tee`** or a terminal that records its session.

```console
# From apps/auth-server in a checkout, with the server's environment:
pnpm exec tsx src/break-glass.ts enrol-admin --realm operator --role security-admin

# In the auth-server image, from /app:
tsx src/break-glass.ts enrol-admin --realm operator --role security-admin
```

## The first admin

A new deployment has no admin, and nothing but this command creates one.
Enrol the first in the operator realm
([Topology](/operate/topology/#the-operator-realm)), or in the realm it
administers:

```console
tsx src/break-glass.ts enrol-admin --realm operator --role security-admin
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
new admin only.

A URL that expired unused leaves an account that cannot sign in, as it holds
no credential: run the command again for a new account and URL. **A URL that
leaked stays valid until it expires**, and running the command again does
not change that: delete its account at once, before anyone uses the URL. As
the database owner, with the account id the command printed:

```sql
DELETE FROM users WHERE id = '<account id>';
```

The enrolment and the grant go with the account. This deletion is not a
break-glass run and writes no audit row: note it with the incident. Then
enrol again.

### What the new admin does with the URL

The URL opens the ceremony app's enrolment page. When the new admin presses
its button, the page posts the token to the auth server
(`POST /auth/admin-enrolment`), which starts the Interaction API's
`admin_enrolment` step
([#621](https://github.com/qauth-labs/qauth/issues/621)): the browser creates
a passkey for the realm, and it must verify the user, with a PIN or a
biometric. Starting reads the token and spends nothing, so a link scanner
that opens the URL, or a ceremony the admin abandons or cancels, leaves it
usable until it expires. The token is spent in the transaction that stores
the passkey, and only then.

- **No password, ever.** The step has no alternative, and the account holds
  the passkey alone. It signs in with it like any account.
- **No approvals for 7 days.** Storing the passkey is a security change of
  the account (`user.credential_added`), so it cannot approve another admin's
  request until 7 days have passed. The enrolment also writes
  `admin.enrolment_completed` to the realm's admin events.
- **One answer for every bad URL.** A token that is unknown, used, expired or
  damaged gets the same page, "This enrolment link is no longer valid", and
  starts nothing. So does every URL while passkey sign-in is off
  (`WEBAUTHN_ENABLED`): the account could not sign in with its passkey. The
  server's log says why at `warn`, and the URL works once passkeys are on.
- **The enrolment signs nobody in.** It ends on the auth server's page
  `/auth/admin-enrolment/status`, or on the realm's ceremony app error page
  when the realm names one (`ceremonyApp.errorPage`), with the code
  `admin_enrolment_finished` or `admin_enrolment_refused`.

:::caution[The enrolment page is the ceremony app's]
The auth server does not serve `/ui/admin-enrolment`, which reads the token
from the URL's fragment. A deployment whose ceremony app does not serve that
page yet opens no page from the URL, and its account cannot sign in.
:::

## A realm with no second admin

Where a realm makes an operation a mandatory two-admin operation and no
other admin may approve, the operation fails closed
([Security operations](/reference/security-operations/)). The ways out are,
in order: another eligible admin approves; an admin that changed its own
credentials, identifier or contact address approves once 7 days have passed;
or the host's holder enrols a new admin with this command.

```console
tsx src/break-glass.ts enrol-admin --realm acme --role security-admin
```

The new admin approves only after [the 7-day wait](#the-7-day-wait). Until
then the operation still fails closed, so plan for a week. The command is not
a way to approve an operation: it creates an approver, which waits like any
new admin.

An emergency key retirement waits for nobody. It never needs an approver
from this command.

## Retire a key in an emergency

```console
tsx src/break-glass.ts retire-key --realm acme --kid <kid> --confirm
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
identifier or contact address waits 7 days from the change too, and
registering the first passkey is such a change: the wait runs from the
enrolment, which comes later than the run.

## What is recorded

Before a run changes anything, and in the transaction of the change, it
writes:

- **an admin audit row of the realm**, with the actor kind
  `break_glass_operator` and the operating-system user as its actor, the
  operation `breakGlass.enrolAdmin` or `breakGlass.retireKey`, the class
  `security`, and a diff whose `after` holds the run: the command, its
  arguments (a secret one masked; no option of the two commands is one), the
  operating-system user's name and uid, the process's audit login uid
  (`/proc/self/loginuid` on Linux, which `sudo` and `su` keep, or `null`),
  the user `sudo` reports it ran the command for (`SUDO_USER`, as the
  environment reports it, or `null`), and the host name. For
  `enrol-admin` it names the account, the role and the realm of the grant
  and the enrolment's expiry; for `retire-key` the kid and the digest of the
  retirement, which is the row's request digest too. The row's trace id is
  the run id each command prints first;
- **a critical `admin.break_glass_used` event**
  ([Events](/reference/events/#adminbreak_glass_used-v1-rc0)), naming the
  command, with the operating-system user as its `operator_cli` actor. It is
  an admin event of the realm's event store, in its admin chain, and every
  route that reads the store sends it: the event API, webhooks, and every
  SSF stream of the realm that requested
  `urn:qauth:secevent:break-glass-used:v1-rc.0`
  ([SSF events](/reference/ssf-events/)). OpenTelemetry export does not:
  a server node exports the events it writes itself, after their commit,
  and the CLI exports nothing, as it makes no outbound call. Watch the
  event API, a webhook or an SSF stream for it, not only an OpenTelemetry
  pipeline.

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
