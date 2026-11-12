---
title: Accounts
description: How to disable a user account and enable it again, what disabling ends at once and for good, what suspending a client or disabling a realm ends, and how an operator verifies an account that cannot confirm its address.
sidebar:
  order: 13
lastVerified: '2026-11-12'
---

An operator disables an account to stop whoever holds it, for example after
the account was taken over. The admin API has no operation for that yet, so
this page uses the operator tool, which talks to the database directly. An
operator also verifies an account that cannot confirm its address
([Verify an account](#verify-an-account)): through the admin API, or on the
server host where no admin API is set up.

## What disabling does

A disabled account cannot sign in and is issued no token. Everything it
already holds stops working at its next use:

- its browser sessions: the hosted pages send the browser to sign-in;
- its refresh tokens and authorization codes: `/oauth/token` answers
  `invalid_grant`;
- its access tokens: introspection reports them inactive, `/oauth/userinfo`
  answers `401`, and the developer API and token exchange refuse them.

The tool ([Disable or enable an account](#disable-or-enable-an-account))
also ends what the account holds at once, in the transaction that disables
it, rather than at its next use:

- every live browser session of the account ends. Each is recorded as a
  `user.session_revoked` event, which the
  [SSF transmitter](/operate/ssf-transmitter/) sends as a CAEP
  `session-revoked` naming the session. Each client a session signed in to
  that registered a back-channel logout URI is sent a logout token;
- every live refresh token of the account is revoked, as `account_disabled`;
- every authorization code of the account not yet redeemed is spent.

An access token cannot be recalled: QAuth keeps no record of it. QAuth's own
endpoints refuse it, as above. A resource server that verifies access tokens
itself, without introspection, accepts one until it expires (15 minutes by
default), unless it acts on the account's signals: `account-disabled` and the
`session-revoked` of each session.

The account keeps its credentials, consents and clients. Signing out still
works.

The rule that refuses what the account held at its next use stays the
authority: it also refuses what is issued while the disabling transaction is
still open, which that transaction does not see, and what an account disabled
by hand holds. An `UPDATE` by hand ends nothing at once and records nothing,
so no receiver hears of it ([Disable or enable an account](#disable-or-enable-an-account)).

## After a takeover

Disabling ends what the account holds, not what whoever took it changed or
added. Enabling the account gives that back with it. Before you enable an
account that was taken over:

1. Find what the account did since the takeover. Its events name it, such as
   `wallet.linked`, `client.created`, `client.secret_rotated` and
   `api_key.created` ([Events](/reference/events/)):

   ```sql
   SELECT to_timestamp(time / 1000.0) AS at, type, subject_type, subject_id, client_id
   FROM events
   WHERE actor_id = '<user id>' AND time >= <takeover time, epoch ms>
   ORDER BY time;
   ```

2. Replace the password. QAuth has no password reset yet
   ([#642](https://github.com/qauth-labs/qauth/issues/642)): an account taken
   over with its password signs in with it again once it is enabled, so keep
   such an account disabled until its password can be replaced.
3. Remove every credential added since the takeover, such as a linked wallet.
   List the account's credentials and delete those you did not expect:

   ```sql
   SELECT id, provider_type, to_timestamp(created_at / 1000.0) AS added
   FROM user_credentials
   WHERE user_id = '<user id>'
   ORDER BY created_at;

   DELETE FROM user_credentials WHERE id = '<credential id>';
   ```

4. Suspend every client the account created since the takeover, and every
   client whose secret it rotated or to which it added an API key. A client
   lives on while its developer is disabled, and its secret and keys with it:

   ```sql
   SELECT c.client_id, to_timestamp(c.created_at / 1000.0) AS created
   FROM oauth_clients c
   WHERE c.developer_id = '<user id>'
   ORDER BY c.created_at;

   SELECT c.client_id, k.name, to_timestamp(k.created_at / 1000.0) AS created
   FROM api_keys k
   JOIN oauth_clients c ON c.id = k.client_id
   WHERE k.developer_id = '<user id>' AND k.revoked_at IS NULL
   ORDER BY k.created_at;
   ```

   ```bash
   DATABASE_URL=postgresql://qauth:pw@db:5432/qauth \
     pnpm nx run infra-db:db:suspend-oauth-client -- --realm=<realm name> --client-id=<client_id>
   ```

   Once the owner has signed in again, they rotate the secret
   (`POST /api/clients/:id/regenerate-secret`) and revoke the keys
   (`DELETE /api/clients/:clientId/api-keys/:keyId`) through the developer
   API, or delete a client they did not create. Then lift the suspension of
   the clients they keep, with `--lift`.

## Enabling an account again

Enabling an account lets its holder sign in again. It does not bring back what
was issued before the account was disabled: every browser session, refresh
token, authorization code and access token from before stays refused, whether
or not anyone used it while the account was disabled. Whoever held one,
the account's owner or someone who took it, must sign in. A refresh token
counts from the start of its family, the code exchange or sign-in that issued
its first token, so a rotation does not make it newer; an authorization code
counts from the sign-in behind it. An access token from before cannot sign the
owner out of the sessions started since.

The account records the time it was last disabled, `users.not_valid_before`
(epoch milliseconds, from the database's clock). Disabling sets it to the
time the disabling transaction commits: until then the account still reads as
enabled, and what it is issued meanwhile counts as issued before. The time is
taken just before the commit, so a commit that then waits, for a synchronous
standby for example, leaves the account readable as enabled a little longer
than the time says. Enabling
never clears it, and the database refuses an update that clears it or moves
it back. A session or token issued up to one second after that time counts
as issued before it, and an access token, whose issue time is kept to the
whole second, up to two seconds after. The margin allows for times kept to
the second and for a skew between the auth server's clock and the database's
of less than a second. Nothing is issued to a disabled account, so the margin
only matters for an account enabled again within those seconds.

Keep every auth server node's clock and the database's synchronised, for
example with NTP. A browser session's issue time is the node's clock, and the
disablement's time the database's: on a node whose clock runs more than a
second ahead of the database, a session issued just before the disablement
counts as issued after it, and survives the account being enabled again.

An ID-JAG assertion (the `jwt-bearer` grant) carries the issue time of the
identity provider that signed it, whose clock may run up to
`ID_JAG_CLOCK_SKEW_LEEWAY` (60 seconds by default) ahead of QAuth's, as its
validation allows. It counts as issued that much before its `iat`: an
assertion issued within that leeway after the disablement is refused too.

The margin bounds what slips through. A sign-in or a code exchange takes the
issue time of the session or the refresh family it starts before it reads
the account, so one whose read came before the disabling commit counts as
issued before it. An access token is signed after that read: one whose request
read the account as enabled before the commit, and was signed more than two
seconds after the time, survives the account being enabled again, until it
expires. A commit that waits more than a second for a synchronous standby
has the same effect on what is issued meanwhile. A database superuser or the
owner of the `users` table can turn the triggers off; QAuth does not guard
against them.

### Accounts from before the upgrade

Migration 0044 adds the column. An account that is disabled when it runs was
disabled at a time nothing recorded, so it gets the time of the migration:
nothing is issued to a disabled account, so everything it holds is older, and
stays refused once the account is enabled.

An account that was disabled and enabled again before the upgrade gets no
time: the migration finds it enabled, and nothing recorded that it was ever
disabled. The previous release brought back every browser session and refresh
token that nobody used while it was disabled, and they keep working after the
upgrade. For each account you enabled again after a takeover before
upgrading, once every node runs this release, disable the account with the
tool (`db:disable-user`), take the steps of [After a takeover](#after-a-takeover),
and enable it again (`db:disable-user --enable`). Disabling records the time
now and ends every session and token the account holds: whoever holds one,
its owner included, signs in again.

During a rolling upgrade, a node of the previous release still checks only
whether the account is enabled. Once the account is enabled again, such a node
accepts the account's old browser sessions and access tokens. Nodes of this
release refuse the refresh tokens it rotates from an old family and the codes
it mints from an old session. But from an old session it can also run a whole
code exchange, and the new refresh family that starts works at every node
until it ends, as does any access token such a node mints until it expires.
Enable an account that was disabled for a takeover only after every node runs
this release.

## Disable or enable an account

Find the user's id. For a password account, by the address it signs in with:

```sql
SELECT c.user_id
FROM user_credentials c
JOIN realms r ON r.id = c.realm_id
WHERE r.name = '<realm name>'
  AND c.provider_type = 'password'
  AND c.external_sub = lower('<address>');
```

From a checkout of the release you run, with dependencies installed, on a host
that holds the database credentials:

```bash
DATABASE_URL=postgresql://qauth:pw@db:5432/qauth \
  pnpm nx run infra-db:db:disable-user -- --realm=<realm name> --user-id=<user id>
```

Add `--enable` to enable the account again. The tool changes the account and
writes the event in one transaction; a disablement ends in it what the account
holds ([What disabling does](#what-disabling-does)). It prints how many
browser sessions it ended, and the time before which sessions and tokens stay
refused. It changes nothing for an account that is already in the state you
ask for, or for a realm or a user it does not find, and says so. Enabling
ends nothing.

| Event                                                                            | When                                                       |
| -------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| [`user.disabled`](/reference/events/#userdisabled-v1-rc0) (`warning`)            | The tool disabled an account                               |
| [`user.session_revoked`](/reference/events/#usersession_revoked-v1-rc0) (`info`) | The disablement ended one of its sessions, one per session |
| [`user.enabled`](/reference/events/#userenabled-v1-rc0) (`info`)                 | The tool enabled it again                                  |

All three are admin events, in the realm's hash chain, with the
operating-system user who ran the tool as the actor. The
[SSF transmitter](/operate/ssf-transmitter/) sends them as RISC 1.0
`account-disabled`, CAEP 1.0 `session-revoked` (naming the session) and RISC
1.0 `account-enabled` to each stream that requested them and has the user as
a subject ([SSF events](/reference/ssf-events/)). Each client sent a logout
token for an ended session has its own `user.client_session_ended`.

`UPDATE users SET enabled = false WHERE id = '<user id>'` by hand disables the
account just as well, and the database records the time the same way, so
everything the account holds is refused at its next use. But it ends nothing
at once, no event is written and no signal is sent: a receiver acting on
signals does not hear of it, and the account's refresh tokens stay unrevoked
rows until they expire. Use the tool.

## Clients and realms

An operator also switches off a client or a whole realm. Whether what it held
comes back when it is switched on again differs:

- **A suspended client** (`db:suspend-oauth-client`, or `clients.disable` of
  the admin API, [Clients](/operate/clients/#suspend-enable-and-delete)) is
  cut off for good, as a disabled account is. The suspension revokes, in its
  own transaction, every refresh token the client holds (as
  `client_suspended`) and spends its authorization codes not yet redeemed.
  Lifting the suspension brings none of them back: the client's users sign in
  through it again. Its access tokens are not recalled; they work until they
  expire, during the suspension too. A suspension sends no Shared Signals
  event: neither CAEP 1.0 nor RISC 1.0 has one for a client. A suspension by
  hand (`UPDATE oauth_clients SET suspended = true …`) revokes nothing, so
  lifting it brings the client's refresh tokens back. Use the tool or the
  admin API.
- **A disabled realm** (`UPDATE realms SET enabled = false …`; no tool or API
  disables one) is paused, not cut off. While it is off, every request to its
  hosts is refused with `421`, so nothing of it is used. Enabling it again
  brings back every browser session and token of the realm that has not
  expired meanwhile, and no signal is sent either way. To end what the
  realm's accounts hold, disable them with the tool, as above.

## Verify an account

A realm that requires verified accounts (`accounts.requireVerifiedAccount`)
signs a password account in only once its address is confirmed, by the code
mailed to it. A deployment that cannot send mail, or an account whose mailbox
is gone, has another way: an operator verifies the account
([ADR-015](/reference/records/adr/015-agent-tree-hardening/), Decision 8, as
amended 2026-11-08). The verification:

- counts wherever QAuth asks for a verified account: signing in where the
  realm requires one, and owning an agent;
- claims the account if it is unclaimed: it is the operator's attestation, so
  another person's later mailbox proof of the address no longer ends the
  account;
- leaves `email_verified` as it is. The address stays unconfirmed, and QAuth
  asserts no address it did not confirm;
- does not open a password reset by mail while the address stays
  unconfirmed: the operator attested the account, not the address, so the
  mailbox's holder need not be the person verified. A reset code for it is
  answered as a wrong one;
- is recorded on the account with the operator who made it, and kept: an
  account an operator verified is not verified again;
- is refused for a disabled account, and for an account the realm does not
  hold (a deleted one).

### Through the admin API

`users.verify` is a security operation: it needs the permission
`users.security`, so a token with `qauth:admin:security`, and an approval
([security operations](/reference/security-operations/)). File the approval
with the account in `params` and an empty body. The approver sees the
account, its credentials with the proof each holds, and the reason you give:

```http
POST /admin/v1-rc.0/realms/<realm id>/approvals
Content-Type: application/json

{ "operation": "users.verify", "params": { "userId": "<user id>" }, "body": {},
  "reason": "No mail transport; the owner confirmed by phone." }
```

Once it is approved, send the verification with the approval:

```http
POST /admin/v1-rc.0/realms/<realm id>/users/<user id>/verification
Content-Type: application/json
If-Match: *
QAuth-Approval: <approval id>

{}
```

It answers the verification, with you as `verifiedBy`. The approval holds
only for the account as it stood when the approval was filed: when a
credential is added, removed or proved in between, it no longer matches, and
you file a new one. A disabled account, and one an operator already verified,
are refused with `409`.

### On the server host

A deployment with no admin API set up yet (no admin listener, or no admin
with a passkey to approve with) runs the migration runner's `verify-account`
command, on a host that holds the database credentials, as it runs the
[migrations](/operate/upgrades/):

```bash
docker compose run --rm migration-runner verify-account --realm <realm name> --user <user id>
```

The command runs only on a database whose migrations are all applied. It
records the verification and its event in one transaction, with the
operating-system user that ran it as the operator, and prints what it did.

| Exit | Meaning                                                                             |
| ---- | ----------------------------------------------------------------------------------- |
| `0`  | The account is verified now, or an operator verified it before (that is kept)       |
| `1`  | Migrations are pending: run the migration runner first. Nothing was changed         |
| `2`  | The arguments are wrong, or `DATABASE_URL` is not set                               |
| `3`  | The command could not run: the database unreachable, or the migrations unreadable   |
| `6`  | The realm holds no such account, there is no such realm, or the account is disabled |

| Event                                                                 | When                            |
| --------------------------------------------------------------------- | ------------------------------- |
| [`user.verified`](/reference/events/#userverified-v1-rc0) (`warning`) | An operator verified an account |

It is an admin event, in the realm's hash chain. Its `method` is `operator`
for `users.verify`, with the admin as its actor, and `operator_cli` for the
command, with the operating-system user as its actor.

During a rolling upgrade from 0.2, a node of 0.2 does not read the
verification: it still asks the account for its mailbox code. Verify accounts
once every node runs this release.
