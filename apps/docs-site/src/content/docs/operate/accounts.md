---
title: Accounts
description: How to disable a user account and enable it again, and what disabling ends for good.
sidebar:
  order: 13
lastVerified: '2026-10-31'
---

An operator disables an account to stop whoever holds it, for example after
the account was taken over. The admin API has no user operations yet, so this
page uses the operator tool, which talks to the database directly.

## What disabling does

A disabled account cannot sign in and is issued no token. Everything it
already holds stops working at its next use:

- its browser sessions: the hosted pages send the browser to sign-in;
- its refresh tokens and authorization codes: `/oauth/token` answers
  `invalid_grant`;
- its access tokens: introspection reports them inactive, `/oauth/userinfo`
  answers `401`, and the developer API and token exchange refuse them.

The account keeps its credentials, consents and clients. Signing out still
works.

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
writes the event in one transaction, and prints the time before which sessions
and tokens stay refused. It changes nothing for an account that is already in
the state you ask for, or for a realm or a user it does not find, and says so.

| Event                                                                 | When                         |
| --------------------------------------------------------------------- | ---------------------------- |
| [`user.disabled`](/reference/events/#userdisabled-v1-rc0) (`warning`) | The tool disabled an account |
| [`user.enabled`](/reference/events/#userenabled-v1-rc0) (`info`)      | The tool enabled it again    |

Both are admin events, in the realm's hash chain, with the operating-system
user who ran the tool as the actor. The [SSF transmitter](/operate/ssf-transmitter/)
sends them as RISC 1.0 `account-disabled` and `account-enabled` to each stream
that requested them and has the user as a subject
([SSF events](/reference/ssf-events/)).

`UPDATE users SET enabled = false WHERE id = '<user id>'` by hand disables the
account just as well, and the database records the time the same way, but no
event is written. Use the tool.
