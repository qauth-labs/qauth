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

## Enabling an account again

Enabling an account lets its holder sign in again. It does not bring back what
was issued before the account was disabled: every browser session, refresh
token, authorization code and access token from before stays refused, whether
or not anyone used it while the account was disabled. Whoever held one,
the account's owner or someone who took it, must sign in.

The account records the time it was last disabled, `users.not_valid_before`
(epoch milliseconds, from the database's clock). Disabling sets it; enabling
never clears it, and the database refuses an update that clears it or moves
it back. A session or token issued up to one second after that time counts
as issued before it, to allow for times kept to the second and for a small
skew between the auth server's clock and the database's. Nothing is issued
to a disabled account, so this only matters for an account enabled again
within a second.

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
user who ran the tool as the actor.

`UPDATE users SET enabled = false WHERE id = '<user id>'` by hand disables the
account just as well, and the database records the time the same way, but no
event is written. Use the tool.
