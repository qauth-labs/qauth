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
the account's owner or someone who took it, must sign in. A refresh token
counts from the sign-in that started its family, so a rotation does not make
it newer, and an authorization code from the sign-in behind it. An access
token from before cannot sign the owner out of the sessions started since.

The account records the time it was last disabled, `users.not_valid_before`
(epoch milliseconds, from the database's clock). Disabling sets it to the
time the disabling transaction commits: until then the account still reads as
enabled, and what it is issued meanwhile counts as issued before. Enabling
never clears it, and the database refuses an update that clears it or moves
it back. A session or token issued up to one second after that time counts
as issued before it, and an access token, whose issue time is kept to the
whole second, up to two seconds after. The margin allows for times kept to
the second and for a skew between the auth server's clock and the database's
of less than a second: keep both synchronised, for example with NTP. Nothing
is issued to a disabled account, so the margin only matters for an account
enabled again within those seconds.

### Accounts disabled before the upgrade

Migration 0044 adds the column. An account that is disabled when it runs was
disabled at a time nothing recorded, so it gets the time of the migration:
nothing is issued to a disabled account, so everything it holds is older, and
stays refused once the account is enabled.

During a rolling upgrade, a node of the previous release still checks only
whether the account is enabled. Once the account is enabled again, such a node
accepts its old browser sessions and access tokens, and may rotate its old
refresh tokens and mint codes from its old sessions. Nodes of this release
refuse those rotated tokens and codes, because they count from the sign-in
behind them, but an access token such a node mints works at them until it
expires. Enable an account that was disabled for a takeover only after every
node runs this release.

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
