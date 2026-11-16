---
title: Account closing at a relying party
description: Let a relying party that closes accounts on its own side delete each one on its realm at once, as a service account with the account-closer grant, with no approval, every session ended with its back-channel logouts, and retries that answer as the first call.
sidebar:
  order: 17
lastVerified: '2026-11-16'
---

Some relying parties own account closing. The person closes the account at
the app, which knows what the account owns there, and the account on the
QAuth realm has to go with it, at once: the app has already told the person
it is gone. This page sets that up. The app deletes the account through the
admin API as a [service account](/operate/service-accounts/), with no human
approval, and keeps the account in a retry table until QAuth confirms the
deletion.

The deletion is the admin API's `users.delete`
([Delete an account](/operate/accounts/#delete-an-account)). It is a
security operation, which normally runs only after a human approves it. The
one exception is the grant this page is about, `account-closer`
([ADR-019](/reference/records/adr/019-deployment-topology-and-trust-boundaries/),
Decision 7, amended 2026-11-16).

## Keep account closing at the relying party

This release has no self-service account deletion: an account is deleted
only through the admin API, so it closes only where the relying party closes
it. Self-service deletion comes later, with a switch per realm
([ADR-020](/reference/records/adr/020-ui-surfaces-and-acceptance-criteria/) §3,
[#692](https://github.com/qauth-labs/qauth/issues/692)). Once it ships,
switch it off on a realm whose relying party owns account closing, so that a
person cannot delete the account behind the app's back.

## Create the service account with the grant

Create one service account for the relying party, on a host that holds the
database credentials, and give it `account-closer` on the realm its users
live in. In simple mode that is the default realm, which is also the operator
realm.

```console
pnpm nx run auth-server:service-accounts -- create \
  --name notes-account-closing \
  --client-id notes-account-closing \
  --jwks-uri https://notes.example.com/.well-known/jwks.json \
  --grant account-closer@customers
```

- `account-closer` holds one permission, `users.delete`, and nothing else
  ([Admin permissions](/reference/admin-permissions/#built-in-roles)). Give
  this service account no other role: its key then deletes accounts of one
  realm, and does nothing else.
- It is granted on one realm, named after `@`. The command refuses
  `account-closer@*`.
- The command makes the service account's client itself. A client that
  registered itself (dynamic client registration or a Client ID Metadata
  Document) never becomes a service account's, and a service account bound
  to one anyway runs every deletion with its approval.
- The command records the creation, with its grants and the operating-system
  user that ran it, in the operator realm's admin audit log
  (`serviceAccounts.create`).

The deletion runs with no approval only while all of these hold:

| Condition                                                                                             | Otherwise                                                     |
| ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| The caller is the service account, through its own client.                                            | A person who holds the role needs an approval for each one.   |
| It holds `account-closer` on exactly the realm the call acts on, not on every realm.                  | `403` `approval_required`, or `404` outside its grants.       |
| The realm does not list `users.delete` in its `admin.twoAdminMandatoryOperations` policy.             | `403` `approval_required`: the two-admin rule asks approvals. |
| The call names no approval in `QAuth-Approval`.                                                       | The call is judged by the approval it names.                  |
| The operation is `users.delete`. Every other security operation needs its approval, whoever calls it. | `403` `approval_required`.                                    |

## Get a token

The service account asks the token endpoint of the operator realm's issuer
for a `client_credentials` token with `private_key_jwt` and a DPoP proof, as
[Service accounts](/operate/service-accounts/#get-a-token) shows, with
`scope=qauth:admin:security` and the admin API's audience as `resource`. The
token lives at most 900 seconds; ask again when it expires.

## Delete the account

When the person confirms the closing, delete the account by the `sub` the
app received in its ID token. QAuth's subjects are public, so the `sub` is
the account's id in the realm:

```http
DELETE /admin/v1-rc.0/realms/<realm id>/users/<sub>
Authorization: DPoP <access token>
DPoP: <proof for this request>
If-Match: *
```

It answers `204` with no body. In one transaction, it:

- ends every session the account holds: each browser session, and each
  logout-only session a sign-up or a password reset left. Every client a
  session signed in to that has a back-channel logout URI, the app itself
  included, is sent one logout token per session
  ([OpenID Connect Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html)).
  The tokens are queued in the deletion's transaction and sent by the
  delivery role after the commit, so no session survives the deletion and no
  token is lost;
- deletes the account with its credentials, recovery codes, consents,
  attributes, upstream identities and refresh tokens. Its access tokens no
  longer introspect, and `/oauth/userinfo` refuses them. A resource server
  that verifies access tokens itself accepts one until it expires;
- records `user.session_revoked` for each session it ended, then
  `user.deleted`, both naming the service account's client as the actor, and
  the call's audit row, which names the service account (`service_account`)
  and lists no approval.

The browser that held the account's session meets the sign-in step at its
next authorization request: no app signs it in again without a prompt.

## Retry until QAuth confirms

Keep the `sub` in the retry table until the deletion answers `204`. The
deletion is idempotent by id: a `sub` the realm does not hold, whether it
was deleted already, is unknown, or is another realm's account, answers
`204` too, changes nothing and records no event; its audit row records the
call with no change. So a retry of a deletion that went through answers as
the first call did.

- Send `If-Match: *` on every attempt. A call that names the account's
  `ETag` answers `412` once the account is gone.
- A deadlock with a code exchange or a refresh of the same account in
  flight fails the call and changes nothing; its retry deletes the account.

| Answer                             | What it means                                                                                                    | Retry?                    |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------------------- | ------------------------- |
| `204`                              | The account is deleted, or the realm holds none with this id.                                                    | No: drop it from the list |
| `401`                              | The token expired, or the service account was disabled.                                                          | With a new token          |
| `429`, `5xx`, a network error      | The call may not have run.                                                                                       | Yes, with `If-Match: *`   |
| `403` `approval_required`          | The service account holds no `account-closer` on this realm, or the realm makes a second admin mandatory for it. | Not until that changes    |
| `403` `forbidden`                  | The token lacks `qauth:admin:security`, or the service account's role lacks `users.delete`.                      | Not until that changes    |
| `404` `not_found`                  | The realm is outside the service account's grants.                                                               | No                        |
| `409` `conflict`                   | The account is a service account's, or holds an admin grant: those are removed through their own paths.          | No                        |
| `409` `approval_unavailable`       | The realm makes a second admin mandatory for it, and has too few admins who could approve.                       | Not until that changes    |
| `412` `precondition_failed`, `428` | `If-Match` named another version, or none.                                                                       | With `If-Match: *`        |

## Take the grant away

- Disable the service account: it gets no token, and a token it holds makes
  no admin call from the next request on.

  ```console
  pnpm nx run auth-server:service-accounts -- disable --name notes-account-closing
  ```

  The command has no way yet to remove one grant: to keep the relying party
  deleting with approvals, create a new service account without
  `account-closer` and disable this one.

- Or have the realm's admins add `users.delete` to the realm's
  `admin.twoAdminMandatoryOperations`. One admin can always add an operation
  to the list; from the next call on, every deletion needs a second admin's
  approval, and the relying party's calls answer `403` `approval_required`.
  Removing it again takes two admins.

## What the logs show

- The audit row of each deletion: operation `users.delete`, actor kind
  `service_account` with the service account's user id, no approvals, and the
  deleted account's id, creation time and credential ids and types, never an
  address.
- The admin events `user.session_revoked` and `user.deleted`, actor type
  `client` and the service account's `client_id`. Shared Signals receivers
  get them as CAEP `session-revoked` and RISC `account-purged`
  ([SSF transmitter](/operate/ssf-transmitter/)).
- One `user.client_session_ended` per ended session and client with a
  back-channel logout URI: the outbox the logout tokens are sent from.

## See also

- [Service accounts](/operate/service-accounts/) — create one, get a token,
  disable it.
- [Accounts](/operate/accounts/#delete-an-account) — what a deletion removes
  and refuses.
- [Security operations](/reference/security-operations/#unattended-account-deletion)
  — the unattended deletion and the two-admin rule.
