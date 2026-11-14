---
title: Account API from a backend
description: How a backend for frontend, such as the account console's, calls the account API — the token it holds, the fresh-authentication challenge it answers, and the refusals it must not retry.
sidebar:
  order: 8
lastVerified: '2026-11-14'
---

The [account API](/reference/account-api/) is called by backends that hold a person's access
token: the account console's backend, or any backend for frontend (BFF) that lets a person manage
their own account. This page is for the people who write one. The contract lists every operation;
this page explains the one guard every call passes, and what a BFF does with each answer.

## The token

Ask for the token with the [authorization code flow and PKCE](/integrate/oauth-flow/), naming the
account API as the RFC 8707 resource:

```http
GET /oauth/authorize?response_type=code&client_id=account-console
    &redirect_uri=https%3A%2F%2Faccount.example.com%2Fcallback
    &scope=openid%20qauth%3Aaccount%3Aread%20qauth%3Aaccount%3Awrite
    &resource=urn%3Aqauth%3Aaud%3Aaccount%3Av1-rc.0
    &code_challenge=…&code_challenge_method=S256&state=…
```

- The client must list `urn:qauth:aud:account:v1-rc.0` in its `audience`. A client that does not
  gets `invalid_target`; an operator provisions the console's client with it.
- The token needs the account scope of each operation's `x-qauth-class`: `qauth:account:read` to
  read, `qauth:account:write` to change anything. Ask for both when the BFF does both; the write
  scope does not reach a read. The client must hold them in its `scopes`, which only an operator
  writes, and the token endpoint issues them only to a client that lists the account audience. A
  call without the scope it needs gets 403 `forbidden` with
  `WWW-Authenticate: Bearer realm="OAuth", error="insufficient_scope", scope="qauth:account:write"`,
  before any rule below: a new sign-in does not help, a token with the scope does.
- The token's only audience is the account API. Keep it on the server side, as every BFF keeps its
  tokens; no cookie authenticates a call.
- It carries how the person signed in: `auth_time` (when) and `amr` (with what: `pwd`, `pop` for a
  passkey, `otp` for an authenticator app, `mfa` for two kinds). A token from the code exchange
  also names the browser session it came from, in `sid`. A token from a refresh does not: its
  family records no session.

## Fresh authentication

An operation whose `x-qauth-fresh-authentication` is not `none` changes a credential, an
identifier, the contact address or a linked account, or deletes the account. It needs a sign-in at
most 300 seconds old whose `amr` holds the account's strongest bound factor: `pop` when the
account has a passkey, else `otp` when it has an authenticator app, else `pwd`. A disabled factor
still counts.

When the token does not meet that, the call is refused before anything changes, with the step-up
challenge of [RFC 9470](https://www.rfc-editor.org/rfc/rfc9470.html) §3:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="insufficient_user_authentication", max_age="300"
Content-Type: application/problem+json

{"type":"https://docs.qauth.dev/reference/problem-types/#insufficient-user-authentication","title":"Insufficient user authentication","status":401,"code":"insufficient_user_authentication","trace_id":"…","max_age":300}
```

- `max_age="300"`: the sign-in is too old, or the token says nothing of when it happened, or it
  dates the sign-in more than a minute ahead of the server's clock.
- `max_age="0"`: the sign-in is recent but lacks the strongest factor. The person signs in again
  now.
- A DPoP-bound token gets the same challenge under the `DPoP` scheme, with the proof algorithms in
  `algs`.

To answer it, send the person to `/oauth/authorize` with the same request and `max_age` set to the
challenge's value, exchange the new code, and repeat the call with the new token. The sign-in that
follows ends with the account's strongest bound factor, since a sign-in completes only once it has
proved it. Read `max_age` from the problem document or the header; both carry the same value.

## After a lost factor

A person who lost their passkey or authenticator app signs in with a recovery code in its place. A
recovery code adds no `amr` value, so such a sign-in never meets the rule above. It counts only for
the two halves of a rebind, the operations whose `x-qauth-fresh-authentication` is
`strongest-factor-or-recovery-code`: removing a passkey or the authenticator app
(`account.passkeys.delete`, `account.totp.delete`) and binding a new authenticator app
(`account.totp.enrollment.create`, `account.totp.enrollment.confirm`). Every other operation
answers the challenge with `max_age="0"`.

The guard finds the recovery code through the token's `sid`: the browser session records that its
sign-in took one. So make the rebind calls with the token of that sign-in's code exchange, within
the five minutes; a refreshed token names no session and gets the challenge.

## Adding a passkey

A passkey belongs to the realm's host (its WebAuthn relying party ID), so a BFF on another host
cannot create one, and the account API has no operation that does. Send the person to the
authorization endpoint instead, with `qauth_action=setup_passkey` (ADR-020 §1):

```http
GET /oauth/authorize?response_type=code&client_id=account-console
    &redirect_uri=https%3A%2F%2Faccount.example.com%2Fpasskeys%2Fadded
    &scope=openid%20qauth%3Aaccount%3Aread%20qauth%3Aaccount%3Awrite
    &resource=urn%3Aqauth%3Aaud%3Aaccount%3Av1-rc.0
    &qauth_action=setup_passkey
    &code_challenge=…&code_challenge_method=S256&state=…
```

- Only a client whose `audience` lists `urn:qauth:aud:account:v1-rc.0` may ask: any other gets
  `unauthorized_client` at its redirect URI. The server must run the hosted pages
  (`INTERACTION_UI_ENABLED`) with passkeys on (`WEBAUTHN_ENABLED`); otherwise the request gets
  `invalid_request`, as it does beside `prompt=create` or `qauth_link`. Under `prompt=none` it gets
  `login_required`.
- The person signs in again, with the account's strongest factor, whatever session the browser
  has. Then the hosted pages ask for a passkey, which the browser creates on the realm's origin,
  and show the first recovery codes when the passkey is the account's first factor beyond its
  password. The consent follows if one is owed, then the code comes back to your redirect URI.
- The person may decline the passkey, and an account whose address was never verified binds none,
  so a code does not mean a passkey was added. Exchange it, then read
  `GET /account/v1-rc.0/passkeys` with the new token and compare the list with the one you had.
- The person may sign in to another account than the one your console shows: the set-up binds the
  passkey to whichever account signed in. Check that the new token's `sub` (and the ID token's) is
  the user you started the set-up for before you use the token; otherwise discard it and start
  over (a `login_hint` with that user's address pre-fills the sign-in, but does not bind it).
- The new token comes from a sign-in that just happened, so it also meets the fresh-authentication
  rule above for the next five minutes. A passkey added after a sign-in that proved only the
  password is new for the realm's window (ADR-017 Decision 8): until the window ends, a fresh
  sign-in with the password alone may remove it.

Renaming a passkey (`account.passkeys.update`, a JSON Merge Patch with `If-Match`) needs no fresh
sign-in, since a name is no credential, but refuses an act-chain token. Removing one
(`account.passkeys.delete`) needs a fresh sign-in with the strongest factor or a recovery code, and
answers 409 `last_credential` for the account's last way to sign in and 409
`second_factor_required` for the last second factor the realm requires of the account.

## Adding an authenticator app

An authenticator app needs no browser ceremony on the realm's host, so the account API binds one
itself, in two calls with a fresh token (the strongest factor, or a recovery code in place of a
lost one):

1. `POST /account/v1-rc.0/totp/enrollment` draws a new secret and answers it once, `201`, as
   `secret` (base32, for typing by hand) and `otpauthUri` (for the QR code), with `expiresAt`, ten
   minutes ahead. Show both to the person and keep neither: QAuth keeps only a ciphertext of the
   secret until the enrolment is confirmed or lapses, never sends it again, and answers it with
   `Cache-Control: no-store`. A new start replaces an enrolment not yet confirmed. `emailCode` is
   always `not_required`: no code is mailed, since a verified account binds its first second factor
   after the fresh sign-in alone (ADR-017 Decision 8).
2. `POST /account/v1-rc.0/totp/enrollment/confirm` with `{"code":"492039"}`, the first code the
   app shows, binds the secret: `200` with `enabledAt`. A wrong code is `400` `invalid_code` and
   binds nothing; the enrolment waits for another code. Without a started enrolment, after it
   lapsed or once it was confirmed, the answer is `404` `not_found`.

- The start answers `409` `conflict` when the account already has an authenticator app (remove it
  first, the first half of a rebind), when its address was never verified (an unclaimed account
  binds no factor), and when it has no address the app could show beside the code.
- When the app is the account's first second factor, the confirmation also answers
  `recoveryCodes`: the account's first set of ten codes, shown once. QAuth marks the set as saved
  as it answers it, so show the codes then; a later sign-in does not show them again.
- An app bound with a token whose sign-in proved only the password is new for the realm's window
  (ADR-017 Decision 8), and the browser session that sign-in started names it: until the window
  ends, a fresh sign-in with the password alone may remove it (`DELETE /account/v1-rc.0/totp`),
  which ends that session.
- Removing the app needs the same fresh sign-in as the start, and answers `409`
  `second_factor_required` for the last second factor the realm requires of the account.

`GET /account/v1-rc.0/recovery-codes` reads how many recovery codes are left and when the set was
issued, never the codes; it takes an act-chain token. `POST /account/v1-rc.0/recovery-codes/regenerate`
answers a new set of ten once and stops every code of the old one. It needs a fresh sign-in with the
strongest factor itself (a recovery code does not do), and answers `409` `conflict` for an account
with no second factor or passkey.

## Refusals a step-up cannot lift

- **403 `delegated_token_refused`**: the token is an act-chain token (RFC 8693 `act`), held by an
  admin or an agent acting for the person. Every operation that changes a credential, an
  identifier, the contact address or a linked account refuses one, and so do deleting the account
  and reporting a sign-in as not the person's (`x-qauth-act-chain: refused`). The refusal comes
  before any fresh-authentication check, and no sign-in lifts it: only the person, with their own
  token, may make the change.
- **503 `service_unavailable`** with `Retry-After`: the guard could not read what it decides on,
  the account's factors or the session. Nothing changed; try again after the given seconds.

Every refusal is recorded as a
[`request.account_operation_refused`](/reference/events/#requestaccount_operation_refused-v1-rc0) event,
with the operation, the reason, the factor the sign-in needed and the challenge's `max_age`. The
security log a person reads leaves it out: a refused change changes nothing on the account.
