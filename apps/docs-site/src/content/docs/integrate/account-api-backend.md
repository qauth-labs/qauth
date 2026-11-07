---
title: Account API from a backend
description: How a backend for frontend, such as the account console's, calls the account API — the token it holds, the fresh-authentication challenge it answers, and the refusals it must not retry.
sidebar:
  order: 8
lastVerified: '2026-11-07'
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
    &scope=openid&resource=urn%3Aqauth%3Aaud%3Aaccount%3Av1-rc.0
    &code_challenge=…&code_challenge_method=S256&state=…
```

- The client must list `urn:qauth:aud:account:v1-rc.0` in its `audience`. A client that does not
  gets `invalid_target`; an operator provisions the console's client with it.
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
