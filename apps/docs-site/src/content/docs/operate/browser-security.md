---
title: Browser Security Model
description: The session cookie, CSRF protection, and response security headers behind QAuth's /ui/* login and consent flow.
sidebar:
  order: 4
lastVerified: '2026-07-27'
---

QAuth's interactive sign-in and consent screens live under `/ui/*` and are
protected by a session cookie, a CSRF token, and a strict set of response
headers. This document describes the contract for anyone integrating with or
operating those endpoints. The machine-to-machine OAuth/OIDC endpoints under
`/oauth/*` and `/auth/*` are JSON/bearer APIs and are **not** affected by the
cookie/CSRF mechanics below.

## Session cookie

| Attribute  | Value                                           |
| ---------- | ----------------------------------------------- |
| Name       | `__Host-qauth_session`                          |
| `HttpOnly` | always                                          |
| `SameSite` | `Lax`                                           |
| `Secure`   | on by default; gated by `SESSION_COOKIE_SECURE` |
| `Path`     | `/`                                             |
| `Domain`   | none (forbidden by the `__Host-` prefix)        |

- The cookie carries only a signed session id (`<sessionId>.<HMAC-SHA256>`).
  The authenticated user is bound to the id server-side in Redis, so logout /
  revocation is a single key delete.
- The `__Host-` prefix is browser-enforced: the cookie is rejected unless it is
  `Secure`, `Path=/`, and has no `Domain`. This isolates it from sibling
  subdomains.
- `Secure` is **on by default**. Set `SESSION_COOKIE_SECURE=false` **only** for
  local plain-HTTP development. In production it must stay on (the `__Host-`
  prefix requires it).

## CSRF protection

Four cookie-authenticated, state-changing browser endpoints ship today, and
**every one of them is CSRF-protected**. They do not all use the same mechanism,
so check the column before integrating:

| Endpoint                | Token travels as                  | Mechanism                                                                   |
| ----------------------- | --------------------------------- | --------------------------------------------------------------------------- |
| `POST /ui/consent`      | `csrf_token` form field           | Session-bound double-submit; token stored in the server-side session.       |
| `POST /ui/login`        | `csrf_token` form field           | Signed `__Host-qauth_login_csrf` double-submit cookie (pre-authentication). |
| `POST /ui/wallet-link`  | `csrf_token` form field           | Session cookie + the same signed login-CSRF cookie.                         |
| `DELETE /consents/{id}` | `X-CSRF-Token` **request header** | Per-session `apiCsrfToken`, echoed from `GET /consents/`.                   |

`POST /auth/link/wallet` is a JSON API on the same session cookie and also
requires the `X-CSRF-Token` header; it is registered only when
`WALLET_FEDERATION_ENABLED` is on.

### `POST /ui/consent` — session-bound double-submit

1. `GET /ui/consent` renders a hidden `<input name="csrf_token">`. The same
   value is stored in the server-side session.
2. `POST /ui/consent` must submit that `csrf_token`. The server compares the
   submitted value against the session copy with a timing-safe comparison
   (`csrfTokensEqual`). A mismatch → `400 invalid_csrf_token` and an audit log
   entry (`oauth.consent.csrf_failure`).
3. The token is **burned** on a successful POST and re-minted on the next
   `GET /ui/consent`, so a captured form cannot be replayed. The token is **not**
   rotated on every GET, so opening the consent page in multiple tabs does not
   invalidate earlier tabs.

Clients embedding the consent flow must round-trip the `csrf_token` field
verbatim from the rendered form; do not generate it client-side.

### `POST /ui/login` — pre-authentication double-submit cookie

Login runs **before** any authenticated session exists, so it cannot use the
session-bound token above. It uses a signed double-submit cookie instead:

1. `GET /ui/login` mints a token, sets it as `__Host-qauth_login_csrf`
   (`HttpOnly`, `SameSite=Lax`, `Path=/`, signed with an HMAC), and renders the
   same value as a hidden `<input name="csrf_token">`.
2. `POST /ui/login` **requires** `csrf_token` in the body — it is a required
   field of the route schema, not an optional hardening extra. A missing or
   mismatched value is rejected and audited as `ui.login.csrf_failure`.

A client that posts credentials without `csrf_token` will be refused. Round-trip
the hidden field verbatim from the rendered form.

### Why the remaining endpoints do not carry a CSRF token

`/auth/login`, `/auth/logout`, `/auth/register`, `/auth/resend-verification`,
and all `/oauth/*` endpoints authenticate with a **bearer token or client
credentials**, not the browser session cookie. They carry no ambient-authority
cookie, so CSRF does not apply.

## Response security headers (issue #113)

`@fastify/helmet` applies the following to every response:

- **Content-Security-Policy** (strict, nonce-based):
  `default-src 'self'`, `script-src 'self'`, `style-src 'self' 'nonce-…'`,
  `img-src 'self' data:`, `font-src 'self' data:`, `connect-src 'self'`,
  `form-action 'self'`, `object-src 'none'`, `frame-ancestors 'none'`,
  `base-uri 'self'`. A fresh per-request nonce authorises the inline `<style>`
  on the login/consent pages; there is **no** `'unsafe-inline'` for scripts, so
  an injected `<script>` is refused by the browser.
- **Strict-Transport-Security**: `max-age=31536000; includeSubDomains; preload`
  (one year, preload-eligible). Gated by `SECURITY_HSTS_ENABLED` /
  `SECURITY_HSTS_MAX_AGE`; keep enabled in production behind TLS.
- **X-Frame-Options**: `DENY` — clickjacking protection.
- **X-Content-Type-Options**: `nosniff`.
- **Referrer-Policy**: `no-referrer`.

### Swagger UI exception

The strict CSP would break Swagger UI (it bundles inline scripts/styles), so the
`/docs` prefix is served a relaxed CSP that permits `'unsafe-inline'` for its
own scripts and styles.

There is a **second** relaxation, and operators should know about it: the
consent screen serves a development CSP (`style-src 'self' 'unsafe-inline'`)
whenever the resolved environment policy has `t3SecurityEnforced` false — i.e.
for a client on the `development` profile. Scripts stay `'self'` in that policy;
only inline styles are permitted. Every other route, and every client on
`staging` or `production`, keeps the strict policy.

## Related configuration

| Env var                 | Default    | Purpose                              |
| ----------------------- | ---------- | ------------------------------------ |
| `SESSION_COOKIE_SECURE` | `true`     | `Secure` flag on the session cookie. |
| `SESSION_COOKIE_TTL`    | `86400`    | Session lifetime (seconds).          |
| `SECURITY_HSTS_ENABLED` | `true`     | Emit the HSTS header.                |
| `SECURITY_HSTS_MAX_AGE` | `31536000` | HSTS `max-age` (seconds).            |

## See also

- [Environment-Aware Authorization](/operate/environment-authorization/) — the `t3SecurityEnforced` knob. **It does not gate this hardening bundle.** Helmet is registered globally and unconditionally, the CSRF checks are unconditional, and the session cookie's `Secure` flag comes from `SESSION_COOKIE_SECURE` — none of them consult the environment profile. Today `t3SecurityEnforced` relaxes exactly one thing: the consent-screen style CSP described above.
- [Keys](/operate/keys/) — the signing-key side of QAuth's security posture.
