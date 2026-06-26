# Browser security model (`/ui/*` flow)

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

## CSRF protection (consent form)

`POST /ui/consent` is the only cookie-authenticated, state-changing browser
endpoint, so it is CSRF-protected with a session-bound double-submit token:

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

### Why other endpoints do not carry a CSRF token

- `POST /ui/login` submits credentials and runs **before** any authenticated
  session exists. Classic CSRF rides an existing ambient session, which is
  absent here; `SameSite=Lax` plus the fresh-session-on-success behaviour
  (session-fixation defence) cover the relevant cases.
- `/auth/login`, `/auth/logout`, `/auth/register`, `/auth/refresh`,
  `/auth/resend-verification`, and all `/oauth/*` endpoints authenticate with a
  **bearer token or client credentials**, not the browser session cookie. They
  carry no ambient-authority cookie, so CSRF does not apply.

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
own scripts and styles. The relaxation is scoped to `/docs` only; every other
route keeps the strict policy.

## Related configuration

| Env var                 | Default    | Purpose                              |
| ----------------------- | ---------- | ------------------------------------ |
| `SESSION_COOKIE_SECURE` | `true`     | `Secure` flag on the session cookie. |
| `SESSION_COOKIE_TTL`    | `86400`    | Session lifetime (seconds).          |
| `SECURITY_HSTS_ENABLED` | `true`     | Emit the HSTS header.                |
| `SECURITY_HSTS_MAX_AGE` | `31536000` | HSTS `max-age` (seconds).            |
