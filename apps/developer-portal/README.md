# Developer Portal

TanStack Start application that lets QAuth users register, verify their email, log in, and manage OAuth consent grants.

## Architecture

The portal owns its own session via an HttpOnly signed cookie `__Host-qauth_portal_session`. The cookie carries `{ accessToken, refreshToken, expiresAt }` signed with HMAC-SHA256. TanStack Start server functions are the only callers of auth-server endpoints — tokens never enter the browser.

## Environment variables

| Variable                | Required | Default | Description                                                                      |
| ----------------------- | -------- | ------- | -------------------------------------------------------------------------------- |
| `AUTH_SERVER_URL`       | Yes      | —       | Base URL the **server** uses to reach auth-server (e.g. `http://localhost:3000`) |
| `VITE_AUTH_SERVER_URL`  | Yes      | —       | Base URL the **browser** uses (e.g. `http://localhost:3000`); build-time inlined |
| `PORTAL_SESSION_SECRET` | Yes      | —       | 32+ char random secret for signing the session cookie                            |
| `PORTAL_SESSION_TTL`    | No       | `900`   | Session cookie lifetime in seconds                                               |

The portal itself listens on **3001**; auth-server is on **3000**. Both URL
variables point at auth-server, never at the portal.

Under Docker Compose these are set indirectly — `PORTAL_AUTH_SERVER_URL` maps to
`AUTH_SERVER_URL` (defaulting to `http://auth-server:3000` on the Compose
network) and `PORTAL_PUBLIC_AUTH_SERVER_URL` maps to `VITE_AUTH_SERVER_URL`. See
the [Docker guide](../../docs/docker.md#environment-variables).

See `.env.example` at the repo root for sample values.

## Server layer

All server-only code lives under `src/server/`:

- `config.ts` — env var validation (throws at startup if required vars are missing)
- `session-cookie.ts` — HMAC-SHA256 sign/verify helpers for the portal session cookie
- `auth-server-client.ts` — typed `fetch` wrappers for each auth-server endpoint, always returning `Result<T>` (never throws)
- `actions/` — TanStack Start server functions (`createServerFn`) consumed by route files

## Running tests

```bash
pnpm nx test developer-portal
```
