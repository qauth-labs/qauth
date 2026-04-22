# ADR-006: OAuth Grants — `client_credentials`, `client_secret_basic`, and `aud` Claim

**Status:** Accepted
**Date:** 2026-04-16
**Authors:** QAuth Team

## Context

Phase 1 shipped a single OAuth grant (`authorization_code` with PKCE) and a single client authentication method (`client_secret_post`). Issued JWTs carried `sub`, `email`, `email_verified`, `client_id`, `iss`, `iat`, and `exp` — but no `aud` and no `scope`.

Three shortcomings surfaced while integrating QAuth into real workloads:

1. **No service-to-service auth.** A daemon or background worker calling a QAuth-protected API has no end user and cannot drive the authorization code flow. The industry-standard solution is OAuth 2.1's `client_credentials` grant (RFC 6749 4.4).
2. **Only one client auth method.** Many clients (and most OIDC conformance profiles) expect HTTP Basic authentication (`client_secret_basic`, RFC 6749 2.3.1) as the default. Shipping only form-body credentials blocks those integrations.
3. **No audience claim.** Without `aud`, a token issued for Service A cannot be safely rejected by Service B — they both trust the same issuer and signature, so a cross-service token replay is a valid token. RFC 8707 ("Resource Indicators") addresses this; the light-mode pattern (per-client audience configured at registration) is the pragmatic choice before full resource-indicator support lands.

This ADR captures the decisions taken while implementing all three.

## Decision

### 1. Add the `client_credentials` grant (RFC 6749 4.4)

- Enabled per-client via `oauth_clients.grant_types` (already a `JSONB` allow-list).
- `sub` on issued tokens equals the `client_id` — there is no end user.
- **No refresh token is issued** (RFC 6749 4.4.3). A new access token is obtained by repeating the grant.
- `scope` is validated against `oauth_clients.scopes` (allow-list). Any scope outside the allow-list causes the request to fail with OAuth error `invalid_scope` → HTTP 400.

### 2. Support `client_secret_basic` alongside `client_secret_post` (RFC 6749 2.3.1)

- Both methods work on `/oauth/token` and `/oauth/introspect`.
- Precedence: `Authorization: Basic <b64>` header wins over body `client_id` / `client_secret`.
- When both are present and the `client_id` in the header and body disagree, the request is rejected with `invalid_client` (RFC 6749 2.3.1).
- Credentials inside the Basic header are `application/x-www-form-urlencoded`-decoded after Base64 decoding per RFC 6749 2.3.1.

### 3. Add `aud` and `scope` to issued JWTs (RFC 8707 light-mode)

- New column `oauth_clients.audience JSONB` — an optional array of audience strings.
- Claim resolution:
  - `audience` is set and has >1 entry → `aud` is the array (multi-audience token).
  - `audience` is set and has exactly 1 entry → `aud` is the single string.
  - `audience` is `NULL` or `[]` → `aud` falls back to `client_id`.
- `scope` is space-separated per RFC 6749 3.3 and is included only when non-empty.
- The same claims flow through:
  - `/auth/login`, `/auth/refresh` (user-context tokens).
  - `/oauth/token` for both `authorization_code` and `client_credentials`.
  - `/oauth/introspect` response (RFC 7662 2.2 — `aud`, `scope`).

### 4. Error mapping (RFC 6749 5.2)

| Failure                                  | OAuth error              | HTTP |
| ---------------------------------------- | ------------------------ | ---- |
| Unknown / disabled / wrong-secret client | `invalid_client`         | 401  |
| Basic/body client_id conflict            | `invalid_client`         | 401  |
| Grant not in `client.grant_types`        | `unauthorized_client`    | 401  |
| Scope outside `client.scopes` allow-list | `invalid_scope`          | 400  |
| Bad / used / expired authorization code  | `invalid_grant`          | 400  |
| Unknown `grant_type`                     | `unsupported_grant_type` | 400  |

## Consequences

### Positive

- Background workers and service-mesh calls can authenticate without an end user.
- Tokens are per-audience — Service B verifying `aud` will reject a token minted for Service A, even though both trust the same issuer. Defense in depth against token replay across services.
- Conformance with standard OIDC client-auth profiles becomes trivial.
- Scope allow-listing gives developers fine-grained control over what a machine client can ask for without changing code on the protected resource.

### Negative

- One more grant type means one more code path to keep in sync across `/oauth/token`, `/oauth/introspect`, audit logging, and docs.
- Adding `aud` to tokens is a minor breaking change for any downstream verifier that previously used QAuth tokens without checking `aud`. Existing verifiers that ignore `aud` continue to work; verifiers that check `aud` need their expected-audience list configured.
- The `oauth_clients.audience` column is optional — misconfiguring it (e.g., leaving it `NULL` in production) silently falls back to `client_id`, which may or may not match what a resource server expects.

### Neutral

- RFC 8707 full-mode (`resource` parameter per request, dynamic audience) is intentionally deferred. Light-mode is sufficient for current needs and avoids API churn. If we later need per-request audience selection, the column becomes an allow-list and the token handler picks a member per the request.
- No changes to the `iss` claim or JWT signing algorithm — this ADR is about claims and grants, not cryptography (see [ADR-001](./001-jwt-key-management.md) and [ADR-005](./005-pqc-hybrid-signing.md)).

## Related

- [RFC 6749 §4.4 — Client Credentials Grant](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4)
- [RFC 6749 §2.3.1 — Client Password (Basic / form body)](https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1)
- [RFC 6749 §5.2 — Error Response](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2)
- [RFC 7662 §2.2 — Introspection Response](https://datatracker.ietf.org/doc/html/rfc7662#section-2.2)
- [RFC 8707 — Resource Indicators for OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc8707)
- [RFC 9700 — OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/rfc9700)
- Migration: `libs/infra/db/drizzle/0001_add_oauth_clients_audience.sql`
