---
name: oauth-oidc
description: OAuth 2.1 / OIDC rules for QAuth. Use when working with authorization endpoints, token flows, PKCE, JWKS, OIDC discovery, or spec compliance (RFC 9700, OIDC Core 1.0). Covers endpoint behaviour, email claim rules, and token security.
---

# OAuth 2.1 / OIDC Rules

You are working in the QAuth OAuth/OIDC implementation.

## Spec References

- OAuth 2.1 (`draft-ietf-oauth-v2-1`) — PKCE mandatory for all authorization code flows
- OIDC Core 1.0 — `sub` is stable UUID, `email` is optional and omitted when unverified
- RFC 7662 — Token introspection (compliance feature, client auth required)
- RFC 7517 — JSON Web Key (JWKS)
- RFC 9700 — OAuth 2.0 Security Best Current Practice

## Endpoints

| Endpoint                                | Description                                                                                          |
| --------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `POST /auth/register`                   | Registration — creates user, credential, attribute, verification token                               |
| `POST /auth/login`                      | Password login — looks up `user_credentials` by `(realm_id, 'password', email)`                      |
| `GET /auth/verify`                      | Email verification — marks `credential_data.email_verified=true` and `user_attributes.verified=true` |
| `POST /auth/resend-verification`        | Resend verification email                                                                            |
| `GET /oauth/authorize`                  | Authorization Code Flow initiation                                                                   |
| `POST /oauth/token`                     | Token endpoint (authorization_code, refresh_token grants)                                            |
| `POST /oauth/introspect`                | RFC 7662 introspection (client auth required)                                                        |
| `GET /oauth/userinfo`                   | OIDC userinfo — reads `sub` from JWT, returns verified email from `user_attributes`                  |
| `GET /.well-known/jwks.json`            | JWKS endpoint                                                                                        |
| `GET /.well-known/openid-configuration` | OIDC discovery                                                                                       |

## Introspection

`POST /oauth/introspect` is a compliance feature, not a primary usage path.
Modern applications validate JWT tokens locally via JWKS.

Client authentication is **required** on this endpoint — not optional.
This prevents token enumeration attacks. The endpoint must return `{"active":false}`
for any unauthenticated request rather than an error, per RFC 7662.

## OIDC Discovery

`/.well-known/openid-configuration` must always reflect the current set of supported
grant types, response types, and signing algorithms.

When wallet federation (Phase 2) is implemented, update to advertise:

- `subject_types_supported: ["public", "pairwise"]`
- `request_object_signing_alg_values_supported` (for SIOPv2)

Do not add these fields until `WalletProvider` is implemented and tested.

## Email Claim Behaviour

The `email` claim in ID tokens and userinfo responses:

- Present only when `user_attributes` has a verified email (`verified=true`)
- Absent (not null) when no verified email exists
- Sourced from the highest-trust attribute source: `wallet > oidc_* > self_reported`

This is intentional and correct per OIDC Core 1.0. Applications that assume
`email` is always present in the userinfo response are not OIDC-compliant.

## PKCE

PKCE is mandatory for all authorization code flows. The server rejects requests
without `code_challenge`. `code_challenge_method` must be `S256`; plain text is
not supported.

## Token Security

- Access tokens: JWT, signed with Ed25519 (Phase 1), hybrid ML-DSA+Ed25519 (Phase 2)
- Refresh tokens: opaque random tokens, SHA-256 hashed before storage
- Verification tokens: opaque random tokens, SHA-256 hashed before storage
- All token hashes stored as 64-character hex strings (SHA-256 output)
