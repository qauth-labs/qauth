---
name: auth-oauth
description: Implements and reviews OAuth 2.0/2.1 flows following RFC 6749, RFC 9700 (BCP), and PKCE (RFC 7636). Use when implementing authorization code flow, token handling, client registration, or securing OAuth endpoints.
---

# OAuth 2.0 / 2.1 (Auth)

Standards-aligned OAuth implementation and review. Follow RFC 6749 (core), RFC 9700 (security BCP, Jan 2025), RFC 7636 (PKCE), and OAuth 2.1 draft where applicable.

## Standards Quick Reference

| Document        | Purpose                                                           |
| --------------- | ----------------------------------------------------------------- |
| RFC 6749        | OAuth 2.0 Authorization Framework (core)                          |
| RFC 6750        | Bearer Token Usage                                                |
| RFC 7636        | PKCE (Proof Key for Code Exchange)                                |
| RFC 8414        | Authorization Server Metadata                                     |
| RFC 9126        | Pushed Authorization Requests (PAR)                               |
| RFC 9207        | Authorization Server Issuer Identification                        |
| RFC 9449        | DPoP (Demonstrating Proof of Possession)                          |
| RFC 9700        | OAuth 2.0 Security BCP (Jan 2025)                                 |
| OAuth 2.1 draft | Consolidates BCP; PKCE mandatory, implicit/password grant removed |

For detailed RFC/BCP excerpts and links, see [reference.md](reference.md).

---

## Grant Types (What to Use / Avoid)

| Grant                                | Use?          | Notes                                                                        |
| ------------------------------------ | ------------- | ---------------------------------------------------------------------------- |
| **Authorization code + PKCE**        | ✅ Required   | All clients (public and confidential). PKCE mandatory (RFC 9700, OAuth 2.1). |
| **Client credentials**               | ✅ M2M        | Confidential clients only. Machine-to-machine flows.                         |
| **Refresh token**                    | ✅ Long-lived | Bind to client; use rotation + sender-constraining.                          |
| **Implicit** (`response_type=token`) | ❌ Forbidden  | Deprecated; tokens leak via URL/fragment/history.                            |
| **Resource owner password**          | ❌ Forbidden  | Exposes credentials to client (RFC 9700 §2.4).                               |

---

## Authorization Code + PKCE (Required Pattern)

### Flow Overview

```
┌──────────┐                               ┌───────────────────┐
│  Client  │                               │ Authorization     │
│          │                               │ Server            │
└────┬─────┘                               └─────────┬─────────┘
     │                                               │
     │ 1. Generate code_verifier (43-128 chars)      │
     │    code_challenge = BASE64URL(SHA256(verifier))│
     │                                               │
     │ 2. GET /authorize                             │
     │    ?response_type=code                        │
     │    &client_id=...                             │
     │    &redirect_uri=...                          │
     │    &code_challenge=...                        │
     │    &code_challenge_method=S256                │
     │    &state=...                                 │
     ├──────────────────────────────────────────────►│
     │                                               │
     │ 3. 302 redirect_uri?code=...&state=...        │
     │◄──────────────────────────────────────────────┤
     │                                               │
     │ 4. POST /token                                │
     │    grant_type=authorization_code              │
     │    &code=...                                  │
     │    &redirect_uri=...                          │
     │    &code_verifier=...                         │
     │    &client_id=...                             │
     │    &client_secret=... (confidential only)     │
     ├──────────────────────────────────────────────►│
     │                                               │
     │ 5. { access_token, refresh_token, ... }       │
     │◄──────────────────────────────────────────────┤
```

### PKCE Implementation (RFC 7636)

```typescript
import { randomBytes, createHash } from 'crypto';

// Generate code_verifier: 32 random bytes → 43-char base64url string
const codeVerifier = randomBytes(32).toString('base64url');
// Result: 43 chars, charset [A-Za-z0-9\-._~]

// Generate code_challenge: SHA256(verifier) → base64url
const codeChallenge = createHash('sha256').update(codeVerifier, 'ascii').digest('base64url');
```

### Security Requirements

| Requirement              | Implementation                                                 |
| ------------------------ | -------------------------------------------------------------- |
| **S256 only**            | Never use `plain` method; S256 is MTI (Mandatory To Implement) |
| **High entropy**         | 32 bytes (256 bits) minimum randomness                         |
| **One-time use**         | Authorization code MUST be invalidated after first use         |
| **Short-lived**          | Authorization code expires in ≤10 minutes                      |
| **Timing-safe**          | Use constant-time comparison for PKCE verification             |
| **Downgrade protection** | Reject `code_verifier` if no `code_challenge` was sent         |

### QAuth Implementation Reference

```typescript
// libs/server/pkce/src/lib/pkce.ts
export function generateCodeVerifier(): string {
  return randomBytes(32).toString('base64url'); // 43 chars
}

export function generateCodeChallenge(verifier: string): string {
  return createHash('sha256').update(verifier, 'ascii').digest('base64url');
}

export function verifyCodeChallenge(verifier: string, challenge: string): boolean {
  const computed = generateCodeChallenge(verifier);
  return timingSafeEqual(Buffer.from(computed), Buffer.from(challenge));
}
```

---

## Pushed Authorization Requests (PAR) - RFC 9126

PAR enhances security by sending authorization parameters via back-channel POST instead of front-channel query parameters.

### Benefits

- **Integrity**: Request parameters are not exposed in browser URL/history
- **Confidentiality**: Sensitive parameters (e.g., `login_hint`) not visible to user
- **Size**: No URL length limitations
- **Authentication**: Client authenticates when pushing request

### Flow

```
┌──────────┐                               ┌───────────────────┐
│  Client  │                               │ Authorization     │
│          │                               │ Server            │
└────┬─────┘                               └─────────┬─────────┘
     │                                               │
     │ 1. POST /par                                  │
     │    Content-Type: application/x-www-form-urlencoded
     │    client_id=...&client_secret=...            │
     │    &response_type=code                        │
     │    &redirect_uri=...                          │
     │    &code_challenge=...                        │
     │    &scope=...                                 │
     ├──────────────────────────────────────────────►│
     │                                               │
     │ 2. 201 Created                                │
     │    { "request_uri": "urn:ietf:...",           │
     │      "expires_in": 60 }                       │
     │◄──────────────────────────────────────────────┤
     │                                               │
     │ 3. GET /authorize                             │
     │    ?client_id=...                             │
     │    &request_uri=urn:ietf:...                  │
     ├──────────────────────────────────────────────►│
     │                                               │
     │    (continues normal authorization flow)      │
```

### Server Metadata

```json
{
  "pushed_authorization_request_endpoint": "https://as.example.com/par",
  "require_pushed_authorization_requests": false
}
```

---

## Sender-Constrained Tokens

### DPoP (RFC 9449)

DPoP binds tokens to a client's key pair, preventing token replay if stolen.

```
┌──────────┐                               ┌───────────────────┐
│  Client  │                               │ Resource Server   │
└────┬─────┘                               └─────────┬─────────┘
     │                                               │
     │ GET /resource                                 │
     │ Authorization: DPoP <access_token>            │
     │ DPoP: <signed_jwt>                            │
     │                                               │
     │ DPoP JWT contains:                            │
     │   typ: "dpop+jwt"                             │
     │   alg: ES256 (or EdDSA)                       │
     │   jwk: { public_key }                         │
     │   jti: unique_id                              │
     │   htm: "GET"                                  │
     │   htu: "https://rs.example.com/resource"      │
     │   iat: timestamp                              │
     ├──────────────────────────────────────────────►│
```

### When to Use

| Mechanism  | Use Case                                                 |
| ---------- | -------------------------------------------------------- |
| **Bearer** | Internal services, low-risk APIs, backward compatibility |
| **DPoP**   | Public clients, high-value APIs, FAPI 2.0 compliance     |
| **mTLS**   | Server-to-server, certificate-based infrastructure       |

---

## Redirect URI Security

### Validation Rules (RFC 9700)

```typescript
function validateRedirectUri(requestUri: string, registeredUris: string[]): boolean {
  // MUST use exact string matching
  // Exception: localhost with variable port for native apps (RFC 8252 §7.3)

  const isLoopback = /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?\//.test(requestUri);

  if (isLoopback) {
    // For native apps: match scheme, host, path; ignore port
    const requestUrl = new URL(requestUri);
    return registeredUris.some((uri) => {
      const registered = new URL(uri);
      return (
        registered.protocol === requestUrl.protocol &&
        registered.hostname === requestUrl.hostname &&
        registered.pathname === requestUrl.pathname
      );
    });
  }

  // Exact match required for all other URIs
  return registeredUris.includes(requestUri);
}
```

### Prohibited Patterns

- ❌ Wildcards: `https://*.example.com/callback`
- ❌ Query params in registered URI: `https://example.com/cb?extra=param`
- ❌ Open redirectors: redirect to arbitrary URL from query param
- ❌ HTTP (except loopback): `http://example.com/callback`

---

## Token Endpoint Security

### Client Authentication Methods

| Method                | Security    | Use Case                                         |
| --------------------- | ----------- | ------------------------------------------------ |
| `private_key_jwt`     | ✅ High     | Asymmetric; recommended for confidential clients |
| `client_secret_jwt`   | ⚠️ Medium   | Symmetric JWT; better than basic                 |
| `client_secret_post`  | ⚠️ Medium   | Secret in body; current QAuth default            |
| `client_secret_basic` | ⚠️ Medium   | Secret in header; widely supported               |
| `none`                | Public only | Public clients with PKCE                         |

### QAuth Token Endpoint Pattern

```typescript
// apps/auth-server/src/app/routes/oauth/token.ts

// 1. Validate client credentials (constant-time)
const clientSecretValid = await fastify.passwordHasher.verifyPassword(
  client.clientSecretHash,
  body.client_secret
);

// 2. Verify PKCE (timing-safe comparison)
const pkceValid = fastify.pkceUtils.verifyCodeChallenge(body.code_verifier, authCode.codeChallenge);

// 3. Mark authorization code as used BEFORE issuing tokens
await fastify.repositories.authorizationCodes.markUsed(authCode.id);

// 4. Resolve email claim from user_attributes (identifier abstraction — no email on users table)
const emailAttr = await fastify.repositories.userAttributes.findVerifiedByUserIdAndKey(
  user.id,
  'email'
);

// 5. Issue tokens — omit email claim entirely if no verified attribute exists
const accessToken = await fastify.jwtUtils.signAccessToken({
  sub: user.id,
  ...(emailAttr ? { email: emailAttr.attrValue, email_verified: true } : {}),
});
```

---

## New Threats (2025-2026 Security Updates)

### COAT Attack (Cross-tool OAuth Account Takeover)

**Threat**: In multi-tenant OAuth clients (supporting multiple tools/providers), attackers steal authorization codes and inject them into different tool contexts.

**Mitigation**:

- Use unique `redirect_uri` per OAuth connection context (tool + provider + tenant)
- Never share OAuth configurations across tools
- Validate the full connection context on callback

### Audience Injection

**Threat**: Malicious AS tricks client into creating JWT assertions valid for honest AS.

**Mitigation**:

```typescript
// Use issuer identifier as audience (NOT token endpoint URL)
const clientAssertion = await signJwt({
  iss: clientId,
  sub: clientId,
  aud: 'https://as.example.com', // Issuer identifier from metadata
  jti: randomUUID(),
  iat: now,
  exp: now + 60,
});
```

### Session Fixation via OAuth

**Threat**: Attacker initiates OAuth flow, victim completes it, attacker gains access.

**Mitigation**:

- Bind session to user BEFORE OAuth flow starts
- Re-authenticate user on session changes
- Validate session binding before token request

---

## Implementation Checklist

### Authorization Endpoint

- [ ] PKCE required (S256 only, reject `plain`)
- [ ] Exact redirect_uri matching (no wildcards)
- [ ] Validate `response_type=code` only (no implicit)
- [ ] Validate client `grant_types` includes `authorization_code`
- [ ] Generate high-entropy authorization code (≥256 bits)
- [ ] Code expires in ≤10 minutes
- [ ] Audit log all authorization attempts

### Token Endpoint

- [ ] Authenticate confidential clients
- [ ] Verify PKCE (timing-safe comparison)
- [ ] Validate authorization code not expired
- [ ] Validate authorization code not already used
- [ ] Validate `redirect_uri` matches original request
- [ ] Mark code as used BEFORE issuing tokens
- [ ] Enforce minimum response time (timing attack prevention)
- [ ] Audit log all token exchanges

### Token Security

- [ ] Access tokens: short-lived (5-15 min recommended)
- [ ] Refresh tokens: bound to client, consider rotation
- [ ] Store token hashes only (never plaintext)
- [ ] Consider sender-constraining (DPoP or mTLS)
- [ ] Restrict audience and scope (minimum privilege)

### General

- [ ] TLS everywhere (except loopback for native)
- [ ] Publish Authorization Server Metadata (RFC 8414)
- [ ] No open redirectors
- [ ] Rate limiting on all endpoints
- [ ] Comprehensive audit logging

---

## Additional Resources

- For RFC/BCP excerpts and links: [reference.md](reference.md)
- QAuth Authorization: `apps/auth-server/src/app/routes/oauth/authorize.ts`
- QAuth Token Exchange: `apps/auth-server/src/app/routes/oauth/token.ts`
- QAuth PKCE Utils: `libs/server/pkce/src/lib/pkce.ts`
