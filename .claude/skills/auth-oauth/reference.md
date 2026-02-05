# OAuth 2.0 / 2.1 — RFC and BCP Reference

Concise reference to standards used by the auth-oauth skill. Use when implementing or auditing OAuth flows.

---

## RFCs and BCP Overview

| Document     | Title                                 | Status        | Notes                                                                           |
| ------------ | ------------------------------------- | ------------- | ------------------------------------------------------------------------------- |
| **RFC 6749** | The OAuth 2.0 Authorization Framework | Standard      | Core OAuth 2.0; grants, tokens, endpoints. Updated by 8252, 8996, 9700.         |
| **RFC 6750** | Bearer Token Usage                    | Standard      | How to send bearer tokens (header, body); not in query. Updated by 8996, 9700.  |
| **RFC 6819** | OAuth 2.0 Threat Model                | Informational | Threat model; referenced by RFC 9700.                                           |
| **RFC 7523** | JWT Profile for Client Auth           | Standard      | private_key_jwt, client_secret_jwt authentication.                              |
| **RFC 7636** | PKCE                                  | Standard      | code_verifier, code_challenge, S256/plain. Required for all clients (RFC 9700). |
| **RFC 8252** | OAuth 2.0 for Native Apps             | BCP           | Loopback redirect, custom URI schemes; localhost port exception.                |
| **RFC 8414** | Authorization Server Metadata         | Standard      | Discovery (.well-known/oauth-authorization-server).                             |
| **RFC 8705** | Mutual TLS for OAuth 2.0              | Standard      | mTLS client auth; certificate-bound access tokens.                              |
| **RFC 8707** | Resource Indicators                   | Standard      | `resource` parameter; audience restriction.                                     |
| **RFC 9068** | JWT Profile for Access Tokens         | Standard      | Structured access tokens; `aud`, `scope`, etc.                                  |
| **RFC 9126** | Pushed Authorization Requests         | Standard      | PAR endpoint; back-channel authorization request.                               |
| **RFC 9207** | Authorization Server Issuer ID        | Standard      | `iss` in auth response; mix-up prevention.                                      |
| **RFC 9449** | DPoP                                  | Standard      | Demonstrating Proof of Possession; sender-constrained tokens.                   |
| **RFC 9700** | Security BCP (BCP 240)                | BCP           | Jan 2025; updates 6749, 6750, 6819; PKCE, redirect URI, no implicit/password.   |

**OAuth 2.1 (draft-ietf-oauth-v2-1)**

- Consolidates RFC 6749/6750 + security BCP
- PKCE mandatory for authorization code
- Implicit and resource owner password grant removed
- Exact redirect URI matching; no patterns

---

## RFC 9700 (Security BCP) — Key Requirements

### MUST Requirements

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ PKCE                                                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│ • Public clients MUST use PKCE                                              │
│ • Authorization servers MUST support PKCE                                   │
│ • AS MUST enforce code_verifier when code_challenge was sent                │
│ • AS MUST reject token request with code_verifier when no code_challenge    │
│   was in the authorization request (PKCE downgrade protection)              │
│ • AS MUST provide a way to detect their support for PKCE                    │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ Redirect URI                                                                │
├─────────────────────────────────────────────────────────────────────────────┤
│ • Authorization servers MUST utilize exact string matching                  │
│   Exception: localhost port flexibility for native apps (RFC 8252 §7.3)     │
│ • MUST NOT expose URLs that forward the user's browser to arbitrary URIs    │
│ • MUST NOT allow redirect URIs using http scheme                            │
│   Exception: loopback for native apps                                       │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ Deprecated Grants                                                           │
├─────────────────────────────────────────────────────────────────────────────┤
│ • Resource owner password credentials grant MUST NOT be used                │
│ • Implicit grant SHOULD NOT be used; use authorization code instead         │
└─────────────────────────────────────────────────────────────────────────────┘
```

### SHOULD/RECOMMENDED Requirements

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Token Security                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│ • SHOULD use mechanisms for sender-constraining access tokens               │
│   (Mutual TLS or DPoP)                                                      │
│ • Access tokens SHOULD be audience-restricted                               │
│ • Tokens SHOULD be restricted to certain resources and actions              │
│ • RECOMMENDED to use end-to-end TLS between client and resource server      │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ Client Authentication                                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│ • Servers SHOULD enforce client authentication where feasible               │
│ • SHOULD use asymmetric cryptography (mTLS or Private Key JWT)              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ Discovery & Metadata                                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│ • RECOMMENDED that AS publish OAuth Authorization Server Metadata           │
│ • Clients SHOULD use `iss` parameter or distinct redirect URIs              │
│   when interacting with multiple authorization servers (mix-up defense)     │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Attacker Model

RFC 9700 accounts for five attacker categories:

1. **Web attackers** - Control arbitrary network endpoints
2. **Network attackers** - Full communications control
3. **Read authorization responses** - Can observe redirect responses
4. **Read authorization requests** - Can observe authorization requests
5. **Acquire valid access tokens** - Possess legitimate tokens

---

## RFC 7636 (PKCE) — Specification

### Code Verifier

```
code_verifier = high-entropy cryptographic random STRING
                using characters [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
                with length 43-128 characters

Recommended: 32 random bytes, base64url encoded → 43 characters
```

### Code Challenge

```
S256:  code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))
plain: code_challenge = code_verifier  ← AVOID; only for constrained devices
```

### Protocol Parameters

| Parameter               | Endpoint      | Description                      |
| ----------------------- | ------------- | -------------------------------- |
| `code_challenge`        | Authorization | BASE64URL(SHA256(code_verifier)) |
| `code_challenge_method` | Authorization | Always `S256`                    |
| `code_verifier`         | Token         | Original random string           |

### Security Properties

- **Entropy**: Code verifier must have sufficient entropy (≥256 bits)
- **S256 protection**: Challenge cannot be reversed to obtain verifier
- **No salting needed**: High entropy makes salting unnecessary
- **Downgrade prevention**: Clients MUST NOT downgrade to plain after trying S256

---

## RFC 9126 (PAR) — Pushed Authorization Requests

### Endpoint

```
POST /par HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

client_id=CLIENT_ID&
client_secret=CLIENT_SECRET&
response_type=code&
redirect_uri=https://client.example.com/callback&
code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&
code_challenge_method=S256&
scope=openid%20profile
```

### Response (201 Created)

```json
{
  "request_uri": "urn:ietf:params:oauth:request_uri:bwc4JK-ESC0w8acc191e-Y1LTC2",
  "expires_in": 60
}
```

### Authorization Request with PAR

```
GET /authorize?client_id=CLIENT_ID&request_uri=urn:ietf:params:oauth:request_uri:bwc4JK-ESC0w8acc191e-Y1LTC2 HTTP/1.1
Host: as.example.com
```

### Server Metadata

```json
{
  "pushed_authorization_request_endpoint": "https://as.example.com/par",
  "require_pushed_authorization_requests": false
}
```

### Security Benefits

| Benefit           | Description                                     |
| ----------------- | ----------------------------------------------- |
| Integrity         | Parameters not exposed in browser URL/history   |
| Confidentiality   | Sensitive params (login_hint, etc.) not visible |
| Authentication    | Client authenticates when pushing request       |
| Size              | No URL length limitations                       |
| Replay prevention | request_uri should be one-time use              |

---

## RFC 9449 (DPoP) — Proof of Possession

### DPoP Proof JWT Structure

```json
{
  "typ": "dpop+jwt",
  "alg": "ES256",
  "jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "...",
    "y": "..."
  }
}
.
{
  "jti": "unique-id",
  "htm": "POST",
  "htu": "https://as.example.com/token",
  "iat": 1562262616
}
```

### Token Request with DPoP

```
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7...

grant_type=authorization_code&
code=...&
redirect_uri=...&
code_verifier=...
```

### Resource Request with DPoP

```
GET /resource HTTP/1.1
Host: rs.example.com
Authorization: DPoP eyJhbGciOiJSUzI1NiIsImtpZCI6ImJlb0dPckgifQ...
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7...
```

### DPoP Claims

| Claim   | Required    | Description                                      |
| ------- | ----------- | ------------------------------------------------ |
| `jti`   | Yes         | Unique identifier for the proof                  |
| `htm`   | Yes         | HTTP method (GET, POST, etc.)                    |
| `htu`   | Yes         | HTTP URI (without query/fragment)                |
| `iat`   | Yes         | Issued at timestamp                              |
| `ath`   | Conditional | Access token hash (when using with access token) |
| `nonce` | Conditional | Server-provided nonce (when required)            |

---

## RFC 9207 — Authorization Server Issuer Identification

### Mix-Up Attack Prevention

When clients interact with multiple authorization servers, they must identify which AS issued a response.

### Authorization Response with iss

```
HTTP/1.1 302 Found
Location: https://client.example.com/callback?
  code=abc123&
  state=xyz789&
  iss=https://as.example.com
```

### Client Validation

```typescript
function validateAuthorizationResponse(
  response: { code: string; state: string; iss?: string },
  expectedIssuer: string
): boolean {
  if (response.iss && response.iss !== expectedIssuer) {
    throw new Error('Issuer mismatch - possible mix-up attack');
  }
  return true;
}
```

---

## RFC 8414 — Authorization Server Metadata

### Discovery URL

```
GET /.well-known/oauth-authorization-server HTTP/1.1
Host: as.example.com
```

### Metadata Example

```json
{
  "issuer": "https://as.example.com",
  "authorization_endpoint": "https://as.example.com/authorize",
  "token_endpoint": "https://as.example.com/token",
  "jwks_uri": "https://as.example.com/.well-known/jwks.json",
  "scopes_supported": ["openid", "profile", "email"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "token_endpoint_auth_methods_supported": [
    "client_secret_basic",
    "client_secret_post",
    "private_key_jwt"
  ],
  "code_challenge_methods_supported": ["S256"],
  "pushed_authorization_request_endpoint": "https://as.example.com/par",
  "dpop_signing_alg_values_supported": ["ES256", "EdDSA"]
}
```

---

## 2025-2026 Security Updates (draft-ietf-oauth-security-topics-update)

### New Threats

| Threat                 | Description                                                            | Mitigation                                                 |
| ---------------------- | ---------------------------------------------------------------------- | ---------------------------------------------------------- |
| **COAT**               | Cross-tool OAuth Account Takeover; code injection across tool contexts | Unique redirect_uri per context; don't share OAuth configs |
| **Audience Injection** | Malicious AS obtains client JWT valid for honest AS                    | Use issuer identifier (not token endpoint) as audience     |
| **Session Fixation**   | Attacker initiates flow, victim completes it                           | Bind session before flow; re-authenticate on changes       |

### COAT Attack Details

**Vulnerability**: Centralized OAuth clients serving multiple tools/providers fail to isolate connection contexts.

**Attack Flow**:

1. Attacker registers malicious tool with same OAuth provider
2. Victim starts authorization for honest tool
3. Attacker intercepts and redirects to their tool's context
4. Valid authorization code is now bound to attacker's context

**Defense**:

```typescript
// Generate unique redirect_uri per connection context
const connectionContext = `${providerId}:${toolId}:${tenantId}`;
const contextHash = createHash('sha256').update(connectionContext).digest('hex').slice(0, 16);
const redirectUri = `https://client.example.com/callback/${contextHash}`;
```

### Audience Injection Defense

```typescript
// WRONG: Using token endpoint as audience
const assertion = await signJwt({
  aud: 'https://as.example.com/token', // Vulnerable!
});

// CORRECT: Using issuer identifier as audience
const assertion = await signJwt({
  aud: 'https://as.example.com', // Issuer from metadata
});
```

---

## Links

### IETF / RFC Editor

- RFC 6749: https://www.rfc-editor.org/rfc/rfc6749
- RFC 6750: https://www.rfc-editor.org/rfc/rfc6750
- RFC 7523: https://www.rfc-editor.org/rfc/rfc7523
- RFC 7636: https://www.rfc-editor.org/rfc/rfc7636
- RFC 8252: https://www.rfc-editor.org/rfc/rfc8252
- RFC 8414: https://www.rfc-editor.org/rfc/rfc8414
- RFC 8705: https://www.rfc-editor.org/rfc/rfc8705
- RFC 9068: https://www.rfc-editor.org/rfc/rfc9068
- RFC 9126: https://www.rfc-editor.org/rfc/rfc9126
- RFC 9207: https://www.rfc-editor.org/rfc/rfc9207
- RFC 9449: https://www.rfc-editor.org/rfc/rfc9449
- RFC 9700: https://www.rfc-editor.org/rfc/rfc9700

### OAuth Working Group

- OAuth 2.1 draft: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1
- Security updates: https://datatracker.ietf.org/doc/draft-ietf-oauth-security-topics-update/

### Best Practices

- OAuth.net BCP: https://oauth.net/2/oauth-best-practice/
- OWASP OAuth Cheatsheet: https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html
