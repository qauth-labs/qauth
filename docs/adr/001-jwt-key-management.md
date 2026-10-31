# ADR-001: JWT Key Management Strategy

**Status:** Accepted  
**Date:** 2026-01-15  
**Authors:** QAuth Team

> **Status (2026-08-08): the "Future — JWKS Support" framing below is superseded; the JWKS endpoint and multi-key publication have shipped.** `GET /.well-known/jwks.json` is registered (`apps/auth-server/src/app/routes/well-known.ts`) and serves `fastify.jwtUtils.getJwks()`. The key set is genuinely multi-entry (`libs/fastify/plugins/jwt/src/lib/fastify-plugin-jwt.ts`): the active Ed25519 key, an optional RS256 key (#309), ML-DSA `AKP` entries (#246), and retired Ed25519 and ML-DSA keys, each under its own `kid` (#248 F9).
>
> **Status (2026-10-31): the three retired-key gaps below are closed.** ADR-019 moved the keys into each realm's encrypted key store, and the plugin holds none.
>
> - **Published.** Each realm's `/.well-known/jwks.json` lists its active keys, its `next` keys before they sign and its retired keys until their retention ends, each under its own `kid` (#491).
> - **Named.** Every access, ID and hybrid token names its key in `kid`, and a hybrid token its ML-DSA-65 key in `pqc_kid` (#491).
> - **Verified.** The plugin picks a token's key by `(kid, alg)` with `selectJwksKey` among the realm's active keys and its retired keys still inside their retention; `next` and `compromised` keys never verify (#492). The hybrid verifier finds the ML-DSA-65 key by the signed `pqc_kid` the same way. A token without a `kid`, from before the upgrade, verifies only against the key imported from `JWT_PRIVATE_KEY` (or `JWT_PUBLIC_KEY` on a process without the signer role), active or retired, while that variable is set. Every check of the server uses this set: `requireJwt`, userinfo, introspection, revocation, `/auth/logout` and the token-exchange subject and actor tokens.
>
> A rotation through the key store therefore keeps the tokens the old key signed. That rotation itself ships with #542 (scheduled) and #544 (manual); until then, a key replaced through its variable leaves the JWKS at once, and its tokens stop verifying.
>
> **What the note of 2026-10-22 recorded** (kept for the record): a rotation made every user sign in again, because of three separate gaps, and closing one left the other two:
>
> - **Retired keys are not wired.** No configuration key holds a retired key or the Ed25519 key's `kid`, and `apps/auth-server/src/app/app.ts` passes none of `retiredKeys`, `retiredMlDsaPublicKeys` or `keyId` to the JWT plugin. A deployed JWKS holds only the active keys, and its Ed25519 entry has no `kid`. The plugin has no retired-key option for the RS256 key.
> - **Tokens carry no `kid`.** `signAccessToken` (`libs/server/jwt/src/lib/jwt-service.ts`) stamps none, and the plugin passes none when it signs an EdDSA ID token, even when `keyId` is set. Such a token cannot name the retired key that signed it: `selectJwksKey` matches a token without a `kid` only to the JWKS entry without one, which after a rotation is the new key.
> - **Retired keys never verify.** The plugin's `verifyAccessToken` checks only the active Ed25519 key, and its hybrid resolver returns only the active ML-DSA key. A retired key passed to the plugin is published but not used to verify, so the server's own checks (introspection, revocation, token exchange and every bearer-protected route) reject a token that key signed.
>
> **Status (2026-10-09): [ADR-019](./019-deployment-topology-and-trust-boundaries.md) supersedes this record's production key model.**
>
> - This record injects keys as environment variables or files on every instance. ADR-019 replaces that model for production.
> - Under ADR-019, each realm holds one key per purpose. Keys are stored envelope-encrypted in Postgres.
> - The key-encryption key comes from a pluggable provider. Environment variables or a file remain the default source.
> - Per-realm keys follow from ADR-019's rule that each realm has its own host and its own issuer.
> - Rotation becomes automatic and overlapping. The next key is pre-published in JWKS, and the old key stays for verification.
> - ADR-019 decides to close the three retired-key gaps described above. All three are closed (status of 2026-10-31).

## Context

QAuth uses EdDSA (Ed25519) asymmetric keys for JWT signing and verification. We need a strategy for:

1. Key generation and storage across environments
2. Key injection in CI/CD pipelines
3. Key rotation without breaking user sessions
4. Balancing automation ease with user experience

### Technical Background

- JWT tokens are **stateless** - signed with private key, verified with public key
- If keys change, all previously issued tokens become invalid
- Users must re-authenticate when keys are rotated (with single-key setup)

## Decision

### Per-Environment Key Management

| Environment           | Key Storage                     | Rotation Policy           |
| --------------------- | ------------------------------- | ------------------------- |
| **Local Development** | `.env` file (gitignored)        | Developer discretion      |
| **CI Tests**          | Generated per run               | N/A (ephemeral)           |
| **Staging**           | GitHub Secrets                  | Freely (testers re-login) |
| **Production**        | Secrets Manager (Vault/AWS/GCP) | Planned, with notice      |

### Key Principles

1. **Keys are injected at runtime, never baked into images**
   - Docker images contain no secrets
   - Keys passed via environment variables at container start

2. **Keys persist across deployments**
   - Same keys used until explicit rotation
   - Deployments don't invalidate user sessions

3. **Different keys per environment**
   - Dev, staging, and production use separate key pairs
   - Compromise in one environment doesn't affect others

4. **Keys are generated once, stored securely**
   - Not auto-generated on each startup
   - Manually generated and stored in secrets manager

### CI/CD Implementation

```yaml
# GitHub Actions example
jobs:
  deploy:
    environment: production
    steps:
      - name: Deploy
        env:
          JWT_PRIVATE_KEY: ${{ secrets.JWT_PRIVATE_KEY }}
          JWT_PUBLIC_KEY: ${{ secrets.JWT_PUBLIC_KEY }}
        run: |
          # Keys injected at runtime
          docker run -e JWT_PRIVATE_KEY -e JWT_PUBLIC_KEY qauth-auth-server
```

### Key Generation

```bash
# Generate Ed25519 key pair
openssl genpkey -algorithm Ed25519 -out private.pem
openssl pkey -in private.pem -pubout -out public.pem

# Add to secrets manager (example: GitHub)
gh secret set JWT_PRIVATE_KEY < private.pem
gh secret set JWT_PUBLIC_KEY < public.pem

# Clean up local files
rm private.pem public.pem
```

### Key Rotation (Current - Single Key)

With the current single-key implementation:

1. Generate new key pair
2. Update secrets in secrets manager
3. Deploy new version
4. **All users must re-authenticate** (unavoidable)
5. Communicate maintenance window for production

### Key Rotation (Future - JWKS Support)

For zero-downtime rotation, implement JWKS (JSON Web Key Set):

```typescript
// Future: Multiple keys for graceful rotation
export async function verifyAccessToken(token: string, publicKeys: KeyLike[]): Promise<JWTPayload> {
  for (const key of publicKeys) {
    try {
      return (await jwtVerify(token, key)).payload;
    } catch {
      continue;
    }
  }
  throw new JWTInvalidError('Verification failed with all keys');
}
```

With JWKS endpoint (`/.well-known/jwks.json`):

```json
{
  "keys": [
    { "kid": "2026-01", "kty": "OKP", "crv": "Ed25519", "x": "..." },
    { "kid": "2025-12", "kty": "OKP", "crv": "Ed25519", "x": "..." }
  ]
}
```

Rotation process:

1. Add new key to JWKS (both keys valid)
2. Start signing with new key
3. Wait for old tokens to expire (grace period)
4. Remove old key from JWKS

## Consequences

### Positive

- **Simple setup** - Single key pair per environment
- **Secure** - Keys never in source code or images
- **Automatable** - CI/CD injects keys at runtime
- **Auditable** - Secrets managers provide access logs

### Negative

- **Session loss on rotation** - Users must re-login (mitigated by future JWKS)
- **Manual key generation** - One-time setup per environment
- **Coordination required** - Production rotation needs planning

### Neutral

- Standard industry practice for JWT-based authentication
- Compatible with future JWKS enhancement

## Related

- [RFC 7517 - JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517)
- [RFC 7518 - JSON Web Algorithms (JWA)](https://tools.ietf.org/html/rfc7518)
