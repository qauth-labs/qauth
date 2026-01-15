# ADR-001: JWT Key Management Strategy

**Status:** Accepted  
**Date:** 2026-01-15  
**Authors:** QAuth Team

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
