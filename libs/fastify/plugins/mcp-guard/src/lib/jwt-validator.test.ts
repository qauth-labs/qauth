import { type CryptoKey, exportJWK, generateKeyPair, type JWK, SignJWT } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';

import { InvalidTokenError } from './errors';
import { JwtValidator } from './jwt-validator';

const ISSUER = 'https://auth.example.com';
const RESOURCE = 'https://mcp.example.com';
const JWKS_URI = `${ISSUER}/.well-known/jwks.json`;

let privateKey: CryptoKey;
let publicJwk: JWK;
// A second, unrelated key — tokens signed with this must fail (bad signature).
let otherPrivateKey: CryptoKey;

/**
 * A jose-compatible fetch that serves our test JWKS, regardless of URL. jose
 * calls it with (url, options) and expects a Response-like with `.json()`.
 */
function jwksFetch(jwks: { keys: JWK[] }) {
  return async () =>
    ({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/jwk-set+json' }),
      json: async () => jwks,
      text: async () => JSON.stringify(jwks),
    }) as unknown as Response;
}

async function signToken(
  key: CryptoKey,
  claims: Record<string, unknown>,
  opts: { issuer?: string; audience?: string | string[]; expSeconds?: number } = {}
): Promise<string> {
  let jwt = new SignJWT(claims)
    .setProtectedHeader({ alg: 'EdDSA' })
    .setIssuedAt()
    .setIssuer(opts.issuer ?? ISSUER)
    .setExpirationTime(`${opts.expSeconds ?? 300}s`);
  if (opts.audience !== undefined) {
    jwt = jwt.setAudience(opts.audience);
  }
  return jwt.sign(key);
}

function validator(fetchImpl: ReturnType<typeof jwksFetch>) {
  return new JwtValidator({
    jwksUri: JWKS_URI,
    issuer: ISSUER,
    audience: RESOURCE,
    fetch: fetchImpl as never,
  });
}

beforeAll(async () => {
  const kp = await generateKeyPair('EdDSA', { extractable: true });
  privateKey = kp.privateKey;
  publicJwk = await exportJWK(kp.publicKey);
  publicJwk.alg = 'EdDSA';
  publicJwk.kid = 'test-key-1';
  const other = await generateKeyPair('EdDSA', { extractable: true });
  otherPrivateKey = other.privateKey;
});

describe('JwtValidator', () => {
  it('accepts a well-formed, audience-bound token and normalises claims', async () => {
    const fetchImpl = jwksFetch({ keys: [publicJwk] });
    const token = await signToken(
      privateKey,
      { sub: 'user-123', client_id: 'client-abc', scope: 'mcp:read mcp:write' },
      { audience: RESOURCE }
    );
    const result = await validator(fetchImpl).validate(token);
    expect(result.sub).toBe('user-123');
    expect(result.clientId).toBe('client-abc');
    expect(result.scopes).toEqual(['mcp:read', 'mcp:write']);
    expect(result.audience).toContain(RESOURCE);
    expect(result.issuer).toBe(ISSUER);
  });

  it('accepts a token whose aud is an array containing the resource', async () => {
    const fetchImpl = jwksFetch({ keys: [publicJwk] });
    const token = await signToken(
      privateKey,
      { sub: 's', client_id: 'c' },
      { audience: ['https://other.example.com', RESOURCE] }
    );
    const result = await validator(fetchImpl).validate(token);
    expect(result.audience).toEqual(['https://other.example.com', RESOURCE]);
  });

  it('rejects a token whose aud is a DIFFERENT resource (no passthrough, RFC 8707)', async () => {
    const fetchImpl = jwksFetch({ keys: [publicJwk] });
    const token = await signToken(
      privateKey,
      { sub: 's', client_id: 'c' },
      { audience: 'https://other-resource.example.com' }
    );
    await expect(validator(fetchImpl).validate(token)).rejects.toBeInstanceOf(InvalidTokenError);
    await expect(validator(fetchImpl).validate(token)).rejects.toThrow(/audience/i);
  });

  it('rejects a token with no aud claim at all', async () => {
    const fetchImpl = jwksFetch({ keys: [publicJwk] });
    const token = await signToken(privateKey, { sub: 's', client_id: 'c' });
    await expect(validator(fetchImpl).validate(token)).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it('rejects a token from an untrusted issuer', async () => {
    const fetchImpl = jwksFetch({ keys: [publicJwk] });
    const token = await signToken(
      privateKey,
      { sub: 's', client_id: 'c' },
      { issuer: 'https://evil.example.com', audience: RESOURCE }
    );
    await expect(validator(fetchImpl).validate(token)).rejects.toThrow(/issuer/i);
  });

  it('rejects an expired token', async () => {
    const fetchImpl = jwksFetch({ keys: [publicJwk] });
    const token = await signToken(
      privateKey,
      { sub: 's', client_id: 'c' },
      { audience: RESOURCE, expSeconds: -10 }
    );
    await expect(validator(fetchImpl).validate(token)).rejects.toThrow(/expired/i);
  });

  it('rejects a token signed by an unknown key (no matching JWK)', async () => {
    const fetchImpl = jwksFetch({ keys: [publicJwk] });
    const token = await signToken(
      otherPrivateKey,
      { sub: 's', client_id: 'c' },
      { audience: RESOURCE }
    );
    await expect(validator(fetchImpl).validate(token)).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it('rejects a structurally invalid token', async () => {
    const fetchImpl = jwksFetch({ keys: [publicJwk] });
    await expect(validator(fetchImpl).validate('not-a-jwt')).rejects.toBeInstanceOf(
      InvalidTokenError
    );
  });

  it('never includes the token in the thrown reason', async () => {
    const fetchImpl = jwksFetch({ keys: [publicJwk] });
    const token = await signToken(
      privateKey,
      { sub: 's', client_id: 'c' },
      { audience: 'https://other.example.com' }
    );
    try {
      await validator(fetchImpl).validate(token);
      expect.unreachable('should have thrown');
    } catch (error) {
      expect((error as Error).message).not.toContain(token);
    }
  });
});
