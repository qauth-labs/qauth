import { type CryptoKey, exportJWK, generateKeyPair, type JWK, SignJWT } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';

import type { ValidatedToken } from '../types';
import { extractBearerToken, McpGuard } from './core';
import {
  InsufficientScopeError,
  InvalidTokenError,
  McpGuardConfigError,
  MissingTokenError,
} from './errors';

const ISSUER = 'https://auth.example.com';
const RESOURCE = 'https://mcp.example.com';

let privateKey: CryptoKey;
let publicJwk: JWK;

function jwksFetch(jwks: { keys: JWK[] }) {
  return (async () =>
    ({
      ok: true,
      status: 200,
      json: async () => jwks,
      text: async () => JSON.stringify(jwks),
    }) as unknown) as never;
}

async function signToken(claims: Record<string, unknown>, audience: string | string[]) {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'EdDSA' })
    .setIssuedAt()
    .setIssuer(ISSUER)
    .setAudience(audience)
    .setExpirationTime('300s')
    .sign(privateKey);
}

beforeAll(async () => {
  const kp = await generateKeyPair('EdDSA', { extractable: true });
  privateKey = kp.privateKey;
  publicJwk = await exportJWK(kp.publicKey);
  publicJwk.alg = 'EdDSA';
  publicJwk.kid = 'k1';
});

describe('extractBearerToken', () => {
  it('extracts the credential from a Bearer header', () => {
    expect(extractBearerToken('Bearer abc.def.ghi')).toBe('abc.def.ghi');
  });
  it('is case-insensitive on the scheme', () => {
    expect(extractBearerToken('bearer xyz')).toBe('xyz');
  });
  it('returns null for missing/empty/non-bearer headers', () => {
    expect(extractBearerToken(undefined)).toBeNull();
    expect(extractBearerToken('')).toBeNull();
    expect(extractBearerToken('Basic abc')).toBeNull();
    expect(extractBearerToken('Bearer ')).toBeNull();
  });
});

describe('McpGuard config validation', () => {
  it('throws without a resource', () => {
    expect(() => new McpGuard({ resource: '', authorizationServer: ISSUER })).toThrow(
      McpGuardConfigError
    );
  });
  it('throws without an authorization server', () => {
    expect(() => new McpGuard({ resource: RESOURCE, authorizationServer: '' })).toThrow(
      McpGuardConfigError
    );
  });
  it('throws when introspection mode lacks client credentials', () => {
    expect(
      () =>
        new McpGuard({
          resource: RESOURCE,
          authorizationServer: ISSUER,
          validationMode: 'introspection',
        })
    ).toThrow(/introspectionClient/);
  });
});

describe('McpGuard metadata', () => {
  const guard = new McpGuard({
    resource: RESOURCE,
    authorizationServer: ISSUER,
    requiredScopes: ['mcp:read'],
    fetch: jwksFetch({ keys: [] }),
  });

  it('builds PRM pointing at the AS with advertised scopes', () => {
    const doc = guard.getProtectedResourceMetadata();
    expect(doc.resource).toBe(RESOURCE);
    expect(doc.authorization_servers).toEqual([ISSUER]);
    expect(doc.scopes_supported).toEqual(['mcp:read']);
  });

  it('returns a fresh copy each call (no shared mutable state)', () => {
    const a = guard.getProtectedResourceMetadata();
    a.authorization_servers.push('https://evil.example.com');
    const b = guard.getProtectedResourceMetadata();
    expect(b.authorization_servers).toEqual([ISSUER]);
  });

  it('exposes the well-known path and absolute URL', () => {
    expect(guard.getMetadataPath()).toBe('/.well-known/oauth-protected-resource');
    expect(guard.getMetadataUrl()).toBe(
      'https://mcp.example.com/.well-known/oauth-protected-resource'
    );
  });
});

describe('McpGuard.authenticate (JWT mode)', () => {
  function guard(requiredScopes: string[] = []) {
    return new McpGuard({
      resource: RESOURCE,
      authorizationServer: ISSUER,
      requiredScopes,
      fetch: jwksFetch({ keys: [publicJwk] }),
    });
  }

  it('throws MissingTokenError when no bearer is present', async () => {
    await expect(guard().authenticate(undefined)).rejects.toBeInstanceOf(MissingTokenError);
  });

  it('validates a good token and returns claims', async () => {
    const token = await signToken({ sub: 'u', client_id: 'c', scope: 'mcp:read' }, RESOURCE);
    const claims = await guard(['mcp:read']).authenticate(`Bearer ${token}`);
    expect(claims.sub).toBe('u');
    expect(claims.scopes).toContain('mcp:read');
  });

  it('rejects a wrong-audience token (no passthrough)', async () => {
    const token = await signToken({ sub: 'u', client_id: 'c' }, 'https://other.example.com');
    await expect(guard().authenticate(`Bearer ${token}`)).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it('throws InsufficientScopeError listing the full required set on step-up', async () => {
    const token = await signToken({ sub: 'u', client_id: 'c', scope: 'mcp:read' }, RESOURCE);
    try {
      await guard(['mcp:read']).authenticate(`Bearer ${token}`, ['mcp:admin']);
      expect.unreachable('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(InsufficientScopeError);
      const e = error as InsufficientScopeError;
      expect(e.requiredScopes).toEqual(['mcp:read', 'mcp:admin']);
      expect(e.missingScopes).toEqual(['mcp:admin']);
    }
  });
});

describe('McpGuard.assertScopes', () => {
  const guard = new McpGuard({
    resource: RESOURCE,
    authorizationServer: ISSUER,
    requiredScopes: ['mcp:read'],
    fetch: jwksFetch({ keys: [] }),
  });
  const claims: ValidatedToken = {
    sub: 'u',
    clientId: 'c',
    scopes: ['mcp:read'],
    audience: [RESOURCE],
    raw: {},
  };

  it('passes when defaults are satisfied and no step-up requested', () => {
    expect(() => guard.assertScopes(claims)).not.toThrow();
  });

  it('throws when a stepped-up scope is missing', () => {
    expect(() => guard.assertScopes(claims, ['mcp:admin'])).toThrow(InsufficientScopeError);
  });
});
