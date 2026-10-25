import { type CryptoKey, exportJWK, generateKeyPair, type JWK, SignJWT } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';

import type { ValidatedToken } from '../types';
import { extractBearerToken, ResourceGuard } from './core';
import {
  InsufficientScopeError,
  InvalidTokenError,
  MissingTokenError,
  ResourceGuardConfigError,
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
  it('requires a space after the scheme, and allows several', () => {
    expect(extractBearerToken('Bearerabc')).toBeNull();
    expect(extractBearerToken('Bearer    abc')).toBe('abc');
  });
  it('refuses a credential containing a line terminator', () => {
    expect(extractBearerToken('Bearer abc\ndef')).toBeNull();
    expect(extractBearerToken('Bearer abc\u2028def')).toBeNull();
  });
  // CodeQL js/polynomial-redos: the old single regex backtracked quadratically
  // on "bearer" + many spaces + a line terminator. Linear now; a 100k-space
  // input finishes far inside any budget a quadratic scan would blow.
  it('stays linear on many spaces before a line terminator', () => {
    const hostile = `bearer ${' '.repeat(100_000)}\nx`;
    const started = performance.now();
    expect(extractBearerToken(hostile)).toBeNull();
    expect(performance.now() - started).toBeLessThan(250);
  });
});

describe('ResourceGuard config validation', () => {
  it('throws without a resource', () => {
    expect(() => new ResourceGuard({ resource: '', authorizationServer: ISSUER })).toThrow(
      ResourceGuardConfigError
    );
  });
  it('throws without an authorization server', () => {
    expect(() => new ResourceGuard({ resource: RESOURCE, authorizationServer: '' })).toThrow(
      ResourceGuardConfigError
    );
  });
  it('throws when introspection mode lacks client credentials', () => {
    expect(
      () =>
        new ResourceGuard({
          resource: RESOURCE,
          authorizationServer: ISSUER,
          validationMode: 'introspection',
        })
    ).toThrow(/introspectionClient/);
  });
});

describe('ResourceGuard metadata', () => {
  const guard = new ResourceGuard({
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

describe('ResourceGuard.authenticate (JWT mode)', () => {
  function guard(requiredScopes: string[] = []) {
    return new ResourceGuard({
      resource: RESOURCE,
      authorizationServer: ISSUER,
      requiredScopes,
      fetch: jwksFetch({ keys: [publicJwk] }),
    });
  }

  it('throws MissingTokenError when no bearer is present', async () => {
    await expect(guard().authenticate(undefined)).rejects.toBeInstanceOf(MissingTokenError);
  });

  // #284 — the 401 challenge advertises what the route needs, so the error has
  // to carry the defaults plus any per-call step-up scopes, de-duplicated.
  it('carries the full required scope set on MissingTokenError', async () => {
    await expect(
      guard(['mcp:read']).authenticate(undefined, ['mcp:read', 'mcp:admin'])
    ).rejects.toMatchObject({ requiredScopes: ['mcp:read', 'mcp:admin'] });
  });

  it('carries an empty required set when the route requires no scopes', async () => {
    await expect(guard().authenticate(undefined)).rejects.toMatchObject({ requiredScopes: [] });
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

describe('ResourceGuard.authenticate (introspection mode)', () => {
  const INTROSPECTION_ENDPOINT = `${ISSUER}/oauth/introspect`;

  // One fetch for both upstreams: the JWKS, and an introspection endpoint that
  // records every token it is asked about and answers "active".
  function introspectionGuard(
    options: { jwksDown?: boolean; introspectionLocalCheck?: boolean } = {}
  ) {
    const introspected: string[] = [];
    const active = { active: true, sub: 'u', client_id: 'c', scope: 'mcp:read', aud: RESOURCE };
    const fetch = (async (input: string | URL, init?: { body?: string }) => {
      const isIntrospection = String(input) === INTROSPECTION_ENDPOINT;
      if (isIntrospection) {
        introspected.push(new URLSearchParams(init?.body).get('token') ?? '');
      } else if (options.jwksDown) {
        return { ok: false, status: 503, json: async () => ({}), text: async () => '' };
      }
      const body = isIntrospection ? active : { keys: [publicJwk] };
      return { ok: true, status: 200, json: async () => body, text: async () => '' };
    }) as never;
    const guard = new ResourceGuard({
      resource: RESOURCE,
      authorizationServer: ISSUER,
      validationMode: 'introspection',
      introspectionClient: { clientId: 'rs', clientSecret: 's' },
      introspectionLocalCheck: options.introspectionLocalCheck,
      fetch,
    });
    return { guard, introspected };
  }

  // The AS rate-limits introspection per caller, and the caller is this RS.
  // A bearer the JWKS cannot verify can never be active, so it must be
  // refused locally rather than spend one of those calls: otherwise anyone
  // able to reach the RS could empty the budget with made-up bearers.
  it('refuses a bearer that fails local verification without introspecting it', async () => {
    const { guard, introspected } = introspectionGuard();
    await expect(guard.authenticate('Bearer junk-0')).rejects.toBeInstanceOf(InvalidTokenError);
    const other = await signToken({ sub: 'u', client_id: 'c' }, 'https://other.example.com');
    await expect(guard.authenticate(`Bearer ${other}`)).rejects.toBeInstanceOf(InvalidTokenError);
    expect(introspected).toEqual([]);
  });

  it('introspects a locally valid token and returns the introspection claims', async () => {
    const { guard, introspected } = introspectionGuard();
    const token = await signToken({ sub: 'u', client_id: 'c', scope: 'mcp:read' }, RESOURCE);
    const claims = await guard.authenticate(`Bearer ${token}`, ['mcp:read']);
    expect(introspected).toEqual([token]);
    expect(claims.sub).toBe('u');
    expect(claims.raw['active']).toBe(true);
  });

  // A JWKS outage is no verdict on the token: fall through to the
  // authoritative introspection call instead of answering 401 to everyone.
  it('falls through to introspection when the JWKS cannot be fetched', async () => {
    const { guard, introspected } = introspectionGuard({ jwksDown: true });
    const token = await signToken({ sub: 'u', client_id: 'c', scope: 'mcp:read' }, RESOURCE);
    const claims = await guard.authenticate(`Bearer ${token}`, ['mcp:read']);
    expect(introspected).toEqual([token]);
    expect(claims.sub).toBe('u');
  });

  it('introspects opaque tokens when the local check is turned off', async () => {
    const { guard, introspected } = introspectionGuard({ introspectionLocalCheck: false });
    const claims = await guard.authenticate('Bearer opaque-token-value', ['mcp:read']);
    expect(introspected).toEqual(['opaque-token-value']);
    expect(claims.sub).toBe('u');
  });
});

describe('ResourceGuard — requireAccessTokenTyp reaches the validator (#283)', () => {
  // Exercised through `ResourceGuardConfig`, NOT by constructing `JwtValidator`
  // directly as the validator's own suite does. The flag is inert unless the
  // guard threads it, and a config field that is declared but never forwarded
  // still type-checks — so only an end-to-end assertion proves the wiring.
  function guard(requireAccessTokenTyp?: boolean) {
    return new ResourceGuard({
      resource: RESOURCE,
      authorizationServer: ISSUER,
      ...(requireAccessTokenTyp !== undefined ? { requireAccessTokenTyp } : {}),
      fetch: jwksFetch({ keys: [publicJwk] }),
    });
  }

  it('rejects a typ-less token when the guard config sets the flag', async () => {
    // `signToken` stamps no `typ`, i.e. exactly what a pre-#283 AS mints.
    const token = await signToken({ sub: 'u', client_id: 'c' }, RESOURCE);
    await expect(guard(true).authenticate(`Bearer ${token}`)).rejects.toBeInstanceOf(
      InvalidTokenError
    );
  });

  it('accepts the same token when the flag is left at its default', async () => {
    const token = await signToken({ sub: 'u', client_id: 'c' }, RESOURCE);
    const claims = await guard().authenticate(`Bearer ${token}`);
    expect(claims.sub).toBe('u');
  });
});

describe('ResourceGuard.assertScopes', () => {
  const guard = new ResourceGuard({
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
