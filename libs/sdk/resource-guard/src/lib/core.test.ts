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

  // RFC 9449 §7.2: no proof is verified here, so a bound token is refused.
  it('refuses a DPoP-bound token sent under Bearer as invalid_token', async () => {
    const token = await signToken(
      { sub: 'u', client_id: 'c', scope: 'mcp:read', cnf: { jkt: 'thumbprint' } },
      RESOURCE
    );
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
    options: {
      jwksDown?: boolean;
      introspectionLocalCheck?: boolean;
      introspectionBody?: Record<string, unknown>;
    } = {}
  ) {
    const introspected: string[] = [];
    const active = options.introspectionBody ?? {
      active: true,
      sub: 'u',
      client_id: 'c',
      scope: 'mcp:read',
      aud: RESOURCE,
    };
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

  // RFC 9449 §7.2. What QAuth's introspection endpoint answers for a
  // DPoP-bound token; the SDK verifies no proof, so it must refuse it.
  const BOUND = {
    active: true,
    sub: 'u',
    client_id: 'c',
    scope: 'mcp:read',
    aud: RESOURCE,
    token_type: 'DPoP',
    cnf: { jkt: 'thumbprint' },
  };

  it('refuses a DPoP-bound JWT at the local check, without introspecting it', async () => {
    const { guard, introspected } = introspectionGuard({ introspectionBody: BOUND });
    const token = await signToken(
      { sub: 'u', client_id: 'c', scope: 'mcp:read', cnf: { jkt: 'thumbprint' } },
      RESOURCE
    );
    await expect(guard.authenticate(`Bearer ${token}`)).rejects.toThrow(/DPoP-bound/);
    expect(introspected).toEqual([]);
  });

  it('refuses a DPoP-bound token the introspection reports, when the JWKS is down', async () => {
    const { guard, introspected } = introspectionGuard({
      jwksDown: true,
      introspectionBody: BOUND,
    });
    const token = await signToken(
      { sub: 'u', client_id: 'c', scope: 'mcp:read', cnf: { jkt: 'thumbprint' } },
      RESOURCE
    );
    await expect(guard.authenticate(`Bearer ${token}`)).rejects.toBeInstanceOf(InvalidTokenError);
    expect(introspected).toEqual([token]);
  });

  it('refuses a DPoP-bound opaque token when the local check is turned off', async () => {
    const { guard } = introspectionGuard({
      introspectionLocalCheck: false,
      introspectionBody: BOUND,
    });
    await expect(guard.authenticate('Bearer opaque-bound')).rejects.toThrow(/DPoP-bound/);
  });
});

describe('ResourceGuard.authenticate — the DPoP scheme is not accepted', () => {
  function guard(requiredScopes: string[] = []) {
    return new ResourceGuard({
      resource: RESOURCE,
      authorizationServer: ISSUER,
      requiredScopes,
      fetch: jwksFetch({ keys: [publicJwk] }),
    });
  }

  // RFC 6750 §3.1: a request that "attempted using an unsupported
  // authentication method" gets the credential-absent answer, with no error
  // code. The message names the scheme so a host's logs show why.
  it.each(['DPoP', 'dpop', 'DPOP'])(
    'answers the %s scheme as a missing bearer, naming the scheme',
    async (scheme) => {
      const token = await signToken({ sub: 'u', client_id: 'c', scope: 'mcp:read' }, RESOURCE);
      const rejection = guard(['mcp:read']).authenticate(`${scheme} ${token}`);
      await expect(rejection).rejects.toBeInstanceOf(MissingTokenError);
      await expect(rejection).rejects.toMatchObject({
        message:
          'The DPoP authorization scheme is not supported; this resource accepts unbound Bearer tokens only',
        requiredScopes: ['mcp:read'],
      });
    }
  );

  it('keeps the generic message for other schemes', async () => {
    await expect(guard().authenticate('Basic abc')).rejects.toThrow('No bearer token presented');
    await expect(guard().authenticate('DPoPabc')).rejects.toThrow('No bearer token presented');
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

// #1088 — a guard that does not set `scopesSupported` must answer exactly as
// 0.2.2 does. The literals below are what 0.2.2 gives; the 401 and 403 of each
// configuration, the `DPoP` scheme's 401 and the scopes each error carries.
describe('ResourceGuard — challenges without scopesSupported are those of 0.2.2', () => {
  const METADATA = `resource_metadata="${RESOURCE}/.well-known/oauth-protected-resource"`;
  const unscoped: ValidatedToken = { scopes: [], audience: [RESOURCE], raw: {} };

  const cases: {
    requiredScopes?: string[];
    scopes: string[];
    named: string[];
    unauthenticated: string;
    insufficient: string | null;
  }[] = [
    { scopes: [], named: [], unauthenticated: `Bearer ${METADATA}`, insufficient: null },
    {
      scopes: ['mcp:admin'],
      named: ['mcp:admin'],
      unauthenticated: `Bearer scope="mcp:admin", ${METADATA}`,
      insufficient: `Bearer error="insufficient_scope", scope="mcp:admin", ${METADATA}`,
    },
    {
      requiredScopes: ['mcp:read'],
      scopes: [],
      named: ['mcp:read'],
      unauthenticated: `Bearer scope="mcp:read", ${METADATA}`,
      insufficient: `Bearer error="insufficient_scope", scope="mcp:read", ${METADATA}`,
    },
    {
      requiredScopes: ['mcp:read', 'offline_access', 'mcp:read'],
      scopes: [],
      named: ['mcp:read', 'offline_access'],
      unauthenticated: `Bearer scope="mcp:read", ${METADATA}`,
      insufficient: `Bearer error="insufficient_scope", scope="mcp:read", ${METADATA}`,
    },
    {
      requiredScopes: ['mcp:read', 'offline_access', 'mcp:read'],
      scopes: ['mcp:admin', 'mcp:read'],
      named: ['mcp:read', 'offline_access', 'mcp:admin'],
      unauthenticated: `Bearer scope="mcp:read mcp:admin", ${METADATA}`,
      insufficient: `Bearer error="insufficient_scope", scope="mcp:read mcp:admin", ${METADATA}`,
    },
  ];

  it.each(cases)(
    'requiredScopes $requiredScopes, call scopes $scopes',
    async ({ requiredScopes, scopes, named, unauthenticated, insufficient }) => {
      const guard = new ResourceGuard({
        resource: RESOURCE,
        authorizationServer: ISSUER,
        ...(requiredScopes ? { requiredScopes } : {}),
        fetch: jwksFetch({ keys: [publicJwk] }),
      });

      for (const authorization of [undefined, 'DPoP abc']) {
        const missing = await guard.authenticate(authorization, scopes).then(
          () => expect.unreachable('should have thrown'),
          (error: unknown) => error
        );
        expect(missing).toBeInstanceOf(MissingTokenError);
        expect((missing as MissingTokenError).requiredScopes).toEqual(named);
        expect(guard.challengeHeader(missing as MissingTokenError)).toBe(unauthenticated);
      }

      if (insufficient === null) {
        expect(() => guard.assertScopes(unscoped, scopes)).not.toThrow();
        return;
      }
      try {
        guard.assertScopes(unscoped, scopes);
        expect.unreachable('should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(InsufficientScopeError);
        expect((error as InsufficientScopeError).requiredScopes).toEqual(named);
        expect(guard.challengeHeader(error as InsufficientScopeError)).toBe(insufficient);
      }
    }
  );
});

// #1088 — a resource whose operations each need their own scope (an MCP
// server with one scope per tool): none is required of every request, and
// every one is advertised.
describe('ResourceGuard — scopesSupported', () => {
  const METADATA = `resource_metadata="${RESOURCE}/.well-known/oauth-protected-resource"`;
  const TOOL_SCOPES = ['notes:read', 'notes:write', 'notes:delete'];

  function guard(config: { requiredScopes?: string[]; scopesSupported?: string[] }) {
    return new ResourceGuard({
      resource: RESOURCE,
      authorizationServer: ISSUER,
      ...config,
      fetch: jwksFetch({ keys: [publicJwk] }),
    });
  }

  async function missingTokenError(
    target: ResourceGuard,
    authorization: string | undefined,
    scopes?: string[]
  ): Promise<MissingTokenError> {
    const error = await target.authenticate(authorization, scopes).then(
      () => expect.unreachable('should have thrown'),
      (rejection: unknown) => rejection
    );
    expect(error).toBeInstanceOf(MissingTokenError);
    return error as MissingTokenError;
  }

  it('refuses a requiredScopes entry missing from scopesSupported', () => {
    expect(() =>
      guard({ requiredScopes: ['notes:read', 'mcp:admin'], scopesSupported: TOOL_SCOPES })
    ).toThrow(ResourceGuardConfigError);
    expect(() =>
      guard({ requiredScopes: ['notes:read', 'mcp:admin'], scopesSupported: TOOL_SCOPES })
    ).toThrow('`scopesSupported` must hold every `requiredScopes` entry; missing: mcp:admin');
    // An empty list leaves out every default.
    expect(() => guard({ requiredScopes: ['notes:read'], scopesSupported: [] })).toThrow(
      ResourceGuardConfigError
    );
  });

  it('accepts a scopesSupported holding every requiredScopes entry, in any order', () => {
    expect(
      guard({ requiredScopes: ['notes:write', 'notes:read'], scopesSupported: TOOL_SCOPES })
        .scopesSupported
    ).toEqual(TOOL_SCOPES);
  });

  it('defaults to requiredScopes', () => {
    expect(guard({ requiredScopes: ['notes:read'] }).scopesSupported).toEqual(['notes:read']);
    expect(guard({}).scopesSupported).toEqual([]);
  });

  it('accepts a token that carries none of the supported scopes', async () => {
    const perTool = guard({ scopesSupported: TOOL_SCOPES });
    for (const claims of [{ sub: 'u' }, { sub: 'u', scope: 'other:scope' }]) {
      const token = await signToken(claims, RESOURCE);
      expect((await perTool.authenticate(`Bearer ${token}`)).sub).toBe('u');
    }
  });

  it('lists every supported scope in the metadata', () => {
    expect(
      guard({ scopesSupported: TOOL_SCOPES }).getProtectedResourceMetadata().scopes_supported
    ).toEqual(TOOL_SCOPES);
  });

  it('names every supported scope on the 401 of a call with no per-operation scopes', async () => {
    const perTool = guard({ scopesSupported: TOOL_SCOPES });
    const challenge = `Bearer scope="notes:read notes:write notes:delete", ${METADATA}`;
    for (const authorization of [undefined, 'DPoP abc', 'Basic abc']) {
      const error = await missingTokenError(perTool, authorization);
      expect(error.requiredScopes).toEqual(TOOL_SCOPES);
      expect(perTool.challengeHeader(error)).toBe(challenge);
    }
    expect(perTool.challengeHeader(await missingTokenError(perTool, undefined, []))).toBe(
      challenge
    );
  });

  it('names the per-operation scopes and requiredScopes when the call passes some', async () => {
    const perTool = guard({ scopesSupported: TOOL_SCOPES });
    const write = await missingTokenError(perTool, undefined, ['notes:write']);
    expect(write.requiredScopes).toEqual(['notes:write']);
    expect(perTool.challengeHeader(write)).toBe(`Bearer scope="notes:write", ${METADATA}`);

    const withDefault = guard({ requiredScopes: ['notes:read'], scopesSupported: TOOL_SCOPES });
    const both = await missingTokenError(withDefault, undefined, ['notes:delete']);
    expect(withDefault.challengeHeader(both)).toBe(
      `Bearer scope="notes:read notes:delete", ${METADATA}`
    );
  });

  it('names only the asserted scope in the 403 of assertScopes', async () => {
    const perTool = guard({ scopesSupported: TOOL_SCOPES });
    const claims = await perTool.authenticate(`Bearer ${await signToken({ sub: 'u' }, RESOURCE)}`);
    try {
      perTool.assertScopes(claims, ['notes:write']);
      expect.unreachable('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(InsufficientScopeError);
      expect((error as InsufficientScopeError).requiredScopes).toEqual(['notes:write']);
      expect(perTool.challengeHeader(error as InsufficientScopeError)).toBe(
        `Bearer error="insufficient_scope", scope="notes:write", ${METADATA}`
      );
    }
  });

  it('requires requiredScopes and the per-call scopes only', async () => {
    const withDefault = guard({ requiredScopes: ['notes:read'], scopesSupported: TOOL_SCOPES });
    const reader = await signToken({ sub: 'u', scope: 'notes:read' }, RESOURCE);
    expect((await withDefault.authenticate(`Bearer ${reader}`)).sub).toBe('u');

    const nobody = await signToken({ sub: 'u' }, RESOURCE);
    await expect(withDefault.authenticate(`Bearer ${nobody}`)).rejects.toMatchObject({
      requiredScopes: ['notes:read'],
      missingScopes: ['notes:read'],
    });
    await expect(
      withDefault.authenticate(`Bearer ${reader}`, ['notes:write'])
    ).rejects.toMatchObject({
      requiredScopes: ['notes:read', 'notes:write'],
      missingScopes: ['notes:write'],
    });
  });

  it('de-duplicates scopesSupported and keeps offline_access out of what it advertises', async () => {
    const perTool = guard({
      scopesSupported: ['notes:read', 'offline_access', 'notes:write', 'notes:read'],
    });
    expect(perTool.scopesSupported).toEqual(['notes:read', 'offline_access', 'notes:write']);
    expect(perTool.getProtectedResourceMetadata().scopes_supported).toEqual([
      'notes:read',
      'notes:write',
    ]);
    expect(perTool.challengeHeader(await missingTokenError(perTool, undefined))).toBe(
      `Bearer scope="notes:read notes:write", ${METADATA}`
    );
  });
});
