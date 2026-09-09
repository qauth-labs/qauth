import Fastify from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';

/**
 * Mutable env stand-in so a test can flip a discovery feature flag
 * (`CIMD_ENABLED`, `ID_JAG_ENABLED`) without re-importing the route module.
 * Starts EMPTY on purpose: every flag reads as `undefined`, which must behave
 * exactly like `false` — that is the fail-closed default the ADR-011 gating
 * relies on.
 */
const { mockEnv } = vi.hoisted(() => ({ mockEnv: {} as Record<string, unknown> }));

vi.mock('../../config/env', () => ({
  env: mockEnv,
}));

import { ID_JAG_GRANT_PROFILE, JWT_BEARER_GRANT_TYPE } from '../schemas/oauth';
import wellKnownRoutes from './well-known';

afterEach(() => {
  for (const key of Object.keys(mockEnv)) delete mockEnv[key];
});

const ISSUER = 'https://auth.example.com';

/**
 * Build a Fastify app with only the discovery routes registered and a
 * stub `jwtUtils` exposing the two methods these routes rely on. This
 * keeps the test hermetic — no DB, no Redis, no key import.
 */
async function buildApp(overrides?: {
  jwks?: { keys: Array<Record<string, unknown>> };
  issuer?: string;
  idTokenSigningAlgValuesSupported?: string[];
}) {
  const app = Fastify({ logger: false });

  const jwks = overrides?.jwks ?? {
    keys: [
      {
        kty: 'OKP',
        crv: 'Ed25519',
        x: 'stub-x-value',
        use: 'sig',
        alg: 'EdDSA',
        kid: 'test-kid',
      },
    ],
  };

  app.decorate('jwtUtils', {
    getIssuer: () => overrides?.issuer ?? ISSUER,
    getJwks: async () => jwks,
    getIdTokenSigningAlgValuesSupported: () =>
      overrides?.idTokenSigningAlgValuesSupported ?? ['EdDSA'],
  } as unknown as never);

  await app.register(wellKnownRoutes);
  await app.ready();
  return app;
}

describe('GET /.well-known/oauth-authorization-server', () => {
  it('returns RFC 8414 §3 metadata with the expected shape and caching headers (§3.1 GET, §3.2 200 + application/json)', async () => {
    const app = await buildApp();
    try {
      const res = await app.inject({
        method: 'GET',
        url: '/.well-known/oauth-authorization-server',
      });

      expect(res.statusCode).toBe(200);
      expect(res.headers['cache-control']).toBe('public, max-age=3600');
      expect(res.headers['content-type']).toMatch(/application\/json/);

      const body = res.json() as Record<string, unknown>;
      expect(body['issuer']).toBe(ISSUER);
      expect(body['authorization_endpoint']).toBe(`${ISSUER}/oauth/authorize`);
      expect(body['token_endpoint']).toBe(`${ISSUER}/oauth/token`);
      expect(body['introspection_endpoint']).toBe(`${ISSUER}/oauth/introspect`);
      expect(body['userinfo_endpoint']).toBe(`${ISSUER}/oauth/userinfo`);
      expect(body['registration_endpoint']).toBe(`${ISSUER}/oauth/register`);
      expect(body['jwks_uri']).toBe(`${ISSUER}/.well-known/jwks.json`);
      expect(body['response_types_supported']).toEqual(['code']);
      expect(body['grant_types_supported']).toEqual(
        expect.arrayContaining(['authorization_code', 'client_credentials', 'refresh_token'])
      );
      expect(body['code_challenge_methods_supported']).toEqual(['S256']);
      expect(body['id_token_signing_alg_values_supported']).toEqual(['EdDSA']);
      // RFC 9207 §3 (#282): /oauth/authorize emits `iss` on every
      // authorization response, so the AS MUST advertise that it does.
      expect(body['authorization_response_iss_parameter_supported']).toBe(true);
      // #384: private_key_jwt is unflagged and always advertised, together with
      // the algorithms the assertion verifier will actually accept.
      expect(body['token_endpoint_auth_methods_supported']).toContain('private_key_jwt');
      expect(
        (body['token_endpoint_auth_signing_alg_values_supported'] as string[]).length
      ).toBeGreaterThan(0);
    } finally {
      await app.close();
    }
  });

  it('does not advertise ID-JAG when the flag is unset (fail-closed default, ADR-011)', async () => {
    // `mockEnv` is empty, so `env.ID_JAG_ENABLED` is undefined — the served
    // document must look exactly as it does with an explicit `false`.
    const app = await buildApp();
    try {
      const body = (
        await app.inject({ method: 'GET', url: '/.well-known/oauth-authorization-server' })
      ).json() as Record<string, unknown>;

      expect(body['grant_types_supported']).not.toContain(JWT_BEARER_GRANT_TYPE);
      expect('authorization_grant_profiles_supported' in body).toBe(false);
    } finally {
      await app.close();
    }
  });

  it('advertises the jwt-bearer grant and ID-JAG profile once ID_JAG_ENABLED is set', async () => {
    mockEnv['ID_JAG_ENABLED'] = true;
    const app = await buildApp();
    try {
      const body = (
        await app.inject({ method: 'GET', url: '/.well-known/oauth-authorization-server' })
      ).json() as Record<string, unknown>;

      expect(body['grant_types_supported']).toContain(JWT_BEARER_GRANT_TYPE);
      expect(body['authorization_grant_profiles_supported']).toEqual([ID_JAG_GRANT_PROFILE]);
    } finally {
      await app.close();
    }
  });

  it('derives endpoint URLs from the configured issuer (no trailing slash)', async () => {
    const app = await buildApp({ issuer: `${ISSUER}/` });
    try {
      const res = await app.inject({
        method: 'GET',
        url: '/.well-known/oauth-authorization-server',
      });
      const body = res.json() as Record<string, unknown>;
      expect(body['issuer']).toBe(ISSUER);
      expect(body['token_endpoint']).toBe(`${ISSUER}/oauth/token`);
    } finally {
      await app.close();
    }
  });
});

describe('GET /.well-known/openid-configuration', () => {
  it('returns an OIDC Discovery 1.0 §3 document superset of the AS metadata (§4 well-known path, §4.1 GET, §4.2 200 + application/json)', async () => {
    const app = await buildApp();
    try {
      const res = await app.inject({
        method: 'GET',
        url: '/.well-known/openid-configuration',
      });

      expect(res.statusCode).toBe(200);
      expect(res.headers['cache-control']).toBe('public, max-age=3600');

      const body = res.json() as Record<string, unknown>;
      expect(body['issuer']).toBe(ISSUER);
      expect(body['jwks_uri']).toBe(`${ISSUER}/.well-known/jwks.json`);
      expect(body['subject_types_supported']).toEqual(['public']);
      expect(body['claims_supported']).toEqual(
        expect.arrayContaining(['sub', 'email', 'email_verified', 'name', 'nonce'])
      );
      // EdDSA is the only ID-token signing algorithm advertised (OIDC Core §16).
      expect(body['id_token_signing_alg_values_supported']).toEqual(['EdDSA']);
      // #282: the RFC 9207 flag is inherited from the AS metadata, so a client
      // that reads only the OIDC document still learns `iss` is validatable.
      expect(body['authorization_response_iss_parameter_supported']).toBe(true);
    } finally {
      await app.close();
    }
  });

  it('advertises RS256 + EdDSA when the plugin reports an RS256 key is configured (#309)', async () => {
    const app = await buildApp({ idTokenSigningAlgValuesSupported: ['RS256', 'EdDSA'] });
    try {
      const res = await app.inject({
        method: 'GET',
        url: '/.well-known/openid-configuration',
      });
      const body = res.json() as Record<string, unknown>;
      // Discovery reflects exactly what the plugin can produce keys for; when an
      // RS256 key is present RS256 is advertised (and listed first, the default).
      expect(body['id_token_signing_alg_values_supported']).toEqual(['RS256', 'EdDSA']);
    } finally {
      await app.close();
    }
  });
});

describe('GET /.well-known/jwks.json', () => {
  it('serves the JWKS from fastify.jwtUtils.getJwks with the proper media type', async () => {
    const app = await buildApp();
    try {
      const res = await app.inject({
        method: 'GET',
        url: '/.well-known/jwks.json',
      });

      expect(res.statusCode).toBe(200);
      expect(res.headers['cache-control']).toBe('public, max-age=3600');
      expect(res.headers['content-type']).toMatch(/application\/jwk-set\+json/);

      const body = res.json() as { keys: Array<Record<string, unknown>> };
      expect(body.keys).toHaveLength(1);
      const [jwk] = body.keys;
      expect(jwk['alg']).toBe('EdDSA');
      expect(jwk['use']).toBe('sig');
      expect(jwk['kid']).toBe('test-kid');
      expect(jwk).not.toHaveProperty('d');
    } finally {
      await app.close();
    }
  });

  it('passes through whatever jwtUtils.getJwks returns (preserves rotation keys)', async () => {
    // Multi-key JWKS — simulates a retired key still being served during
    // rotation so in-flight tokens keep verifying. End-to-end signature
    // verification against a real keypair is covered in the JWT plugin
    // and `libs/server/jwt` unit tests to avoid a direct `jose` dep here.
    const multiKeyJwks = {
      keys: [
        {
          kty: 'OKP',
          crv: 'Ed25519',
          x: 'active-key-x',
          use: 'sig',
          alg: 'EdDSA',
          kid: 'active',
        },
        {
          kty: 'OKP',
          crv: 'Ed25519',
          x: 'retired-key-x',
          use: 'sig',
          alg: 'EdDSA',
          kid: 'retired',
        },
      ],
    };

    const app = await buildApp({ jwks: multiKeyJwks });
    try {
      const res = await app.inject({ method: 'GET', url: '/.well-known/jwks.json' });
      expect(res.statusCode).toBe(200);

      const served = res.json() as { keys: Array<Record<string, unknown>> };
      expect(served.keys).toHaveLength(2);
      expect(served.keys.map((k) => k['kid'])).toEqual(['active', 'retired']);
    } finally {
      await app.close();
    }
  });
});
