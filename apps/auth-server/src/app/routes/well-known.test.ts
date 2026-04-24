import Fastify from 'fastify';
import { describe, expect, it, vi } from 'vitest';

vi.mock('../../config/env', () => ({
  env: {},
}));

import wellKnownRoutes from './well-known';

const ISSUER = 'https://auth.example.com';

/**
 * Build a Fastify app with only the discovery routes registered and a
 * stub `jwtUtils` exposing the two methods these routes rely on. This
 * keeps the test hermetic — no DB, no Redis, no key import.
 */
async function buildApp(overrides?: {
  jwks?: { keys: Array<Record<string, unknown>> };
  issuer?: string;
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
  } as unknown as never);

  await app.register(wellKnownRoutes);
  await app.ready();
  return app;
}

describe('GET /.well-known/oauth-authorization-server', () => {
  it('returns RFC 8414 metadata with the expected shape and caching headers', async () => {
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
  it('returns an OIDC Discovery document superset of the AS metadata', async () => {
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
        expect.arrayContaining(['sub', 'email', 'email_verified'])
      );
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
