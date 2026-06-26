/**
 * OIDC conformance validator suite (T3, issue #121).
 *
 * A self-contained suite that exercises the OIDC surface end to end WITHOUT an
 * external certification service:
 *
 *  1. Discovery (`/.well-known/openid-configuration`) advertises the OIDC
 *     fields a relying party needs (issuer, jwks_uri, signing alg, claims).
 *  2. JWKS (`/.well-known/jwks.json`) publishes the EdDSA public key.
 *  3. The token endpoint's ID token (minted here via the real `jwtUtils`
 *     plugin) decodes and validates against the server's published key —
 *     correct `iss`, `aud`, `exp`/`iat`, echoed `nonce`, and identity claims
 *     (OIDC Core 1.0 §2, §3.1.3.6, §3.1.3.7).
 *
 * The jwt plugin and discovery builder used here are the SAME ones the
 * production routes use, so a green run asserts real conformance of the wiring
 * — only the HTTP framing around them is reconstructed for hermeticity.
 *
 * Crypto stays inside the jwt plugin per the project's security boundary: the
 * test signs and verifies through `app.jwtUtils` and only generates a raw
 * Ed25519 key pair (via `node:crypto`) to seed the plugin. It deliberately
 * does NOT import `jose` or `@qauth-labs/server-jwt` directly, keeping within
 * the auth-server dependency graph.
 *
 * Known gaps (documented per #121): no external OpenID certification run; no
 * `at_hash`/`c_hash` (OIDC Core §3.3.2.11, only required for hybrid/implicit
 * which QAuth does not support); userinfo signed-response JWTs are not offered
 * (`userinfo_signing_alg_values_supported` intentionally absent). ID token
 * signature verification is asserted via `jwtUtils.verifyAccessToken` (the
 * same EdDSA public key the JWKS publishes) plus a cross-key rejection test,
 * rather than re-importing the JWK in the test process.
 */
import { generateKeyPairSync } from 'node:crypto';

import { jwtPlugin } from '@qauth-labs/fastify-plugin-jwt';
import { JWTInvalidError } from '@qauth-labs/shared-errors';
import Fastify, { type FastifyInstance } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

vi.mock('../../../config/env', () => ({
  env: { CIMD_ENABLED: false },
}));

import wellKnownRoutes from '../well-known';

const ISSUER = 'https://auth.test.example.com';
const CLIENT_ID = 'test-client-oidc';
const ACCESS_TOKEN_LIFESPAN = 900;

/** Generate a fresh extractable Ed25519 key pair as PEM strings. */
function generateEd25519Pem(): { privateKeyPem: string; publicKeyPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
}

/**
 * Build a Fastify app with the REAL jwt plugin (keyed by a fresh EdDSA pair)
 * and the production discovery routes.
 */
async function buildApp(): Promise<FastifyInstance> {
  const { privateKeyPem, publicKeyPem } = generateEd25519Pem();

  const app = Fastify({ logger: false });
  await app.register(jwtPlugin, {
    privateKey: privateKeyPem,
    publicKey: publicKeyPem,
    issuer: ISSUER,
    accessTokenLifespan: ACCESS_TOKEN_LIFESPAN,
    refreshTokenLifespan: 86400,
  });
  await app.register(wellKnownRoutes);
  await app.ready();

  return app;
}

/** Fetch and parse the OIDC discovery document via HTTP inject. */
async function fetchDiscovery(app: FastifyInstance): Promise<Record<string, unknown>> {
  const res = await app.inject({ method: 'GET', url: '/.well-known/openid-configuration' });
  expect(res.statusCode).toBe(200);
  return res.json() as Record<string, unknown>;
}

/** Fetch the JWKS via HTTP inject. */
async function fetchJwks(app: FastifyInstance): Promise<{ keys: Array<Record<string, unknown>> }> {
  const res = await app.inject({ method: 'GET', url: '/.well-known/jwks.json' });
  expect(res.statusCode).toBe(200);
  return res.json() as { keys: Array<Record<string, unknown>> };
}

/**
 * Decode the JWT payload segment WITHOUT verifying (test-only). Used to assert
 * claim presence/absence after signature verification has already established
 * authenticity. Avoids the plugin's `decodeTokenUnsafe`, which requires an
 * `email` claim and would reject a name-less ID token.
 */
function decodeClaims(token: string): Record<string, unknown> {
  const [, payload] = token.split('.');
  return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
}

describe('OIDC conformance — discovery document', () => {
  it('advertises the issuer, endpoints, and JWKS URI consistently', async () => {
    const app = await buildApp();
    try {
      const doc = await fetchDiscovery(app);
      expect(doc['issuer']).toBe(ISSUER);
      expect(doc['authorization_endpoint']).toBe(`${ISSUER}/oauth/authorize`);
      expect(doc['token_endpoint']).toBe(`${ISSUER}/oauth/token`);
      expect(doc['userinfo_endpoint']).toBe(`${ISSUER}/oauth/userinfo`);
      expect(doc['jwks_uri']).toBe(`${ISSUER}/.well-known/jwks.json`);
    } finally {
      await app.close();
    }
  });

  it('declares EdDSA as the only ID token signing algorithm', async () => {
    const app = await buildApp();
    try {
      const doc = await fetchDiscovery(app);
      expect(doc['id_token_signing_alg_values_supported']).toEqual(['EdDSA']);
      expect(doc['response_types_supported']).toEqual(['code']);
      expect(doc['code_challenge_methods_supported']).toEqual(['S256']);
      expect(doc['subject_types_supported']).toEqual(['public']);
    } finally {
      await app.close();
    }
  });

  it('lists the claims emitted in the ID token / userinfo', async () => {
    const app = await buildApp();
    try {
      const doc = await fetchDiscovery(app);
      expect(doc['claims_supported']).toEqual(
        expect.arrayContaining([
          'sub',
          'iss',
          'aud',
          'exp',
          'iat',
          'nonce',
          'email',
          'email_verified',
          'name',
        ])
      );
    } finally {
      await app.close();
    }
  });
});

describe('OIDC conformance — JWKS', () => {
  it('publishes an EdDSA Ed25519 public verification key without the private component', async () => {
    const app = await buildApp();
    try {
      const jwks = await fetchJwks(app);
      expect(jwks.keys).toHaveLength(1);
      const [jwk] = jwks.keys;
      expect(jwk['kty']).toBe('OKP');
      expect(jwk['crv']).toBe('Ed25519');
      expect(jwk['use']).toBe('sig');
      expect(jwk['alg']).toBe('EdDSA');
      // The private component MUST NOT be exposed (RFC 7517 §4).
      expect(jwk['d']).toBeUndefined();
      // The public component MUST be present so relying parties can verify.
      expect(typeof jwk['x']).toBe('string');
    } finally {
      await app.close();
    }
  });
});

describe('OIDC conformance — ID token validation against the published key', () => {
  it('mints an ID token that verifies against the server key with all required claims', async () => {
    const app = await buildApp();
    try {
      const nonce = 'n-0S6_WzA2Mj';
      // Mint via the SAME jwtUtils the token endpoint uses.
      const idToken = await app.jwtUtils.signIdToken({
        sub: 'user-uuid-1',
        audience: CLIENT_ID,
        email: 'user@example.com',
        email_verified: true,
        name: 'Ada Lovelace',
        nonce,
      });

      // The JWKS publishes the public half of the signing key. Verify the
      // token through jwtUtils (same EdDSA key) asserting the client's own
      // client_id as the expected audience (OIDC Core §3.1.3.7.3).
      const jwks = await fetchJwks(app);
      expect(jwks.keys).toHaveLength(1);

      const payload = await app.jwtUtils.verifyAccessToken(idToken, { audience: CLIENT_ID });

      // §3.1.3.7.6/7: iss + aud validated.
      expect(payload.iss).toBe(ISSUER);
      expect(payload.aud).toBe(CLIENT_ID);
      expect(payload.sub).toBe('user-uuid-1');
      // §3.1.3.7.9/10: exp present and in the future; iat present.
      expect(typeof payload.exp).toBe('number');
      expect(typeof payload.iat).toBe('number');
      expect((payload.exp as number) > Math.floor(Date.now() / 1000)).toBe(true);
      // §3.1.3.6: nonce echoed verbatim.
      const claims = decodeClaims(idToken);
      expect(claims['nonce']).toBe(nonce);
      // Identity claims + token-confusion marker.
      expect(payload.email).toBe('user@example.com');
      expect(payload.email_verified).toBe(true);
      expect(claims['name']).toBe('Ada Lovelace');
      expect(claims['token_use']).toBe('id');
    } finally {
      await app.close();
    }
  });

  it('omits nonce/name/email when not supplied to the signer', async () => {
    const app = await buildApp();
    try {
      const idToken = await app.jwtUtils.signIdToken({
        sub: 'user-uuid-2',
        audience: CLIENT_ID,
      });

      const claims = decodeClaims(idToken);
      expect(claims['nonce']).toBeUndefined();
      expect(claims['name']).toBeUndefined();
      expect(claims['email']).toBeUndefined();
      expect(claims['sub']).toBe('user-uuid-2');
      expect(claims['aud']).toBe(CLIENT_ID);
    } finally {
      await app.close();
    }
  });

  it('rejects an ID token whose audience does not match the relying party', async () => {
    const app = await buildApp();
    try {
      const idToken = await app.jwtUtils.signIdToken({
        sub: 'user-uuid-3',
        audience: CLIENT_ID,
      });

      // A different client_id as the expected audience MUST fail (OIDC Core
      // §3.1.3.7.3 — the client MUST verify aud contains its own client_id).
      await expect(
        app.jwtUtils.verifyAccessToken(idToken, { audience: 'some-other-client' })
      ).rejects.toThrow(JWTInvalidError);
    } finally {
      await app.close();
    }
  });

  it('rejects an ID token signed by a different server key (foreign signature)', async () => {
    const app = await buildApp();
    const otherApp = await buildApp(); // independent key pair
    try {
      // Mint on the OTHER server, then attempt to verify against THIS server's
      // key — a relying party bound to this server's JWKS must reject it.
      const foreignIdToken = await otherApp.jwtUtils.signIdToken({
        sub: 'user-uuid-4',
        audience: CLIENT_ID,
      });

      await expect(
        app.jwtUtils.verifyAccessToken(foreignIdToken, { audience: CLIENT_ID })
      ).rejects.toThrow(JWTInvalidError);
    } finally {
      await app.close();
      await otherApp.close();
    }
  });
});
