import { generateKeyPairSync } from 'node:crypto';

import { jwtPlugin } from '@qauth-labs/fastify-plugin-jwt';
import Fastify from 'fastify';
import { decodeProtectedHeader, importSPKI, jwtVerify } from 'jose';
import { describe, expect, it } from 'vitest';

import { bootAuthServer, generateJwtPem, REQUIRED_TEST_ENVIRONMENT } from '../testing/e2e-harness';
import { createMockVerifierPki, verifierIdentityEnvironment } from '../testing/mock-verifier-pki';

/**
 * THE TWO KEY SETS MUST NOT BE INTERCHANGEABLE (#298's risk note, #377 Phase A).
 *
 * QAuth now holds two kinds of private key at once, and they answer different
 * questions to different audiences:
 *
 * | key | proves | published at |
 * | --- | --- | --- |
 * | `JWT_PRIVATE_KEY` (+ optional RS256) | "QAuth issued this token" | `GET /.well-known/jwks.json` |
 * | `OID4VP_VERIFIER_SIGNING_KEY` | "QAuth is the Verifier in this request" | nowhere |
 *
 * A leak in either direction is a real vulnerability rather than an untidiness.
 * The verifier key appearing in the JWKS would invite a relying party to accept
 * an access token signed by it — a key whose only purpose is to identify QAuth
 * to a WALLET, held for the lifetime of an operator's certificate rather than
 * rotated with the token keys. A token key reaching the request-signing path
 * would put QAuth's issuance identity into an artifact every wallet in an
 * ecosystem receives.
 *
 * ## Why this suite provisions the verifier key
 *
 * The vacuity trap, stated plainly: a test that only inspects the DEFAULT JWKS
 * passes today for the wrong reason — a deployment with no P-256 key has none to
 * leak. So every deployment booted here HAS one, and the assertions are about
 * what the running server does with it.
 *
 * ## No containers, but an integration suite
 *
 * Nothing here opens a connection — the assertions are about key material and
 * signing. It lives under `*.integration.test.ts` for a different reason: the
 * only way to ask the REAL bootstrap what it publishes is to boot it, and
 * booting it needs `@fastify/autoload` inlined into Vite's module graph, which
 * only `vitest.integration.config.ts` does. A version of this suite that
 * assembled its own Fastify from `jwtPlugin` + the discovery routes would be
 * asserting about a server this repo does not ship.
 */

const pki = createMockVerifierPki();

/** A deployment that provisions BOTH key sets. */
async function bootWithVerifierIdentity() {
  const jwt = await generateJwtPem();

  return bootAuthServer({
    ...REQUIRED_TEST_ENVIRONMENT,
    // Syntactically valid and never dialled: nothing here issues a query.
    DATABASE_URL: 'postgresql://unused:unused@127.0.0.1:1/unused',
    REDIS_URL: 'redis://127.0.0.1:1/0',
    JWT_PRIVATE_KEY: jwt.privateKey,
    JWT_PUBLIC_KEY: jwt.publicKey,
    WALLET_FEDERATION_ENABLED: 'true',
    OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base',
    OID4VP_REQUESTED_VCT: 'https://credentials.example.com/pid',
    ...verifierIdentityEnvironment(pki),
  });
}

/**
 * The published set is read from `jwtUtils.getJwks()` rather than over HTTP.
 *
 * `GET /.well-known/jwks.json` sends that value VERBATIM — the route adds two
 * headers and nothing else, and `routes/well-known.test.ts` already pins the
 * pass-through against a stubbed `jwtUtils`. What that stub cannot check is what
 * the REAL bootstrap puts in the set, which is the question here. Going through
 * the socket instead would additionally require Redis, because the global rate
 * limiter is on the request path — a container this suite has no other reason to
 * start, for an assertion the two halves already make together.
 */
describe('the verifier key never reaches the published JWKS (#377)', () => {
  it('publishes no EC key at all, on a deployment that HAS one', async () => {
    const server = await bootWithVerifierIdentity();

    try {
      const { keys } = await server.app.jwtUtils.getJwks();

      expect(keys.length).toBeGreaterThan(0);

      for (const key of keys as unknown as Array<Record<string, unknown>>) {
        expect(key['kty']).not.toBe('EC');
        expect(key['crv']).not.toBe('P-256');
        expect(key['alg']).not.toBe('ES256');
      }
    } finally {
      await server.close();
    }
  });

  it("publishes nothing matching the verifier leaf's own public coordinates", async () => {
    // The strongest form of the assertion: not "no EC key" by shape, but "not
    // THIS key" by value. A future entry that carried the verifier key under a
    // mislabelled `kty` would still fail here.
    const server = await bootWithVerifierIdentity();

    try {
      const jwk = pki.leaf.publicKey.export({ format: 'jwk' }) as { x?: string; y?: string };
      const published = JSON.stringify(await server.app.jwtUtils.getJwks());

      expect(jwk.x).toBeDefined();
      expect(published).not.toContain(jwk.x as string);
      expect(published).not.toContain(jwk.y as string);
    } finally {
      await server.close();
    }
  });

  it('publishes only the EdDSA token key it was configured with', async () => {
    // The control that makes the two assertions above non-vacuous in the other
    // direction: the set is not empty and not accidentally filtered — it holds
    // exactly the key type QAuth signs its own tokens with.
    const server = await bootWithVerifierIdentity();

    try {
      const { keys } = await server.app.jwtUtils.getJwks();

      expect((keys as unknown as Array<Record<string, unknown>>).map((key) => key['kty'])).toEqual([
        'OKP',
      ]);
    } finally {
      await server.close();
    }
  });
});

describe('the verifier key cannot sign a QAuth access or ID token (#377)', () => {
  it('signs an access token with EdDSA, not ES256', async () => {
    const server = await bootWithVerifierIdentity();

    try {
      const token = await server.app.jwtUtils.signAccessToken({
        sub: 'user-1',
        clientId: 'client-1',
        scope: 'openid',
      });

      expect(decodeProtectedHeader(token).alg).toBe('EdDSA');
    } finally {
      await server.close();
    }
  });

  it('signs an ID token with EdDSA, not ES256', async () => {
    const server = await bootWithVerifierIdentity();

    try {
      const token = await server.app.jwtUtils.signIdToken({
        sub: 'user-1',
        audience: 'client-1',
      });

      expect(decodeProtectedHeader(token).alg).toBe('EdDSA');
    } finally {
      await server.close();
    }
  });

  it('issues tokens that do NOT verify under the verifier key', async () => {
    // What "cannot sign" means on the wire: a token the verifier key had
    // produced would verify under it. Neither of these does.
    const server = await bootWithVerifierIdentity();

    try {
      const verifierKey = await importSPKI(
        pki.leaf.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
        'ES256'
      );

      const accessToken = await server.app.jwtUtils.signAccessToken({
        sub: 'user-1',
        clientId: 'client-1',
      });
      const idToken = await server.app.jwtUtils.signIdToken({
        sub: 'user-1',
        audience: 'client-1',
      });

      await expect(jwtVerify(accessToken, verifierKey)).rejects.toThrow();
      await expect(jwtVerify(idToken, verifierKey)).rejects.toThrow();
    } finally {
      await server.close();
    }
  });
});

describe('the JWT plugin refuses the verifier key at ADMISSION (#377)', () => {
  it('will not accept a P-256 PEM as the token-signing key', async () => {
    // The structural half of the guarantee, and the one that holds even if a
    // future bootstrap wired the wrong variable through: every key-bearing
    // option on the JWT plugin is imported against a PINNED algorithm, so a
    // P-256 key cannot become a token signer by configuration mistake.
    const app = Fastify({ logger: false });

    await expect(
      app.register(jwtPlugin, {
        privateKey: pki.signingKeyPem,
        issuer: 'https://auth.example.com',
        accessTokenLifespan: 900,
        refreshTokenLifespan: 86400,
      })
    ).rejects.toThrow();

    await app.close();
  });

  it('accepts an Ed25519 key in the same slot — the refusal is about the key type', async () => {
    // The control. Without it the test above would pass for any registration
    // failure at all.
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const app = Fastify({ logger: false });

    await expect(
      app.register(jwtPlugin, {
        privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
        publicKey: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
        issuer: 'https://auth.example.com',
        accessTokenLifespan: 900,
        refreshTokenLifespan: 86400,
      })
    ).resolves.toBeDefined();

    await app.close();
  });
});
