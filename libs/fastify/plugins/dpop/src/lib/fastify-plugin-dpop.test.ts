import { randomUUID } from 'node:crypto';

import { CACHE_PLUGIN_NAME } from '@qauth-labs/fastify-plugin-cache';
import Fastify, { type FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';
import { calculateJwkThumbprint, CompactSign, exportJWK, generateKeyPair, type JWK } from 'jose';
import { describe, expect, it } from 'vitest';

import { DpopProofError } from '../index';
import { DPOP_REPLAY_KEY_PREFIX, dpopPlugin, type DpopRequestCheck } from './fastify-plugin-dpop';

const ORIGIN = 'https://auth.example.com';

/** An in-memory `SET key value PX ms NX`, recording every key, or one that fails. */
function fakeRedis(options: { failing?: boolean } = {}) {
  const keys = new Map<string, number>();
  return {
    keys,
    async set(key: string, _value: string, _mode: 'PX', ttl: number) {
      if (options.failing) throw new Error('connection refused');
      if (keys.has(key)) return null;
      keys.set(key, ttl);
      return 'OK' as const;
    },
  };
}

async function buildApp(options: {
  enabled: boolean;
  redis?: ReturnType<typeof fakeRedis>;
  check?: DpopRequestCheck;
  baseUrl?: string;
}): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });
  await app.register(
    fp(
      async (instance) => {
        instance.decorate('redis', (options.redis ?? fakeRedis()) as never);
      },
      { name: CACHE_PLUGIN_NAME }
    )
  );
  await app.register(dpopPlugin, {
    enabled: options.enabled,
    baseUrl: options.baseUrl ?? ORIGIN,
  });
  app.setErrorHandler((error, _request, reply) => {
    if (error instanceof DpopProofError) {
      return reply.code(400).send({ error: error.error, reason: error.reason });
    }
    return reply.code(500).send({ error: String(error) });
  });
  app.post('/oauth/token', async (request) => {
    if (app.dpop === null) return { dpop: null };
    const { thumbprint } = await app.dpop.verifyRequest(request, options.check);
    return { thumbprint };
  });
  await app.ready();
  return app;
}

interface ProofKey {
  readonly privateKey: CryptoKey;
  readonly jwk: JWK;
  readonly thumbprint: string;
}

async function proofKey(): Promise<ProofKey> {
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
  const jwk = await exportJWK(publicKey);
  return { privateKey, jwk, thumbprint: await calculateJwkThumbprint(jwk, 'sha256') };
}

async function proof(key: ProofKey, claims: Record<string, unknown> = {}): Promise<string> {
  const payload = {
    jti: randomUUID(),
    htm: 'POST',
    htu: `${ORIGIN}/oauth/token`,
    iat: Math.floor(Date.now() / 1000),
    ...claims,
  };
  return new CompactSign(new TextEncoder().encode(JSON.stringify(payload)))
    .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: key.jwk })
    .sign(key.privateKey);
}

describe('dpopPlugin (#480)', () => {
  it('decorates fastify.dpop with null while DPOP_ENABLED is off, and reads no header', async () => {
    const app = await buildApp({ enabled: false });
    try {
      expect(app.dpop).toBeNull();
      const response = await app.inject({
        method: 'POST',
        url: '/oauth/token',
        headers: { dpop: 'not-a-proof' },
      });
      expect(response.json()).toEqual({ dpop: null });
    } finally {
      await app.close();
    }
  });

  it('verifies a proof against the configured origin and the request path', async () => {
    const redis = fakeRedis();
    const app = await buildApp({ enabled: true, redis });
    try {
      const key = await proofKey();
      const response = await app.inject({
        method: 'POST',
        // The query is not part of `htu` (RFC 9449 §4.3 step 9).
        url: '/oauth/token?x=1',
        headers: { dpop: await proof(key) },
      });
      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({ thumbprint: key.thumbprint });
      expect([...redis.keys.keys()]).toEqual([
        expect.stringMatching(new RegExp(`^${DPOP_REPLAY_KEY_PREFIX}[A-Za-z0-9_-]{43}$`)),
      ]);
      expect(app.dpop?.algorithms).toContain('ES256');
    } finally {
      await app.close();
    }
  });

  it('refuses a replayed proof', async () => {
    const app = await buildApp({ enabled: true });
    try {
      const dpop = await proof(await proofKey());
      const first = await app.inject({ method: 'POST', url: '/oauth/token', headers: { dpop } });
      const second = await app.inject({ method: 'POST', url: '/oauth/token', headers: { dpop } });
      expect(first.statusCode).toBe(200);
      expect(second.json()).toEqual({ error: 'invalid_dpop_proof', reason: 'replayed' });
    } finally {
      await app.close();
    }
  });

  it("compares htu with the configured origin, never the request's Host", async () => {
    const app = await buildApp({ enabled: true });
    try {
      const key = await proofKey();
      const response = await app.inject({
        method: 'POST',
        url: '/oauth/token',
        headers: {
          host: 'evil.example',
          dpop: await proof(key, { htu: 'https://evil.example/oauth/token' }),
        },
      });
      expect(response.json()).toEqual({ error: 'invalid_dpop_proof', reason: 'htu' });
    } finally {
      await app.close();
    }
  });

  it('compares htu with an issuer that carries a path, as discovery publishes the endpoint', async () => {
    const app = await buildApp({ enabled: true, baseUrl: `${ORIGIN}/tenant/` });
    try {
      const key = await proofKey();
      const withPath = await app.inject({
        method: 'POST',
        url: '/oauth/token',
        headers: { dpop: await proof(key, { htu: `${ORIGIN}/tenant/oauth/token` }) },
      });
      expect(withPath.json()).toEqual({ thumbprint: key.thumbprint });
      const withoutPath = await app.inject({
        method: 'POST',
        url: '/oauth/token',
        headers: { dpop: await proof(key) },
      });
      expect(withoutPath.json()).toEqual({ error: 'invalid_dpop_proof', reason: 'htu' });
    } finally {
      await app.close();
    }
  });

  it('refuses a request without a proof', async () => {
    const app = await buildApp({ enabled: true });
    try {
      const response = await app.inject({ method: 'POST', url: '/oauth/token' });
      expect(response.json()).toEqual({ error: 'invalid_dpop_proof', reason: 'missing-proof' });
    } finally {
      await app.close();
    }
  });

  it('refuses every proof while Redis fails', async () => {
    const app = await buildApp({ enabled: true, redis: fakeRedis({ failing: true }) });
    try {
      const response = await app.inject({
        method: 'POST',
        url: '/oauth/token',
        headers: { dpop: await proof(await proofKey()) },
      });
      expect(response.json()).toEqual({
        error: 'invalid_dpop_proof',
        reason: 'replay-store-unavailable',
      });
    } finally {
      await app.close();
    }
  });

  it('passes the expected thumbprint through: a proof under another key is refused', async () => {
    const bound = await proofKey();
    const app = await buildApp({ enabled: true, check: { expectedThumbprint: bound.thumbprint } });
    try {
      const other = await app.inject({
        method: 'POST',
        url: '/oauth/token',
        headers: { dpop: await proof(await proofKey()) },
      });
      expect(other.json()).toEqual({ error: 'invalid_dpop_proof', reason: 'key-mismatch' });
      const same = await app.inject({
        method: 'POST',
        url: '/oauth/token',
        headers: { dpop: await proof(bound) },
      });
      expect(same.json()).toEqual({ thumbprint: bound.thumbprint });
    } finally {
      await app.close();
    }
  });

  it('passes the access token through: a proof without its ath is refused', async () => {
    const app = await buildApp({ enabled: true, check: { accessToken: 'the-token' } });
    try {
      const response = await app.inject({
        method: 'POST',
        url: '/oauth/token',
        headers: { dpop: await proof(await proofKey()) },
      });
      expect(response.json()).toEqual({ error: 'invalid_dpop_proof', reason: 'ath' });
    } finally {
      await app.close();
    }
  });

  it('refuses to boot with an origin that is not an absolute http(s) URL', async () => {
    const app = Fastify({ logger: false });
    await app.register(
      fp(
        async (instance) => {
          instance.decorate('redis', fakeRedis() as never);
        },
        { name: CACHE_PLUGIN_NAME }
      )
    );
    await expect(
      (async () => {
        await app.register(dpopPlugin, { enabled: true, baseUrl: 'auth.example.com' });
        await app.ready();
      })()
    ).rejects.toThrow('must be an absolute http(s) URL');
    await app.close();
  });
});
