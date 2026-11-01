import formbody from '@fastify/formbody';
import Fastify, { type FastifyInstance } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { type Mock, vi } from 'vitest';

import { securityHeadersPlugin } from '../app/plugins/security-headers';
import verifyApiRoute from '../app/routes/auth/verify';
import verifyPageRoute from '../app/routes/auth/verify-page';
import uiVerifyRoute from '../app/routes/ui/verify';
import { createFakeCookieSigner } from './cookie-keys';
import { testPolicyStore } from './realm-policies';
import { supplyRequestRealm, testRealm } from './request-realm';

/** The token row a known token resolves to. */
export function verificationTokenFixture(overrides: Record<string, unknown> = {}) {
  return {
    id: 'token-1',
    tokenHash: 'hashed',
    userId: 'user-1',
    credentialId: 'cred-1',
    expiresAt: Date.now() + 3600_000,
    used: false,
    ...overrides,
  };
}

/** The password credential the token targets. */
export function passwordCredentialFixture(overrides: Record<string, unknown> = {}) {
  return {
    id: 'cred-1',
    userId: 'user-1',
    realmId: 'realm-1',
    providerType: 'password',
    externalSub: 'user@example.com',
    credentialData: { password_hash: 'hash', email_verified: false },
    ...overrides,
  };
}

/**
 * In-memory Redis with the commands the failed-login helper uses (ttl, incr,
 * decr, expire, set with EX and optional NX, del).
 */
export function createMemoryRedis() {
  const store = new Map<string, string>();
  const ttls = new Map<string, number>();
  return {
    ttl: vi.fn(async (key: string) => (store.has(key) ? (ttls.get(key) ?? -1) : -2)),
    incr: vi.fn(async (key: string) => {
      const next = Number(store.get(key) ?? '0') + 1;
      store.set(key, String(next));
      return next;
    }),
    decr: vi.fn(async (key: string) => {
      const next = Number(store.get(key) ?? '0') - 1;
      store.set(key, String(next));
      return next;
    }),
    expire: vi.fn(async (key: string, seconds: number) => {
      if (!store.has(key)) return 0;
      ttls.set(key, seconds);
      return 1;
    }),
    set: vi.fn(async (key: string, value: string, _ex: 'EX', seconds: number, nx?: 'NX') => {
      if (nx === 'NX' && store.has(key)) return null;
      store.set(key, value);
      ttls.set(key, seconds);
      return 'OK';
    }),
    del: vi.fn(async (...keys: string[]) => {
      let count = 0;
      for (const key of keys) {
        if (store.delete(key)) count++;
        ttls.delete(key);
      }
      return count;
    }),
    _store: store,
    _ttls: ttls,
  };
}

/** The decorations the verification routes read, as mocks a test can steer. */
export interface EmailVerificationStubs {
  readonly findByTokenHash: Mock;
  readonly markUsed: Mock;
  readonly findCredentialById: Mock;
  readonly setEmailVerified: Mock;
  readonly setVerified: Mock;
  readonly findUserById: Mock;
  readonly hashToken: Mock;
  readonly verifyPassword: Mock;
  readonly transaction: Mock;
  readonly redis: ReturnType<typeof createMemoryRedis>;
}

/**
 * A Fastify instance with the three routes at `/auth/verify` and `/ui/verify`
 * — the JSON API, the mailed link's page and its form — behind the real
 * security headers (#113), form-body parser and Zod compilers, with the realm
 * resolver's decoration and the database, Redis and password hasher stubbed.
 *
 * No error handler of the app's: Fastify's own answers a thrown domain error
 * with its `statusCode`, which is all a test comparing the JSON route's status
 * with the form's needs.
 */
export async function buildEmailVerificationApp(): Promise<{
  app: FastifyInstance;
  stubs: EmailVerificationStubs;
}> {
  const app = Fastify({ logger: false });
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);
  await app.register(securityHeadersPlugin);
  await app.register(formbody);
  supplyRequestRealm(app, testRealm({ id: 'realm-1' }));

  const stubs: EmailVerificationStubs = {
    findByTokenHash: vi.fn().mockResolvedValue(verificationTokenFixture()),
    markUsed: vi.fn().mockResolvedValue({ id: 'token-1' }),
    findCredentialById: vi.fn().mockResolvedValue(passwordCredentialFixture()),
    setEmailVerified: vi.fn().mockResolvedValue({}),
    setVerified: vi.fn().mockResolvedValue({ id: 'attr-1' }),
    findUserById: vi.fn(async (id: string) => ({ id, enabled: true })),
    hashToken: vi.fn().mockReturnValue('hashed'),
    verifyPassword: vi.fn().mockResolvedValue(true),
    transaction: vi.fn(async (fn: (tx: unknown) => Promise<unknown>) => fn({ __tx: true })),
    redis: createMemoryRedis(),
  };

  app.decorate('repositories', {
    emailVerificationTokens: { findByTokenHash: stubs.findByTokenHash, markUsed: stubs.markUsed },
    userCredentials: {
      findById: stubs.findCredentialById,
      setEmailVerified: stubs.setEmailVerified,
    },
    userAttributes: { setVerified: stubs.setVerified },
    users: { findById: stubs.findUserById },
  } as unknown as FastifyInstance['repositories']);
  app.decorate('emailVerificationTokenUtils', {
    hashToken: stubs.hashToken,
  } as unknown as FastifyInstance['emailVerificationTokenUtils']);
  app.decorate('passwordHasher', {
    verifyPassword: stubs.verifyPassword,
  } as unknown as FastifyInstance['passwordHasher']);
  app.decorate('db', { transaction: stubs.transaction } as unknown as FastifyInstance['db']);
  app.decorate('redis', stubs.redis as unknown as FastifyInstance['redis']);
  // The realm's brute-force policy (#528), which the password check counts
  // under: the seeded default, 5 failures in 900 s lock for 900 s.
  app.decorate('policyStore', testPolicyStore() as unknown as FastifyInstance['policyStore']);
  // The login-CSRF cookie is signed with the realm's cookie key (#493).
  app.decorate('signer', createFakeCookieSigner() as unknown as FastifyInstance['signer']);

  await app.register(verifyApiRoute, { prefix: '/auth' });
  await app.register(verifyPageRoute, { prefix: '/auth' });
  await app.register(uiVerifyRoute, { prefix: '/ui' });
  await app.ready();
  return { app, stubs };
}

/** Pull the value of a hidden form field out of a rendered page. */
export function hiddenField(page: string, name: string): string | undefined {
  return new RegExp(`name="${name}" value="([^"]*)"`).exec(page)?.[1];
}

/** The `name=value` pair of each `Set-Cookie` of a response, for a `cookie` request header. */
export function cookieHeader(setCookie: string | string[] | undefined): string {
  return [setCookie ?? []]
    .flat()
    .map((header) => header.split(';', 1)[0])
    .join('; ');
}
