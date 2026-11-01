import { createPasswordProvider } from '@qauth-labs/fastify-plugin-federation';
import {
  BadRequestError,
  UniqueConstraintError,
  WeakPasswordError,
} from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { beforeEach, describe, expect, it, type Mock, vi } from 'vitest';

vi.mock('../../helpers/timing', () => ({
  ensureMinimumResponseTime: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('../../../config/env', () => ({
  env: {
    DEFAULT_REALM_NAME: 'master',
    REGISTRATION_RATE_LIMIT: 10,
    REGISTRATION_RATE_WINDOW: 900,
    EMAIL_VERIFICATION_TOKEN_EXPIRY: 3600,
    EMAIL_VERIFICATION_INVALIDATE_EXISTING_ON_RESEND: true,
    RESEND_VERIFICATION_EMAIL_LIMIT: 3,
    RESEND_VERIFICATION_EMAIL_WINDOW: 3600,
    RESEND_VERIFICATION_MIN_INTERVAL: 60,
  },
}));

import { testRealm } from '../../../testing/request-realm';
import { REDIS_KEYS, SUCCESS_MESSAGES } from '../../constants';
import { hashEmail } from '../../helpers/auth-events';
import { ensureMinimumResponseTime } from '../../helpers/timing';
import { emitUserEvent } from '../../helpers/user-events';
import registerRoute from './register';

vi.mock('../../helpers/user-events', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../helpers/user-events')>();
  const { checkedEmitUserEvent } = await import('../../../testing/user-events');
  return { ...actual, emitUserEvent: vi.fn(checkedEmitUserEvent(actual.userEventFor)) };
});

const emitUserEventMock = vi.mocked(emitUserEvent);

interface TestContext {
  handler?: (request: any, reply: any) => Promise<unknown>;
  onClose?: () => Promise<unknown>;
}

/** Sentinel transaction client — asserting writes carry it proves they share the tx. */
const TX = { __tx: 'register-tx' };

/** The address every request below registers, as the route normalizes it. */
const ADDRESS = 'user@example.com';

/** The realm the realm resolver (#486) decorated every request with. */
const REALM = testRealm({ id: 'realm-1' });

function createReply() {
  const state: { statusCode?: number; body?: unknown; headers: Record<string, string> } = {
    headers: {},
  };
  const reply: any = {
    state,
    code(n: number) {
      state.statusCode = n;
      return reply;
    },
    header(k: string, v: string) {
      state.headers[k] = v;
      return reply;
    },
    send(body: unknown) {
      state.body = body;
      return body;
    },
  };
  return reply;
}

/** In-memory Redis with the commands the per-address mail caps use. */
function createMemoryRedis() {
  const store = new Map<string, string>();
  return {
    incr: vi.fn(async (key: string) => {
      const next = Number(store.get(key) ?? '0') + 1;
      store.set(key, String(next));
      return next;
    }),
    expire: vi.fn(async () => 1),
    set: vi.fn(async (key: string, value: string, _ex: 'EX', _seconds: number, nx?: 'NX') => {
      if (nx === 'NX' && store.has(key)) return null;
      store.set(key, value);
      return 'OK';
    }),
    store,
  };
}

/** The password credential of an address that is already registered. */
function existingCredential(overrides: { emailVerified?: boolean } = {}) {
  return {
    id: 'cred-existing',
    userId: 'user-existing',
    realmId: 'realm-1',
    providerType: 'password',
    externalSub: ADDRESS,
    credentialData: {
      password_hash: '$argon2id$owner',
      email_verified: overrides.emailVerified ?? true,
    },
  };
}

function createFastifyStub() {
  const ctx: TestContext = {};
  const createdUser = {
    id: 'user-1',
    realmId: 'realm-1',
    createdAt: 1_600_000_000_000,
    updatedAt: 1_600_000_000_000,
  };

  const fastify: any = {
    withTypeProvider: () => ({
      post: (_url: string, _opts: unknown, handler: any) => {
        ctx.handler = handler;
        return fastify;
      },
    }),
    addHook: (name: string, hook: () => Promise<unknown>) => {
      if (name === 'onClose') ctx.onClose = hook;
      return fastify;
    },
    db: {
      transaction: vi.fn(async (fn: (tx: unknown) => Promise<unknown>) => fn(TX)),
    },
    redis: createMemoryRedis(),
    repositories: {
      users: {
        create: vi.fn().mockResolvedValue(createdUser),
        findById: vi.fn().mockResolvedValue({ id: 'user-existing', enabled: true }),
      },
      userCredentials: {
        create: vi.fn().mockResolvedValue({ id: 'cred-1', userId: 'user-1' }),
        findByRealmProviderSub: vi.fn().mockResolvedValue(existingCredential()),
      },
      userAttributes: {
        upsertMany: vi.fn().mockResolvedValue([]),
      },
      emailVerificationTokens: {
        create: vi.fn().mockResolvedValue({ id: 'token-1' }),
        invalidateCredentialTokens: vi.fn().mockResolvedValue(undefined),
      },
    },
    passwordValidator: {
      validatePasswordStrength: vi.fn().mockReturnValue({ valid: true, feedback: [] }),
    },
    passwordHasher: {
      hashPassword: vi.fn().mockResolvedValue('$argon2id$hashed'),
    },
    providerRegistry: {
      resolve: vi.fn().mockReturnValue(createPasswordProvider()),
      has: vi.fn().mockReturnValue(true),
      register: vi.fn(),
    },
    emailVerificationTokenUtils: {
      generateVerificationToken: vi.fn().mockReturnValue({ token: 'plain', tokenHash: 'hashed' }),
    },
    emailService: {
      sendVerificationEmail: vi.fn().mockResolvedValue(undefined),
      sendAccountExistsEmail: vi.fn().mockResolvedValue(undefined),
    },
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
  return { fastify: fastify as FastifyInstance, ctx };
}

/** Make the credential insert find the address taken, as the unique index does. */
function addressTaken(fastify: FastifyInstance) {
  (fastify.repositories.userCredentials.create as unknown as Mock).mockRejectedValue(
    new UniqueConstraintError(
      'idx_user_credentials_realm_provider_sub_unique',
      // The real cause chain carries the insert's parameters, hash included.
      new Error('insert into user_credentials ... params: $argon2id$hashed')
    )
  );
}

function requestFixture() {
  return {
    body: { email: 'User@Example.com', password: 'Str0ng-Passw0rd!' },
    ip: '127.0.0.1',
    headers: { 'user-agent': 'vitest' },
    log: { info: vi.fn(), warn: vi.fn() },
    realm: REALM,
  };
}

/** Let the background mail tasks the handler started run to completion. */
async function drainBackground(ctx: TestContext) {
  if (!ctx.onClose) throw new Error('No onClose hook registered');
  await ctx.onClose();
}

async function register(setup?: (fastify: FastifyInstance) => void) {
  const { fastify, ctx } = createFastifyStub();
  await registerRoute(fastify);
  if (!ctx.handler) throw new Error('Handler missing');
  setup?.(fastify);
  vi.mocked(ensureMinimumResponseTime).mockClear();
  const request = requestFixture();
  const reply = createReply();
  await ctx.handler(request, reply);
  return { fastify, ctx, request, reply };
}

beforeEach(() => {
  vi.mocked(ensureMinimumResponseTime).mockClear();
  emitUserEventMock.mockClear();
});

describe('POST /auth/register', () => {
  it('writes users → credential → attributes → token in ONE transaction with exact shapes', async () => {
    const { fastify, ctx, reply } = await register();

    // Single transaction wraps the whole identity write set.
    expect(fastify.db.transaction).toHaveBeenCalledOnce();

    // Pure identity anchor (#230): realmId only — no credential fields.
    expect(fastify.repositories.users.create).toHaveBeenCalledWith({ realmId: 'realm-1' }, TX);

    // Credential row: exact snake_case credential_data shape, normalized sub.
    expect(fastify.repositories.userCredentials.create).toHaveBeenCalledWith(
      {
        userId: 'user-1',
        realmId: 'realm-1',
        providerType: 'password',
        externalSub: ADDRESS,
        credentialData: { password_hash: '$argon2id$hashed', email_verified: false },
      },
      TX
    );

    // Attribute row from extractAttributes(): unverified self-reported email.
    expect(fastify.repositories.userAttributes.upsertMany).toHaveBeenCalledWith(
      'user-1',
      [
        {
          source: 'self_reported',
          attrKey: 'email',
          attrValue: ADDRESS,
          verified: false,
          expiresAt: null,
        },
      ],
      TX
    );

    // Verification token targets the credential — its only identity link.
    expect(fastify.repositories.emailVerificationTokens.create).toHaveBeenCalledWith(
      expect.objectContaining({
        credentialId: 'cred-1',
        tokenHash: 'hashed',
        used: false,
      }),
      TX
    );

    // The account's event, in the same transaction: it commits with the
    // account or not at all.
    expect(emitUserEventMock).toHaveBeenCalledOnce();
    expect(emitUserEventMock).toHaveBeenCalledWith(
      expect.anything(),
      'urn:qauth:event:user.registered:v1-rc.0',
      { method: 'password' },
      { tx: TX, realmId: 'realm-1', userId: 'user-1', actor: 'user' }
    );

    // ORDER GUARD: the users insert precedes the credentials insert
    // (user_credentials.user_id FKs users.id).
    const usersOrder = (fastify.repositories.users.create as unknown as Mock).mock
      .invocationCallOrder[0];
    const credsOrder = (fastify.repositories.userCredentials.create as unknown as Mock).mock
      .invocationCallOrder[0];
    expect(usersOrder).toBeLessThan(credsOrder);

    // The one answer every address gets: no id, no timestamps, no flag.
    expect(reply.state.statusCode).toBe(202);
    expect(reply.state.body).toEqual({ message: SUCCESS_MESSAGES.REGISTRATION });
    expect(reply.state.headers).toEqual({ 'Cache-Control': 'no-store' });

    await drainBackground(ctx);
    expect(fastify.emailService.sendVerificationEmail).toHaveBeenCalledWith(
      REALM.id,
      ADDRESS,
      'plain',
      {
        baseUrl: REALM.issuer,
      }
    );
    expect(fastify.emailService.sendAccountExistsEmail).not.toHaveBeenCalled();
  });

  describe('an address that is already registered (ANT-2026-SPEMY9GU)', () => {
    /** Everything a caller can observe about one registration, and the work done for it. */
    function observed(run: Awaited<ReturnType<typeof register>>) {
      return {
        statusCode: run.reply.state.statusCode,
        body: run.reply.state.body,
        headers: run.reply.state.headers,
        floor: vi.mocked(ensureMinimumResponseTime).mock.calls.map(([, floorMs]) => floorMs),
        hashed: (run.fastify.passwordHasher.hashPassword as unknown as Mock).mock.calls.length,
        transactions: (run.fastify.db.transaction as unknown as Mock).mock.calls.length,
      };
    }

    it('gets the same status, body, headers, floor and work as a free address', async () => {
      const free = await register();
      const freeSeen = observed(free);
      const taken = await register(addressTaken);
      const takenSeen = observed(taken);

      // It used to be 409 UNIQUE_CONSTRAINT_VIOLATION for this address and
      // 201 with the new user's id for a free one.
      expect(takenSeen).toEqual(freeSeen);
      expect(takenSeen).toEqual({
        statusCode: 202,
        body: { message: SUCCESS_MESSAGES.REGISTRATION },
        headers: { 'Cache-Control': 'no-store' },
        floor: [500],
        hashed: 1,
        transactions: 1,
      });
    });

    it('creates nothing: the anchor row rolls back with the refused credential insert', async () => {
      const { fastify } = await register(addressTaken);

      expect(fastify.repositories.users.create).toHaveBeenCalledOnce();
      expect(fastify.repositories.userAttributes.upsertMany).not.toHaveBeenCalled();
      expect(fastify.repositories.emailVerificationTokens.create).not.toHaveBeenCalled();
      // No event either: a registration that did not happen records none.
      expect(emitUserEventMock).not.toHaveBeenCalled();
    });

    it('mails the owner of a verified account a notice, not a link', async () => {
      const { fastify, ctx } = await register(addressTaken);
      await drainBackground(ctx);

      expect(fastify.repositories.userCredentials.findByRealmProviderSub).toHaveBeenCalledWith(
        'realm-1',
        'password',
        ADDRESS
      );
      expect(fastify.emailService.sendAccountExistsEmail).toHaveBeenCalledExactlyOnceWith(
        REALM.id,
        ADDRESS
      );
      expect(fastify.emailService.sendVerificationEmail).not.toHaveBeenCalled();
      expect(fastify.repositories.emailVerificationTokens.create).not.toHaveBeenCalled();
    });

    it('sends an unverified account its verification link again, with a fresh token', async () => {
      const { fastify, ctx } = await register((stub) => {
        addressTaken(stub);
        (
          stub.repositories.userCredentials.findByRealmProviderSub as unknown as Mock
        ).mockResolvedValue(existingCredential({ emailVerified: false }));
      });
      await drainBackground(ctx);

      expect(
        fastify.repositories.emailVerificationTokens.invalidateCredentialTokens
      ).toHaveBeenCalledWith('cred-existing');
      expect(fastify.repositories.emailVerificationTokens.create).toHaveBeenCalledWith(
        expect.objectContaining({ credentialId: 'cred-existing', tokenHash: 'hashed', used: false })
      );
      expect(fastify.emailService.sendVerificationEmail).toHaveBeenCalledExactlyOnceWith(
        REALM.id,
        ADDRESS,
        'plain',
        { baseUrl: REALM.issuer }
      );
      expect(fastify.emailService.sendAccountExistsEmail).not.toHaveBeenCalled();
    });

    it('mails nobody for a disabled account', async () => {
      const { fastify, ctx } = await register((stub) => {
        addressTaken(stub);
        (stub.repositories.users.findById as unknown as Mock).mockResolvedValue({
          id: 'user-existing',
          enabled: false,
        });
      });
      await drainBackground(ctx);

      expect(fastify.emailService.sendAccountExistsEmail).not.toHaveBeenCalled();
      expect(fastify.emailService.sendVerificationEmail).not.toHaveBeenCalled();
    });

    it('logs the attempt with the address hashed, and never the error that carries the hash', async () => {
      const { fastify, request } = await register(addressTaken);

      expect(request.log.warn).toHaveBeenCalledWith(
        expect.objectContaining({
          authEvent: 'user.register.failure',
          emailHash: hashEmail(ADDRESS),
          reason: 'address_in_use',
        }),
        expect.any(String)
      );
      const everyLogArgument = [
        ...request.log.warn.mock.calls,
        ...request.log.info.mock.calls,
        ...Object.values(fastify.log).flatMap((fn) => (fn as Mock).mock.calls),
      ].flat();
      expect(JSON.stringify(everyLogArgument)).not.toContain('$argon2id$hashed');
      expect(everyLogArgument.some((arg) => arg instanceof UniqueConstraintError)).toBe(false);
    });
  });

  describe('mail stays off the request path', () => {
    /** A send that never settles, like a provider that hangs. */
    const hangs = () => new Promise<void>(() => undefined);

    it.each([
      ['a free address', (_stub: FastifyInstance) => undefined],
      ['a registered address', addressTaken],
    ])('answers %s without waiting for the mail provider', async (_label, setup) => {
      const { fastify, ctx } = createFastifyStub();
      await registerRoute(fastify);
      if (!ctx.handler) throw new Error('Handler missing');
      setup(fastify);
      (fastify.emailService.sendVerificationEmail as unknown as Mock).mockImplementation(hangs);
      (fastify.emailService.sendAccountExistsEmail as unknown as Mock).mockImplementation(hangs);

      const reply = createReply();
      const answered = ctx.handler(requestFixture(), reply);
      const outcome = await Promise.race([
        answered.then(() => 'answered'),
        new Promise<string>((resolve) => setTimeout(() => resolve('waiting'), 50)),
      ]);

      expect(outcome).toBe('answered');
      expect(reply.state.statusCode).toBe(202);
    });

    it('still answers 202 when the verification mail fails, and logs the failure', async () => {
      const { fastify, ctx, reply } = await register((stub) => {
        (stub.emailService.sendVerificationEmail as unknown as Mock).mockRejectedValue(
          new Error('smtp down')
        );
      });
      await drainBackground(ctx);

      expect(reply.state.statusCode).toBe(202);
      expect(fastify.log.error).toHaveBeenCalledWith(
        expect.any(Error),
        'Failed to send verification email during registration'
      );
    });
  });

  describe('per-address mail caps (shared with resend-verification)', () => {
    it('claims the caps for every registration, before the outcome is known', async () => {
      for (const setup of [undefined, addressTaken]) {
        const { fastify } = await register(setup);
        const redis = fastify.redis as unknown as ReturnType<typeof createMemoryRedis>;

        expect(redis.incr).toHaveBeenCalledWith(REDIS_KEYS.RESEND_RATE_LIMIT(REALM.id, ADDRESS));
        expect(redis.set).toHaveBeenCalledWith(
          REDIS_KEYS.LAST_EMAIL_SENT(REALM.id, ADDRESS),
          expect.any(String),
          'EX',
          60,
          'NX'
        );
        // Before the transaction: a resend right after either registration
        // then finds the same interval claimed.
        expect(redis.set.mock.invocationCallOrder[0]).toBeLessThan(
          (fastify.db.transaction as unknown as Mock).mock.invocationCallOrder[0]
        );
      }
    });

    it('sends the owner of a registered address nothing within the minimum interval', async () => {
      const { fastify, ctx } = await register((stub) => {
        addressTaken(stub);
        (stub.redis as unknown as ReturnType<typeof createMemoryRedis>).store.set(
          REDIS_KEYS.LAST_EMAIL_SENT(REALM.id, ADDRESS),
          '1'
        );
      });
      await drainBackground(ctx);

      expect(fastify.repositories.userCredentials.findByRealmProviderSub).not.toHaveBeenCalled();
      expect(fastify.emailService.sendAccountExistsEmail).not.toHaveBeenCalled();
    });

    it('sends the owner of a registered address nothing once the window allowance is spent', async () => {
      const { fastify, ctx } = await register((stub) => {
        addressTaken(stub);
        (stub.redis as unknown as ReturnType<typeof createMemoryRedis>).store.set(
          REDIS_KEYS.RESEND_RATE_LIMIT(REALM.id, ADDRESS),
          '3'
        );
      });
      await drainBackground(ctx);

      expect(fastify.emailService.sendAccountExistsEmail).not.toHaveBeenCalled();
    });

    it('still sends a new account its verification mail when the caps are spent', async () => {
      const { fastify, ctx } = await register((stub) => {
        (stub.redis as unknown as ReturnType<typeof createMemoryRedis>).store.set(
          REDIS_KEYS.LAST_EMAIL_SENT(REALM.id, ADDRESS),
          '1'
        );
      });
      await drainBackground(ctx);

      expect(fastify.emailService.sendVerificationEmail).toHaveBeenCalledWith(
        REALM.id,
        ADDRESS,
        'plain',
        {
          baseUrl: REALM.issuer,
        }
      );
    });
  });

  it("links the verification mail to the request realm's issuer, not EMAIL_BASE_URL (ADR-019 Decision 1, #490)", async () => {
    const realmB = testRealm({ id: 'realm-b', issuer: 'https://b.example.com' });
    const { fastify, ctx } = createFastifyStub();
    await registerRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    await ctx.handler({ ...requestFixture(), realm: realmB }, createReply());
    await drainBackground(ctx);

    // ...and goes out through realm B's own transport (#529).
    expect(fastify.emailService.sendVerificationEmail).toHaveBeenCalledExactlyOnceWith(
      'realm-b',
      ADDRESS,
      'plain',
      { baseUrl: 'https://b.example.com' }
    );
  });

  it("registers in the request's realm: a body realmId may only name that realm (#487)", async () => {
    // The host chooses the realm. A body realmId naming it, in any case, is
    // accepted; one naming any other realm is refused as unknown, before
    // anything is hashed or written.
    const realm = testRealm({ id: '0b5a1c2d-3e4f-4a5b-8c6d-7e8f9a0b1c2d' });
    const { fastify, ctx } = createFastifyStub();
    await registerRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    const fixture = requestFixture();
    await ctx.handler(
      { ...fixture, realm, body: { ...fixture.body, realmId: realm.id.toUpperCase() } },
      createReply()
    );
    expect(fastify.repositories.users.create).toHaveBeenCalledWith({ realmId: realm.id }, TX);

    vi.mocked(fastify.repositories.users.create).mockClear();
    vi.mocked(fastify.passwordHasher.hashPassword).mockClear();
    const other = '9f8e7d6c-5b4a-4c3d-9e2f-1a0b9c8d7e6f';
    const refused = ctx.handler(
      { ...fixture, realm, body: { ...fixture.body, realmId: other } },
      createReply()
    );
    await expect(refused).rejects.toBeInstanceOf(BadRequestError);
    expect(fastify.passwordHasher.hashPassword).not.toHaveBeenCalled();
    expect(fastify.repositories.users.create).not.toHaveBeenCalled();
  });

  it('lets any other failure of the transaction through', async () => {
    const { fastify, ctx } = createFastifyStub();
    await registerRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');
    (fastify.repositories.userCredentials.create as unknown as Mock).mockRejectedValue(
      new Error('connection terminated')
    );

    await expect(ctx.handler(requestFixture(), createReply())).rejects.toThrow(
      'connection terminated'
    );
  });

  it('rejects weak passwords before touching the database', async () => {
    const { fastify, ctx } = createFastifyStub();
    await registerRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    (fastify.passwordValidator.validatePasswordStrength as unknown as Mock).mockReturnValue({
      valid: false,
      feedback: ['too short'],
    });

    await expect(ctx.handler(requestFixture(), createReply())).rejects.toThrow(WeakPasswordError);
    expect(fastify.db.transaction).not.toHaveBeenCalled();
  });
});
