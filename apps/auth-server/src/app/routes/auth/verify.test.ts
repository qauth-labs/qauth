import { SignInStoreUnavailableError } from '@qauth-labs/fastify-plugin-sign-in-engine';
import {
  EmailAlreadyVerifiedError,
  InvalidCredentialsError,
  InvalidTokenError,
  TemporarilyUnavailableError,
  TooManyRequestsError,
} from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { describe, expect, it, type Mock, vi } from 'vitest';

vi.mock('../../../config/env', () => ({
  env: {
    VERIFICATION_RATE_LIMIT: 10,
    VERIFICATION_RATE_WINDOW: 900,
  },
}));

import {
  createFakePasswordAttempts,
  type FakePasswordAttempts,
} from '../../../testing/password-attempts';
import { testPolicyStore } from '../../../testing/realm-policies';
import { testRealm } from '../../../testing/request-realm';
import { hashEmail } from '../../helpers/auth-events';
import verifyRoute from './verify';

interface TestContext {
  handler?: (request: any, reply?: unknown) => Promise<unknown>;
  registered?: { method: string; url: string; opts: unknown };
}

/** Sentinel transaction client shared by the completion write set. */
const TX = { __tx: 'verify-tx' };

function tokenFixture(overrides: Record<string, unknown> = {}) {
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

function credentialFixture(overrides: Record<string, unknown> = {}) {
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
function createMemoryRedis() {
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

function createFastifyStub() {
  const ctx: TestContext = {};
  const fastify: any = {
    withTypeProvider: () => ({
      post: (url: string, opts: unknown, handler: any) => {
        ctx.handler = handler;
        ctx.registered = { method: 'POST', url, opts };
        return fastify;
      },
    }),
    db: {
      transaction: vi.fn(async (fn: (tx: unknown) => Promise<unknown>) => fn(TX)),
    },
    repositories: {
      emailVerificationTokens: {
        findByTokenHash: vi.fn(),
        markUsed: vi.fn().mockResolvedValue({ id: 'token-1' }),
      },
      userCredentials: {
        findById: vi.fn(),
        findByUserIdAndType: vi.fn(),
        setEmailVerified: vi.fn().mockResolvedValue({}),
      },
      userAttributes: {
        setVerified: vi.fn().mockResolvedValue({ id: 'attr-1' }),
      },
      // A disabled account cannot complete verification.
      users: {
        findById: vi.fn(async (realmId: string, id: string) => ({ id, realmId, enabled: true })),
      },
    },
    emailVerificationTokenUtils: {
      hashToken: vi.fn().mockReturnValue('hashed'),
    },
    // The registrant's password is checked against credential_data.password_hash.
    passwordHasher: {
      verifyPassword: vi.fn().mockResolvedValue(true),
    },
    redis: createMemoryRedis(),
    // The per-account failure ladder (#615): every attempt reserved by default.
    passwordAttempts: createFakePasswordAttempts(),
    // The login routes' failed-login lockout, which the password check here
    // shares (UZ1HDHZP), under the realm's brute-force policy (#528): the
    // seeded default, 5 failures in 900 s lock for 900 s.
    policyStore: testPolicyStore(),
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
  return { fastify: fastify as FastifyInstance, ctx };
}

/** The realm the realm resolver (#486) decorated the request with. */
const REALM = testRealm({ id: 'realm-1' });

const request = {
  body: { token: 'a'.repeat(64), password: 'registrant-password' },
  realm: REALM,
};

describe('POST /auth/verify', () => {
  it('is registered as POST with the token in the body — never a state-changing GET', async () => {
    // A GET verified on any fetch of the emailed link (link scanners,
    // prefetch, a page calling the API on load). Verification must take an
    // explicit POST.
    const { fastify, ctx } = createFastifyStub();
    await verifyRoute(fastify);

    expect(ctx.registered?.method).toBe('POST');
    expect(ctx.registered?.url).toBe('/verify');
    if (!ctx.registered) throw new Error('Route missing');
    const schema = (ctx.registered.opts as { schema: Record<string, unknown> }).schema;
    expect(schema.body).toBeDefined();
    expect(schema.querystring).toBeUndefined();
  });

  it('completes verification with the completion write set in one transaction and exact body', async () => {
    const { fastify, ctx } = createFastifyStub();
    await verifyRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    (
      fastify.repositories.emailVerificationTokens.findByTokenHash as unknown as Mock
    ).mockResolvedValue(tokenFixture());
    (fastify.repositories.userCredentials.findById as unknown as Mock).mockResolvedValue(
      credentialFixture()
    );

    const result = await ctx.handler(request);

    // The token, its credential and its user are looked up in the request's
    // realm (#489).
    expect(fastify.repositories.emailVerificationTokens.findByTokenHash).toHaveBeenCalledWith(
      REALM.id,
      'hashed'
    );
    expect(fastify.repositories.userCredentials.findById).toHaveBeenCalledWith(REALM.id, 'cred-1');
    expect(fastify.repositories.users.findById).toHaveBeenCalledWith(REALM.id, 'user-1');
    expect(fastify.db.transaction).toHaveBeenCalledOnce();
    // The complete dual-write set, all on the same transaction client:
    expect(fastify.repositories.emailVerificationTokens.markUsed).toHaveBeenCalledWith(
      'token-1',
      TX
    );
    expect(fastify.repositories.userCredentials.setEmailVerified).toHaveBeenCalledWith(
      'cred-1',
      TX
    );
    expect(fastify.repositories.userAttributes.setVerified).toHaveBeenCalledWith(
      'user-1',
      'self_reported',
      'email',
      true,
      TX
    );

    // #230: the response email is the credential's external_sub.
    expect(result).toEqual({
      message: 'Email verified successfully',
      email: 'user@example.com',
    });
  });

  // The token proves the mailbox, not who registered. A person who registered
  // with someone else's address holds the password; the mailbox owner holds
  // the token. Verification must need both, so neither can do it alone.
  it('checks the password against the credential the token targets', async () => {
    const { fastify, ctx } = createFastifyStub();
    await verifyRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');
    (
      fastify.repositories.emailVerificationTokens.findByTokenHash as unknown as Mock
    ).mockResolvedValue(tokenFixture());
    (fastify.repositories.userCredentials.findById as unknown as Mock).mockResolvedValue(
      credentialFixture()
    );

    await ctx.handler(request);

    expect(fastify.passwordHasher.verifyPassword).toHaveBeenCalledWith(
      (credentialFixture().credentialData as { password_hash: string }).password_hash,
      'registrant-password'
    );
  });

  it('refuses a wrong password and consumes NOTHING — the mailbox alone cannot verify', async () => {
    const { fastify, ctx } = createFastifyStub();
    await verifyRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');
    (
      fastify.repositories.emailVerificationTokens.findByTokenHash as unknown as Mock
    ).mockResolvedValue(tokenFixture());
    (fastify.repositories.userCredentials.findById as unknown as Mock).mockResolvedValue(
      credentialFixture()
    );
    (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(false);

    await expect(
      ctx.handler({
        body: { token: 'a'.repeat(64), password: 'mailbox-owner-guess' },
        realm: REALM,
      })
    ).rejects.toThrow(InvalidCredentialsError);
    // The token survives, so the genuine registrant can still verify.
    expect(fastify.db.transaction).not.toHaveBeenCalled();
    expect(fastify.repositories.emailVerificationTokens.markUsed).not.toHaveBeenCalled();
    expect(fastify.repositories.userCredentials.setEmailVerified).not.toHaveBeenCalled();
    expect(fastify.repositories.userAttributes.setVerified).not.toHaveBeenCalled();
  });

  // Whoever holds a live token (a mailbox reader, or the owner of an address
  // someone else registered by mistake) must not get a password oracle for
  // the account. The password check shares the login routes' failed-login
  // lockout, with the same identifiers (UZ1HDHZP).
  describe("shares the login routes' failed-login lockout", () => {
    const EMAIL_ID = `email:${hashEmail('user@example.com')}`;
    // Counted in the request's realm, the account's (its credential is looked
    // up in that realm only, #489), the realm the login routes count it in
    // (#487).
    const REALM_ID = REALM.id;

    function createReply() {
      const headers: Record<string, string> = {};
      return {
        reply: {
          header: vi.fn((name: string, value: string) => {
            headers[name] = value;
          }),
        },
        headers,
      };
    }

    async function setup(options: { verifies: boolean }) {
      const { fastify, ctx } = createFastifyStub();
      await verifyRoute(fastify);
      if (!ctx.handler) throw new Error('Handler missing');
      (
        fastify.repositories.emailVerificationTokens.findByTokenHash as unknown as Mock
      ).mockResolvedValue(tokenFixture());
      (fastify.repositories.userCredentials.findById as unknown as Mock).mockResolvedValue(
        credentialFixture()
      );
      (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(
        options.verifies
      );
      const redis = (fastify as unknown as { redis: ReturnType<typeof createMemoryRedis> }).redis;
      const handler = ctx.handler;
      return { fastify, redis, handler };
    }

    it('counts wrong passwords against the account and locks it after the max', async () => {
      const { fastify, handler } = await setup({ verifies: false });

      for (let i = 0; i < 5; i++) {
        await expect(
          handler({ ...request, ip: `198.51.100.${i + 1}` }, createReply().reply)
        ).rejects.toThrow(InvalidCredentialsError);
      }
      // From a sixth address: the account itself is locked.
      const { reply, headers } = createReply();
      await expect(handler({ ...request, ip: '198.51.100.6' }, reply)).rejects.toThrow(
        TooManyRequestsError
      );
      expect(headers['Retry-After']).toBe('900');
      expect(fastify.passwordHasher.verifyPassword).toHaveBeenCalledTimes(5);
      expect(fastify.db.transaction).not.toHaveBeenCalled();
    });

    it('refuses an account locked on a login route before the password is compared', async () => {
      const { fastify, redis, handler } = await setup({ verifies: true });
      redis._store.set(`failed-login:lockout:${REALM_ID}:${EMAIL_ID}`, '1');
      redis._ttls.set(`failed-login:lockout:${REALM_ID}:${EMAIL_ID}`, 300);

      const { reply, headers } = createReply();
      await expect(handler({ ...request, ip: '127.0.0.1' }, reply)).rejects.toThrow(
        TooManyRequestsError
      );
      expect(headers['Retry-After']).toBe('300');
      expect(fastify.passwordHasher.verifyPassword).not.toHaveBeenCalled();
      // Nothing consumed, nothing verified.
      expect(fastify.db.transaction).not.toHaveBeenCalled();
    });

    it('keys the ip: identifier with the client address key (an IPv6 client by its /64)', async () => {
      const { redis, handler } = await setup({ verifies: false });

      await expect(
        handler({ ...request, ip: '2001:db8:1:2:aaaa:bbbb:cccc:7' }, createReply().reply)
      ).rejects.toThrow(InvalidCredentialsError);

      expect(redis._store.get(`failed-login:attempts:${REALM_ID}:${EMAIL_ID}`)).toBe('1');
      expect(redis._store.get(`failed-login:attempts:${REALM_ID}:ip:2001:db8:1:2::`)).toBe('1');
    });

    it("settles a right password like a login: the account's count is cleared", async () => {
      const { fastify, redis, handler } = await setup({ verifies: false });
      for (let i = 0; i < 2; i++) {
        await expect(handler({ ...request, ip: '127.0.0.1' }, createReply().reply)).rejects.toThrow(
          InvalidCredentialsError
        );
      }
      (fastify.passwordHasher.verifyPassword as unknown as Mock).mockResolvedValue(true);

      await expect(handler({ ...request, ip: '127.0.0.1' }, createReply().reply)).resolves.toEqual({
        message: 'Email verified successfully',
        email: 'user@example.com',
      });

      expect(redis._store.has(`failed-login:attempts:${REALM_ID}:${EMAIL_ID}`)).toBe(false);
      // The address keeps the failures counted against it.
      expect(redis._store.get(`failed-login:attempts:${REALM_ID}:ip:127.0.0.1`)).toBe('2');
    });

    describe('the per-account failure ladder (#615)', () => {
      const attemptsOf = (fastify: FastifyInstance) =>
        (fastify as unknown as { passwordAttempts: FakePasswordAttempts }).passwordAttempts;

      it('reserves the attempt before the compare and counts a wrong password', async () => {
        const { fastify, handler } = await setup({ verifies: false });
        const attempts = attemptsOf(fastify);
        attempts.atCeiling = true;

        await expect(
          handler({ ...request, ip: '2001:db8:1:2:aaaa:bbbb:cccc:7' }, createReply().reply)
        ).rejects.toThrow(InvalidCredentialsError);

        expect(attempts.reserve).toHaveBeenCalledWith({
          realmId: REALM_ID,
          identifier: 'user@example.com',
          endUserIp: '2001:db8:1:2::',
        });
        const [reservation] = attempts.reserved;
        expect(reservation.failed).toHaveBeenCalledTimes(1);
        expect(reservation.account).toEqual({ userId: 'user-1' });
        expect(reservation.succeeded).not.toHaveBeenCalled();
      });

      it('hands the ladder no end-user IP for a request with no client address, so none is exempted or made known', async () => {
        const { fastify, handler } = await setup({ verifies: false });
        const attempts = attemptsOf(fastify);

        await expect(handler({ ...request, ip: undefined }, createReply().reply)).rejects.toThrow(
          InvalidCredentialsError
        );

        expect(attempts.reserve).toHaveBeenCalledOnce();
        expect(attempts.reserve.mock.calls[0][0]).toStrictEqual({
          realmId: REALM_ID,
          identifier: 'user@example.com',
        });
      });

      it('refuses an attempt inside the wait before the compare, with Retry-After', async () => {
        const { fastify, handler } = await setup({ verifies: true });
        attemptsOf(fastify).reserve.mockResolvedValueOnce({ kind: 'wait', retryAfterSeconds: 8 });

        const { reply, headers } = createReply();
        await expect(handler({ ...request, ip: '127.0.0.1' }, reply)).rejects.toThrow(
          TooManyRequestsError
        );
        expect(headers['Retry-After']).toBe('8');
        expect(fastify.passwordHasher.verifyPassword).not.toHaveBeenCalled();
        expect(fastify.db.transaction).not.toHaveBeenCalled();
      });

      it('refuses with 503 before the compare when the ladder store fails', async () => {
        const { fastify, handler } = await setup({ verifies: true });
        attemptsOf(fastify).reserve.mockRejectedValueOnce(
          new SignInStoreUnavailableError('ladder', new Error('redis down'))
        );

        const error = await handler({ ...request, ip: '127.0.0.1' }, createReply().reply).catch(
          (thrown: unknown) => thrown
        );
        expect(error).toBeInstanceOf(TemporarilyUnavailableError);
        expect((error as TemporarilyUnavailableError).retryAfterSeconds).toBe(5);
        expect(fastify.passwordHasher.verifyPassword).not.toHaveBeenCalled();
        expect(fastify.db.transaction).not.toHaveBeenCalled();
      });

      it('settles a right password as a success, and clears a mark the unarmed hard action ignored', async () => {
        const { fastify, handler } = await setup({ verifies: true });
        (fastify.repositories.userCredentials.findById as unknown as Mock).mockResolvedValue(
          credentialFixture({ disabledAt: 1_793_491_200_000 })
        );

        await expect(
          handler({ ...request, ip: '127.0.0.1' }, createReply().reply)
        ).resolves.toEqual({ message: 'Email verified successfully', email: 'user@example.com' });
        const [reservation] = attemptsOf(fastify).reserved;
        expect(reservation.succeeded).toHaveBeenCalledWith({ userId: 'user-1', ignoredMark: true });
      });

      it('refuses a password the armed hard action disabled without comparing it', async () => {
        const { fastify, handler } = await setup({ verifies: true });
        const attempts = attemptsOf(fastify);
        attempts.hardActionArmed.mockResolvedValue(true);
        (fastify.repositories.userCredentials.findById as unknown as Mock).mockResolvedValue(
          credentialFixture({ disabledAt: 1_793_491_200_000 })
        );

        await expect(handler({ ...request, ip: '127.0.0.1' }, createReply().reply)).rejects.toThrow(
          InvalidCredentialsError
        );
        expect(attempts.hardActionArmed).toHaveBeenCalledWith(REALM_ID);
        expect(fastify.passwordHasher.verifyPassword).not.toHaveBeenCalled();
        expect(attempts.reserved[0].failed).toHaveBeenCalledTimes(1);
        expect(fastify.db.transaction).not.toHaveBeenCalled();
      });
    });

    it("counts the attempt in the request's realm, the token's account's (#487, #489)", async () => {
      const { fastify, redis, handler } = await setup({ verifies: false });
      // A request to another realm's host: its token and credential are that
      // realm's, the only realm they are looked up in.
      const otherRealm = testRealm({ id: 'realm-2', name: 'other' });
      (fastify.repositories.userCredentials.findById as unknown as Mock).mockResolvedValue(
        credentialFixture({ realmId: 'realm-2' })
      );

      await expect(
        handler({ ...request, realm: otherRealm, ip: '127.0.0.1' }, createReply().reply)
      ).rejects.toThrow(InvalidCredentialsError);

      expect(fastify.repositories.userCredentials.findById).toHaveBeenCalledWith(
        'realm-2',
        'cred-1'
      );
      expect(redis._store.get(`failed-login:attempts:realm-2:${EMAIL_ID}`)).toBe('1');
      expect(redis._store.get('failed-login:attempts:realm-2:ip:127.0.0.1')).toBe('1');
      expect(redis._store.has(`failed-login:attempts:${REALM_ID}:${EMAIL_ID}`)).toBe(false);
    });
  });

  it('requires a password in the request body schema', async () => {
    const { fastify, ctx } = createFastifyStub();
    await verifyRoute(fastify);
    if (!ctx.registered) throw new Error('Route missing');
    const body = (
      ctx.registered.opts as {
        schema: { body: { safeParse: (v: unknown) => { success: boolean } } };
      }
    ).schema.body;

    expect(body.safeParse({ token: 'a'.repeat(64) }).success).toBe(false);
    expect(body.safeParse({ token: 'a'.repeat(64), password: '' }).success).toBe(false);
    expect(body.safeParse({ token: 'a'.repeat(64), password: 'x' }).success).toBe(true);
  });

  it('refuses a disabled account before the password check, leaving the token unconsumed', async () => {
    const { fastify, ctx } = createFastifyStub();
    await verifyRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    (
      fastify.repositories.emailVerificationTokens.findByTokenHash as unknown as Mock
    ).mockResolvedValue(tokenFixture());
    (fastify.repositories.userCredentials.findById as unknown as Mock).mockResolvedValue(
      credentialFixture()
    );
    (fastify.repositories.users.findById as unknown as Mock).mockResolvedValue({
      id: 'user-1',
      enabled: false,
    });

    await expect(ctx.handler(request)).rejects.toBeInstanceOf(InvalidTokenError);
    expect(fastify.repositories.users.findById).toHaveBeenCalledWith(REALM.id, 'user-1');
    expect(fastify.passwordHasher.verifyPassword).not.toHaveBeenCalled();
    expect(fastify.db.transaction).not.toHaveBeenCalled();
    expect(fastify.repositories.emailVerificationTokens.markUsed).not.toHaveBeenCalled();
    expect(fastify.repositories.userCredentials.setEmailVerified).not.toHaveBeenCalled();
  });

  it('throws InvalidTokenError for an unknown/expired/used token', async () => {
    const { fastify, ctx } = createFastifyStub();
    await verifyRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    (
      fastify.repositories.emailVerificationTokens.findByTokenHash as unknown as Mock
    ).mockResolvedValue(undefined);

    await expect(ctx.handler(request)).rejects.toThrow(InvalidTokenError);
    expect(fastify.db.transaction).not.toHaveBeenCalled();
  });

  // #489: the token is looked up in the request's realm only. A token mailed
  // for another realm's account is no row here, refused exactly as an unknown
  // token is, so the answer does not tell that it exists in another realm.
  it("answers another realm's token exactly as an unknown token (#489)", async () => {
    const { fastify, ctx } = createFastifyStub();
    await verifyRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');
    const findByTokenHash = fastify.repositories.emailVerificationTokens
      .findByTokenHash as unknown as Mock;
    // The token is realm-2's: the realm-scoped lookup finds it there only.
    findByTokenHash.mockImplementation(async (realmId: string, tokenHash: string) =>
      realmId === 'realm-2' && tokenHash === 'hashed' ? tokenFixture() : undefined
    );
    (fastify.repositories.userCredentials.findById as unknown as Mock).mockResolvedValue(
      credentialFixture({ realmId: 'realm-2' })
    );

    const otherRealmToken = await ctx.handler(request).catch((error: unknown) => error);
    findByTokenHash.mockResolvedValue(undefined);
    const unknownToken = await ctx.handler(request).catch((error: unknown) => error);

    expect(findByTokenHash).toHaveBeenNthCalledWith(1, REALM.id, 'hashed');
    expect(otherRealmToken).toBeInstanceOf(InvalidTokenError);
    expect(unknownToken).toBeInstanceOf(InvalidTokenError);
    const answer = (error: unknown) => {
      const { name, message, statusCode, code } = error as InvalidTokenError;
      return { name, message, statusCode, code };
    };
    expect(answer(otherRealmToken)).toEqual(answer(unknownToken));
    // Nothing of the other realm's account is read, checked or counted.
    expect(fastify.repositories.userCredentials.findById).not.toHaveBeenCalled();
    expect(fastify.repositories.users.findById).not.toHaveBeenCalled();
    expect(fastify.passwordHasher.verifyPassword).not.toHaveBeenCalled();
    expect(fastify.redis.incr).not.toHaveBeenCalled();
    expect(fastify.db.transaction).not.toHaveBeenCalled();
  });

  it('maps a lost single-use race (CAS returns undefined) to the generic token error — #258', async () => {
    const { fastify, ctx } = createFastifyStub();
    await verifyRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    (
      fastify.repositories.emailVerificationTokens.findByTokenHash as unknown as Mock
    ).mockResolvedValue(tokenFixture());
    (fastify.repositories.userCredentials.findById as unknown as Mock).mockResolvedValue(
      credentialFixture()
    );
    // A concurrent attempt consumed the token between the read and the CAS.
    (fastify.repositories.emailVerificationTokens.markUsed as unknown as Mock).mockResolvedValue(
      undefined
    );

    await expect(ctx.handler(request)).rejects.toThrow(InvalidTokenError);
    // The loser's transaction rolled back — no verified-state writes land.
    expect(fastify.repositories.userCredentials.setEmailVerified).toHaveBeenCalledTimes(0);
  });

  it('fails closed with InvalidTokenError when no credential resolves', async () => {
    const { fastify, ctx } = createFastifyStub();
    await verifyRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    (
      fastify.repositories.emailVerificationTokens.findByTokenHash as unknown as Mock
    ).mockResolvedValue(tokenFixture());
    (fastify.repositories.userCredentials.findById as unknown as Mock).mockResolvedValue(undefined);

    await expect(ctx.handler(request)).rejects.toThrow(InvalidTokenError);
    expect(fastify.repositories.emailVerificationTokens.markUsed).not.toHaveBeenCalled();
  });

  it('treats malformed credential_data as an invalid token and logs for operators', async () => {
    const { fastify, ctx } = createFastifyStub();
    await verifyRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    (
      fastify.repositories.emailVerificationTokens.findByTokenHash as unknown as Mock
    ).mockResolvedValue(tokenFixture());
    (fastify.repositories.userCredentials.findById as unknown as Mock).mockResolvedValue(
      credentialFixture({ credentialData: { nonsense: true } })
    );

    await expect(ctx.handler(request)).rejects.toThrow(InvalidTokenError);
    expect(fastify.log.error).toHaveBeenCalledWith(
      expect.objectContaining({ credentialId: 'cred-1' }),
      expect.stringContaining('malformed credential_data')
    );
    expect(fastify.repositories.emailVerificationTokens.markUsed).not.toHaveBeenCalled();
  });

  it('rejects an already-verified email sourced from credential_data without consuming the token', async () => {
    const { fastify, ctx } = createFastifyStub();
    await verifyRoute(fastify);
    if (!ctx.handler) throw new Error('Handler missing');

    (
      fastify.repositories.emailVerificationTokens.findByTokenHash as unknown as Mock
    ).mockResolvedValue(tokenFixture());
    (fastify.repositories.userCredentials.findById as unknown as Mock).mockResolvedValue(
      credentialFixture({ credentialData: { password_hash: 'hash', email_verified: true } })
    );

    await expect(ctx.handler(request)).rejects.toThrow(EmailAlreadyVerifiedError);
    expect(fastify.repositories.emailVerificationTokens.markUsed).not.toHaveBeenCalled();
    expect(fastify.repositories.userCredentials.setEmailVerified).not.toHaveBeenCalled();
  });
});
