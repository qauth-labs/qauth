import { TemporarilyUnavailableError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { emitUserEvent, bindsNewFactor, tokenSessionOf } = vi.hoisted(() => ({
  emitUserEvent: vi.fn<(...args: unknown[]) => Promise<string>>(async () => 'event-id'),
  bindsNewFactor: vi.fn(() => false),
  tokenSessionOf: vi.fn(
    async (): Promise<{ id: string; recoveryCodeUsed?: boolean } | undefined> => undefined
  ),
}));
// The helpers' modules read the environment at import; these rules read none of it.
vi.mock('../../config/env', () => ({ env: { NODE_ENV: 'test' } }));
vi.mock('./user-events', () => ({ emitUserEvent }));
vi.mock('./account-operation-guard', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./account-operation-guard')>()),
  bindsNewFactor,
  tokenSessionOf,
}));
vi.mock('./account-sign-in-methods', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./account-sign-in-methods')>()),
  accountCredentials: vi.fn(async () => []),
}));

import { REDIS_KEYS } from '../constants/redis-keys';
import {
  type AccountFactors,
  confirmTotpEnrolment,
  readRecoveryCodeSummary,
  regenerateAnsweredRecoveryCodes,
  startTotpEnrolment,
  TOTP_ENROLMENT_LIFETIME_MS,
} from './account-factors';
import { InsufficientUserAuthenticationError } from './account-operation-errors';

const REALM_ID = '00000000-0000-4000-8000-0000000000aa';
const USER_ID = '00000000-0000-4000-8000-000000000001';
const SESSION_ID = '00000000-0000-4000-8000-0000000000c1';
const CREDENTIAL_ID = '00000000-0000-4000-8000-0000000000d1';
const NOW = Date.UTC(2026, 10, 14, 12);
/** The token's `auth_time`: a minute before now, in whole seconds. */
const AUTH_TIME = NOW - 60_000;
const OWNER = { realmId: REALM_ID, userId: USER_ID, clientId: 'account-console' };
const KEY = REDIS_KEYS.ACCOUNT_TOTP_ENROLMENT(REALM_ID, USER_ID);
const SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
const SEALED = 'sealed-ciphertext';
const CODES = Array.from(
  { length: 10 },
  (_, n) => `abcd-efgh-ijkl-mn${String.fromCharCode(97 + n)}2`
);

/** An account as the engine's directory reads it. */
function account(overrides: Record<string, unknown> = {}) {
  return {
    userId: USER_ID,
    verified: true,
    identifier: 'ada@example.com',
    factors: [] as { type: string }[],
    ...overrides,
  };
}

interface Fakes {
  readonly fastify: FastifyInstance;
  readonly request: FastifyRequest;
  readonly factors: AccountFactors;
  readonly redis: Map<string, string>;
  readonly error: ReturnType<typeof vi.fn>;
  readonly ports: {
    readonly findByUserId: ReturnType<typeof vi.fn>;
    readonly start: ReturnType<typeof vi.fn>;
    readonly check: ReturnType<typeof vi.fn>;
    readonly bind: ReturnType<typeof vi.fn>;
    readonly status: ReturnType<typeof vi.fn>;
    readonly issue: ReturnType<typeof vi.fn>;
    readonly confirm: ReturnType<typeof vi.fn>;
    readonly regenerate: ReturnType<typeof vi.fn>;
    readonly nameNewCredential: ReturnType<typeof vi.fn>;
    readonly findSession: ReturnType<typeof vi.fn>;
    readonly currentSet: ReturnType<typeof vi.fn>;
    readonly findAllByUserId: ReturnType<typeof vi.fn>;
    readonly recordSecurityChange: ReturnType<typeof vi.fn>;
  };
}

/** A server whose Redis is a map, and the account API's ports over fakes. */
function fakes(
  options: { redisDown?: boolean; credentials?: { providerType: string }[] } = {}
): Fakes {
  const redis = new Map<string, string>();
  const down = async () => {
    throw new Error('ECONNREFUSED');
  };
  const error = vi.fn();
  const ports = {
    findByUserId: vi.fn(async () => account()),
    start: vi.fn(async () => ({
      sealed: SEALED,
      display: { secret: SECRET, otpauthUri: 'otpauth://totp/x' },
    })),
    check: vi.fn(async () => ({ kind: 'valid', step: 123 })),
    bind: vi.fn(async () => ({ kind: 'bound', credentialId: CREDENTIAL_ID })),
    status: vi.fn(async () => ({ issued: false, confirmed: false, unused: 0 })),
    issue: vi.fn(async () => ({ codes: CODES, setId: 'set-1' })),
    confirm: vi.fn(async () => true),
    regenerate: vi.fn(async () => ({ codes: CODES, setId: 'set-2' })),
    nameNewCredential: vi.fn(async () => true),
    // The sign-in's session, ended: it signed in at the token's `auth_time`.
    findSession: vi.fn(async (): Promise<Record<string, unknown> | undefined> => ({
      id: SESSION_ID,
      userId: USER_ID,
      authTime: AUTH_TIME + 250,
      revokedAt: NOW - 1000,
    })),
    currentSet: vi.fn(async () => ({ issuedAt: NOW - 1000, unused: 10 })),
    findAllByUserId: vi.fn(async () =>
      (options.credentials ?? [{ providerType: 'password' }, { providerType: 'totp' }]).map(
        (row) => ({ ...row, realmId: REALM_ID, userId: USER_ID })
      )
    ),
    recordSecurityChange: vi.fn(async () => 1),
  };
  const fastify = {
    log: { error, warn: vi.fn(), info: vi.fn() },
    redis: options.redisDown
      ? { get: down, set: down, eval: down }
      : {
          get: async (key: string) => redis.get(key) ?? null,
          set: async (key: string, value: string) => {
            redis.set(key, value);
            return 'OK';
          },
          eval: async (_script: string, _keys: number, key: string, value: string) => {
            if (redis.get(key) !== value) return 0;
            redis.delete(key);
            return 1;
          },
        },
    repositories: {
      sessions: { nameNewCredential: ports.nameNewCredential, findById: ports.findSession },
      userRecoveryCodes: { currentSet: ports.currentSet },
      userCredentials: { findAllByUserId: ports.findAllByUserId },
      adminGrants: { recordSecurityChange: ports.recordSecurityChange },
    },
  } as unknown as FastifyInstance;
  const request = {
    id: 'request-1',
    server: fastify,
    jwtPayload: {
      sub: USER_ID,
      amr: ['pwd'],
      clientId: 'account-console',
      sid: SESSION_ID,
      authTime: AUTH_TIME,
    },
  } as unknown as FastifyRequest;
  const factors = {
    totp: { start: ports.start, check: ports.check, bind: ports.bind },
    recoveryCodes: {
      status: ports.status,
      issue: ports.issue,
      confirm: ports.confirm,
      regenerate: ports.regenerate,
    },
    forRequest: (_request: FastifyRequest, work: () => Promise<unknown>) => work(),
    accounts: { findByUserId: ports.findByUserId },
  } as unknown as AccountFactors;
  return { fastify, request, factors, redis, error, ports };
}

/** A started enrolment, held as the start keeps it. */
function held(f: Fakes, expiresAt = NOW + TOTP_ENROLMENT_LIFETIME_MS): void {
  f.redis.set(KEY, JSON.stringify({ sealed: SEALED, expiresAt }));
}

beforeEach(() => {
  vi.clearAllMocks();
  bindsNewFactor.mockReturnValue(false);
  tokenSessionOf.mockResolvedValue(undefined);
});

describe('startTotpEnrolment (#1109)', () => {
  it('draws a secret, keeps only its ciphertext, and answers the secret once', async () => {
    const f = fakes();
    const started = await startTotpEnrolment(f.fastify, f.request, f.factors, OWNER, NOW);
    expect(started).toEqual({
      kind: 'started',
      secret: SECRET,
      otpauthUri: 'otpauth://totp/x',
      expiresAt: NOW + TOTP_ENROLMENT_LIFETIME_MS,
    });
    expect(f.ports.start).toHaveBeenCalledWith({
      realmId: REALM_ID,
      userId: USER_ID,
      identifier: 'ada@example.com',
    });
    const kept = f.redis.get(KEY);
    expect(JSON.parse(kept as string)).toEqual({
      sealed: SEALED,
      expiresAt: NOW + TOTP_ENROLMENT_LIFETIME_MS,
    });
    expect(kept).not.toContain(SECRET);
  });

  it.each([
    ['bound', { factors: [{ type: 'totp' }] }],
    ['unclaimed', { verified: false }],
    ['no_address', { identifier: undefined }],
  ] as const)('refuses with conflict (%s)', async (reason, overrides) => {
    const f = fakes();
    f.ports.findByUserId.mockResolvedValue(account(overrides));
    expect(await startTotpEnrolment(f.fastify, f.request, f.factors, OWNER, NOW)).toEqual({
      kind: 'conflict',
      reason,
    });
    expect(f.ports.start).not.toHaveBeenCalled();
    expect(f.redis.size).toBe(0);
  });

  it('answers 503 when the enrolment cannot be kept', async () => {
    const f = fakes({ redisDown: true });
    await expect(
      startTotpEnrolment(f.fastify, f.request, f.factors, OWNER, NOW)
    ).rejects.toBeInstanceOf(TemporarilyUnavailableError);
  });
});

describe('confirmTotpEnrolment (#1109)', () => {
  it('is not_found without a started enrolment, or after it lapsed', async () => {
    const f = fakes();
    expect(
      await confirmTotpEnrolment(f.fastify, f.request, f.factors, OWNER, '123456', NOW)
    ).toEqual({ kind: 'not_found' });
    held(f, NOW);
    expect(
      await confirmTotpEnrolment(f.fastify, f.request, f.factors, OWNER, '123456', NOW)
    ).toEqual({ kind: 'not_found' });
    expect(f.ports.check).not.toHaveBeenCalled();
  });

  it('binds nothing on a wrong code, and keeps the enrolment for another', async () => {
    const f = fakes();
    held(f);
    f.ports.check.mockResolvedValue({ kind: 'invalid' });
    expect(
      await confirmTotpEnrolment(f.fastify, f.request, f.factors, OWNER, '000000', NOW)
    ).toEqual({ kind: 'invalid_code' });
    expect(f.ports.check).toHaveBeenCalledWith({
      realmId: REALM_ID,
      userId: USER_ID,
      sealed: SEALED,
      code: '000000',
    });
    expect(f.ports.bind).not.toHaveBeenCalled();
    expect(f.redis.has(KEY)).toBe(true);
  });

  it('binds on a valid code, takes the enrolment, and answers the first set once', async () => {
    const f = fakes();
    held(f);
    const result = await confirmTotpEnrolment(
      f.fastify,
      f.request,
      f.factors,
      OWNER,
      '492039',
      NOW
    );
    expect(result).toEqual({
      kind: 'bound',
      enabledAt: expect.any(Number),
      recoveryCodes: { codes: CODES, issuedAt: NOW - 1000 },
    });
    expect(f.ports.bind).toHaveBeenCalledWith({
      realmId: REALM_ID,
      userId: USER_ID,
      clientId: 'account-console',
      sealed: SEALED,
      step: 123,
    });
    expect(f.redis.has(KEY)).toBe(false);
    // The set is marked confirmed as it is answered: no sign-in replaces it.
    expect(f.ports.confirm).toHaveBeenCalledWith({
      realmId: REALM_ID,
      userId: USER_ID,
      setId: 'set-1',
    });
    // Not new: the session names nothing.
    expect(f.ports.nameNewCredential).not.toHaveBeenCalled();
    // Taken: a second confirmation finds none.
    expect(
      await confirmTotpEnrolment(f.fastify, f.request, f.factors, OWNER, '492039', NOW)
    ).toEqual({ kind: 'not_found' });
  });

  it('binds a new app after a password-only sign-in whose session, live or ended, names it (#1064)', async () => {
    const f = fakes();
    held(f);
    bindsNewFactor.mockReturnValue(true);
    tokenSessionOf.mockResolvedValue({ id: SESSION_ID });
    await confirmTotpEnrolment(f.fastify, f.request, f.factors, OWNER, '492039', NOW);
    expect(f.ports.bind).toHaveBeenCalledWith(expect.objectContaining({ isNew: true }));
    // The binding's own transaction names it (`totp-sign-in.ts`), never a
    // write after it.
    expect(f.ports.nameNewCredential).not.toHaveBeenCalled();

    // The sign-in's session has ended since: it is still the one to name.
    held(f);
    f.ports.findByUserId.mockResolvedValue(account());
    tokenSessionOf.mockResolvedValue(undefined);
    expect(
      await confirmTotpEnrolment(f.fastify, f.request, f.factors, OWNER, '492039', NOW)
    ).toMatchObject({ kind: 'bound' });
    expect(f.ports.findSession).toHaveBeenCalledWith(REALM_ID, SESSION_ID);
  });

  it('binds no new app that no session of its sign-in could name, and keeps the enrolment', async () => {
    bindsNewFactor.mockReturnValue(true);
    for (const missing of ['no session', 'another sign-in', 'no sid'] as const) {
      const f = fakes();
      if (missing === 'no session') f.ports.findSession.mockResolvedValue(undefined);
      if (missing === 'another sign-in') {
        f.ports.findSession.mockResolvedValue({
          id: SESSION_ID,
          userId: USER_ID,
          authTime: AUTH_TIME - 5_000,
        });
      }
      if (missing === 'no sid') {
        (f.request as unknown as { jwtPayload: Record<string, unknown> }).jwtPayload['sid'] =
          undefined;
      }
      // Refused at the start, before a secret is drawn...
      await expect(
        startTotpEnrolment(f.fastify, f.request, f.factors, OWNER, NOW)
      ).rejects.toBeInstanceOf(InsufficientUserAuthenticationError);
      expect(f.ports.start).not.toHaveBeenCalled();
      // ...and at the confirmation, before the enrolment is taken.
      held(f);
      await expect(
        confirmTotpEnrolment(f.fastify, f.request, f.factors, OWNER, '492039', NOW)
      ).rejects.toBeInstanceOf(InsufficientUserAuthenticationError);
      expect(f.ports.bind).not.toHaveBeenCalled();
      expect(f.redis.has(KEY)).toBe(true);
    }
  });

  it('lets a recovery-code sign-in rebind a lost app, which the binding replaces', async () => {
    const f = fakes();
    f.ports.findByUserId.mockResolvedValue(account({ factors: [{ type: 'totp' }] }));
    tokenSessionOf.mockResolvedValue({ id: SESSION_ID, recoveryCodeUsed: true });
    expect(await startTotpEnrolment(f.fastify, f.request, f.factors, OWNER, NOW)).toMatchObject({
      kind: 'started',
    });
    expect(
      await confirmTotpEnrolment(f.fastify, f.request, f.factors, OWNER, '492039', NOW)
    ).toMatchObject({ kind: 'bound' });
    expect(f.ports.bind).toHaveBeenCalledTimes(1);
  });

  it('answers no set where the account holds one it confirmed', async () => {
    const f = fakes();
    held(f);
    f.ports.status.mockResolvedValue({ issued: true, confirmed: true, unused: 7 });
    expect(
      await confirmTotpEnrolment(f.fastify, f.request, f.factors, OWNER, '492039', NOW)
    ).toEqual({ kind: 'bound', enabledAt: expect.any(Number) });
    expect(f.ports.issue).not.toHaveBeenCalled();
  });

  it('keeps the binding when its first set cannot be issued, and logs no code', async () => {
    const f = fakes();
    held(f);
    f.ports.issue.mockRejectedValue(new Error('database down'));
    expect(
      await confirmTotpEnrolment(f.fastify, f.request, f.factors, OWNER, '492039', NOW)
    ).toEqual({ kind: 'bound', enabledAt: expect.any(Number) });
    expect(f.error).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(f.error.mock.calls)).not.toContain('492039');
  });

  it('binds nothing where the account bound an app meanwhile, or another call took the enrolment', async () => {
    const f = fakes();
    held(f);
    f.ports.findByUserId.mockResolvedValue(account({ factors: [{ type: 'totp' }] }));
    expect(
      await confirmTotpEnrolment(f.fastify, f.request, f.factors, OWNER, '492039', NOW)
    ).toEqual({ kind: 'not_found' });
    // A read that refuses leaves the enrolment where it was.
    expect(f.redis.has(KEY)).toBe(true);

    f.ports.findByUserId.mockResolvedValue(account());
    f.ports.check.mockImplementation(async () => {
      // A new enrolment replaces this one while its code is checked.
      f.redis.set(KEY, JSON.stringify({ sealed: 'other', expiresAt: NOW + 1 }));
      return { kind: 'valid', step: 123 };
    });
    expect(
      await confirmTotpEnrolment(f.fastify, f.request, f.factors, OWNER, '492039', NOW)
    ).toEqual({ kind: 'not_found' });
    expect(f.ports.bind).not.toHaveBeenCalled();
  });

  it('answers 503 when the enrolment cannot be read', async () => {
    const f = fakes({ redisDown: true });
    await expect(
      confirmTotpEnrolment(f.fastify, f.request, f.factors, OWNER, '492039', NOW)
    ).rejects.toBeInstanceOf(TemporarilyUnavailableError);
  });
});

describe('the recovery codes (#1109)', () => {
  it('reads how many are left and when the set was issued, never the codes', async () => {
    const f = fakes();
    expect(await readRecoveryCodeSummary(f.fastify, REALM_ID, USER_ID)).toEqual({
      remaining: 10,
      issuedAt: NOW - 1000,
    });
    f.ports.currentSet.mockResolvedValue(undefined);
    expect(await readRecoveryCodeSummary(f.fastify, REALM_ID, USER_ID)).toEqual({
      remaining: 0,
      issuedAt: null,
    });
  });

  it('regenerates a set, confirms it as it is answered, and records it', async () => {
    const f = fakes();
    expect(await regenerateAnsweredRecoveryCodes(f.fastify, f.request, f.factors, OWNER)).toEqual({
      codes: CODES,
      issuedAt: NOW - 1000,
    });
    expect(f.ports.confirm).toHaveBeenCalledWith({
      realmId: REALM_ID,
      userId: USER_ID,
      setId: 'set-2',
    });
    expect(emitUserEvent).toHaveBeenCalledWith(
      f.request,
      'urn:qauth:event:user.recovery_codes_regenerated:v1-rc.0',
      {},
      { realmId: REALM_ID, userId: USER_ID, clientId: 'account-console', actor: 'user' }
    );
  });

  // The two-admin rule (#521): a new set stops an admin approving for 7
  // days. The store keeps its own transaction, so the record comes first,
  // and one that fails refuses the regeneration instead of being logged.
  it('records the security change before the set, and regenerates nothing when it fails', async () => {
    const f = fakes();
    await regenerateAnsweredRecoveryCodes(f.fastify, f.request, f.factors, OWNER);
    expect(f.ports.recordSecurityChange).toHaveBeenCalledWith(REALM_ID, USER_ID, undefined);
    expect(f.ports.recordSecurityChange.mock.invocationCallOrder[0]).toBeLessThan(
      f.ports.regenerate.mock.invocationCallOrder[0] ?? 0
    );

    const failing = fakes();
    failing.ports.recordSecurityChange.mockRejectedValue(new Error('ECONNRESET'));
    await expect(
      regenerateAnsweredRecoveryCodes(failing.fastify, failing.request, failing.factors, OWNER)
    ).rejects.toThrow('ECONNRESET');
    expect(failing.ports.regenerate).not.toHaveBeenCalled();
  });

  it('is a conflict without a second factor, or when another set replaced the new one', async () => {
    const plain = fakes({ credentials: [{ providerType: 'password' }] });
    expect(
      await regenerateAnsweredRecoveryCodes(plain.fastify, plain.request, plain.factors, OWNER)
    ).toBe('conflict');
    expect(plain.ports.regenerate).not.toHaveBeenCalled();

    const raced = fakes();
    raced.ports.confirm.mockResolvedValue(false);
    expect(
      await regenerateAnsweredRecoveryCodes(raced.fastify, raced.request, raced.factors, OWNER)
    ).toBe('conflict');
  });
});
