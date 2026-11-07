import type { FastifyInstance } from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';

const env = vi.hoisted(() => ({ INTERACTION_UI_ENABLED: true }));
vi.mock('../../config/env', () => ({ env }));

import { REDIS_KEYS } from '../constants/redis-keys';
import { NOT_VALID_BEFORE_MARGIN_MS } from './account-validity';
import {
  PASSWORD_CHANGE_CUTOFF_TTL_MS,
  passwordChangeNotBefore,
  predatesReset,
  recordPasswordChange,
  resetAllowed,
  resetNotBefore,
  signInNotBefore,
} from './password-reset';

/** Who may start a password reset, and the session epoch it advances (#642). */

afterEach(() => {
  env.INTERACTION_UI_ENABLED = true;
});

describe('resetAllowed', () => {
  it('lets every usable client reset while the hosted pages are on: reset needs no client flag', () => {
    expect(resetAllowed({ enabled: true })).toBe(true);
    expect(resetAllowed({ enabled: true, suspended: false })).toBe(true);
    expect(resetAllowed({ enabled: true, suspended: null })).toBe(true);
  });

  it('refuses a disabled or suspended client, and no client', () => {
    expect(resetAllowed({ enabled: false })).toBe(false);
    expect(resetAllowed({ enabled: true, suspended: true })).toBe(false);
    expect(resetAllowed(undefined)).toBe(false);
    expect(resetAllowed(null)).toBe(false);
  });

  it('refuses every client while the hosted pages are off', () => {
    env.INTERACTION_UI_ENABLED = false;
    expect(resetAllowed({ enabled: true })).toBe(false);
  });
});

describe('predatesReset', () => {
  const RESET_AT = 1_800_000_000_000;

  it('holds for what was issued no later than the reset, with the margin', () => {
    expect(predatesReset(RESET_AT, RESET_AT - 60_000)).toBe(true);
    expect(predatesReset(RESET_AT, RESET_AT)).toBe(true);
    expect(predatesReset(RESET_AT, RESET_AT + NOT_VALID_BEFORE_MARGIN_MS)).toBe(true);
    expect(predatesReset(RESET_AT, RESET_AT + NOT_VALID_BEFORE_MARGIN_MS + 1)).toBe(false);
  });

  it('never holds for a user never reset, and always for an issue time that is not a time', () => {
    expect(predatesReset(null, 0)).toBe(false);
    expect(predatesReset(RESET_AT, Number.NaN)).toBe(true);
  });
});

describe('resetNotBefore', () => {
  it('adds the margin to the last reset, and answers null for a user never reset', async () => {
    const lastReset = vi.fn(async ({ userId }: { realmId: string; userId: string }) =>
      userId === 'user-1' ? 5_000 : null
    );
    const fastify = { sessionEpochs: { lastReset } } as unknown as FastifyInstance;

    await expect(resetNotBefore(fastify, 'realm-1', 'user-1')).resolves.toBe(
      5_000 + NOT_VALID_BEFORE_MARGIN_MS
    );
    await expect(resetNotBefore(fastify, 'realm-1', 'user-2')).resolves.toBeNull();
    expect(lastReset).toHaveBeenCalledWith({ realmId: 'realm-1', userId: 'user-1' });
  });
});

/** A Redis that keeps what it is given, and the TTL of each key. */
function memoryRedis() {
  const values = new Map<string, string>();
  const ttls = new Map<string, number>();
  return {
    values,
    ttls,
    redis: {
      get: vi.fn(async (key: string) => values.get(key) ?? null),
      set: vi.fn(async (key: string, value: string, _mode: 'PX', ttlMs: number) => {
        values.set(key, value);
        ttls.set(key, ttlMs);
        return 'OK';
      }),
    },
  };
}

describe('the password change cutoff (#844)', () => {
  const CHANGED_AT = 1_800_000_000_000;

  it('keeps the change time for as long as a sign-in transaction lives', async () => {
    const { redis, values, ttls } = memoryRedis();
    const fastify = { redis } as unknown as FastifyInstance;

    await expect(passwordChangeNotBefore(fastify, 'realm-1', 'user-1')).resolves.toBeNull();
    await recordPasswordChange(fastify, 'realm-1', 'user-1', CHANGED_AT);

    const key = REDIS_KEYS.PASSWORD_CHANGED('realm-1', 'user-1');
    expect(values.get(key)).toBe(String(CHANGED_AT));
    // Two hours and the engine's clock skew (`SIGN_IN_TRANSACTION_MAX_AGE_MS`).
    expect(ttls.get(key)).toBe(PASSWORD_CHANGE_CUTOFF_TTL_MS);
    expect(PASSWORD_CHANGE_CUTOFF_TTL_MS).toBe(2 * 60 * 60_000 + 60_000);
    await expect(passwordChangeNotBefore(fastify, 'realm-1', 'user-1')).resolves.toBe(CHANGED_AT);
    // Another user's, or another realm's, is not this one.
    await expect(passwordChangeNotBefore(fastify, 'realm-2', 'user-1')).resolves.toBeNull();
    await expect(passwordChangeNotBefore(fastify, 'realm-1', 'user-2')).resolves.toBeNull();
  });

  it.each(['', '0', '-5', '1.5', 'soon', '99999999999999999'])(
    'throws for a stored value %j that is no time, so the round is refused',
    async (raw) => {
      const { redis, values } = memoryRedis();
      values.set(REDIS_KEYS.PASSWORD_CHANGED('realm-1', 'user-1'), raw);
      await expect(
        passwordChangeNotBefore({ redis } as unknown as FastifyInstance, 'realm-1', 'user-1')
      ).rejects.toThrow('not a password change time');
    }
  );

  it('records no time that is none', async () => {
    const { redis } = memoryRedis();
    await expect(
      recordPasswordChange({ redis } as unknown as FastifyInstance, 'realm-1', 'user-1', Number.NaN)
    ).rejects.toThrow('not a password change time');
    expect(redis.set).not.toHaveBeenCalled();
  });

  it('gives the engine the later of the last reset and the last change, or null for neither', async () => {
    const { redis } = memoryRedis();
    const lastReset = vi.fn(async ({ userId }: { realmId: string; userId: string }) =>
      userId === 'reset' || userId === 'both' ? CHANGED_AT : null
    );
    const fastify = { redis, sessionEpochs: { lastReset } } as unknown as FastifyInstance;
    await recordPasswordChange(fastify, 'realm-1', 'changed', CHANGED_AT);
    await recordPasswordChange(fastify, 'realm-1', 'both', CHANGED_AT + 60_000);

    await expect(signInNotBefore(fastify, 'realm-1', 'neither')).resolves.toBeNull();
    await expect(signInNotBefore(fastify, 'realm-1', 'reset')).resolves.toBe(
      CHANGED_AT + NOT_VALID_BEFORE_MARGIN_MS
    );
    await expect(signInNotBefore(fastify, 'realm-1', 'changed')).resolves.toBe(CHANGED_AT);
    await expect(signInNotBefore(fastify, 'realm-1', 'both')).resolves.toBe(CHANGED_AT + 60_000);
  });
});
