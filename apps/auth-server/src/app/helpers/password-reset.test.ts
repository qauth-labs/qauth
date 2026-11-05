import type { FastifyInstance } from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';

const env = vi.hoisted(() => ({ INTERACTION_UI_ENABLED: true }));
vi.mock('../../config/env', () => ({ env }));

import { NOT_VALID_BEFORE_MARGIN_MS } from './account-validity';
import { predatesReset, resetAllowed, resetNotBefore } from './password-reset';

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
