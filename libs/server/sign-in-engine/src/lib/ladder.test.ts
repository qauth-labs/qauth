import { describe, expect, it } from 'vitest';

import { checkLadderPolicy, type LadderPolicy, PASSWORD_LADDER_POLICY } from './ladder';

const DAY = 86_400_000;

describe('the password ladder’s retentions (#969, ADR-017 Decision 7)', () => {
  it('keeps a run 2 days below the free failures and 30 days from the first wait', () => {
    expect(PASSWORD_LADDER_POLICY).toMatchObject({
      freeFailures: 5,
      maxWaitMs: 15 * 60_000,
      hardCeiling: 100,
      freeRetentionMs: 2 * DAY,
      retentionMs: 30 * DAY,
    });
    expect(checkLadderPolicy(PASSWORD_LADDER_POLICY)).toBe(PASSWORD_LADDER_POLICY);
  });
});

describe('checkLadderPolicy', () => {
  const policy = (overrides: Partial<LadderPolicy>): LadderPolicy => ({
    ...PASSWORD_LADDER_POLICY,
    ...overrides,
  });

  it('refuses a free retention shorter than the longest wait', () => {
    expect(() =>
      checkLadderPolicy(policy({ freeFailures: 1, freeRetentionMs: 15 * 60_000 - 1 }))
    ).toThrow(/freeRetentionMs shorter/);
    expect(() =>
      checkLadderPolicy(policy({ freeFailures: 1, freeRetentionMs: 15 * 60_000 }))
    ).not.toThrow();
  });

  it('refuses a free retention that lets a guesser below the ladder outpace its longest waits', () => {
    // No hard ceiling: 4 free failures an hour are one per 15 minutes, the ladder's steady pace.
    const noCeiling = { hardCeiling: null };
    expect(() =>
      checkLadderPolicy(policy({ ...noCeiling, freeRetentionMs: 60 * 60_000 - 1 }))
    ).toThrow(/freeRetentionMs shorter/);
    expect(() =>
      checkLadderPolicy(policy({ ...noCeiling, freeRetentionMs: 60 * 60_000 }))
    ).not.toThrow();
  });

  it('refuses a free retention that gives a guesser below the ladder more tries than the hard ceiling', () => {
    // 4 tries per free retention against 99 per 30 days: at least 120/99 days.
    expect(() => checkLadderPolicy(policy({ freeRetentionMs: DAY }))).toThrow(
      /more tries below the hard ceiling/
    );
    expect(() => checkLadderPolicy(policy({ freeRetentionMs: 104_727_272 }))).toThrow(
      /more tries below the hard ceiling/
    );
    expect(() => checkLadderPolicy(policy({ freeRetentionMs: 104_727_273 }))).not.toThrow();
  });

  it('refuses a free retention longer than the retention, or not a whole number of ms', () => {
    expect(() => checkLadderPolicy(policy({ freeRetentionMs: 30 * DAY + 1 }))).toThrow(
      /longer than retentionMs/
    );
    expect(() => checkLadderPolicy(policy({ freeRetentionMs: 30 * DAY }))).not.toThrow();
    expect(() => checkLadderPolicy(policy({ freeRetentionMs: Number.NaN }))).toThrow(
      /freeRetentionMs/
    );
    expect(() => checkLadderPolicy(policy({ freeRetentionMs: 2 * DAY + 0.5 }))).toThrow(
      /freeRetentionMs/
    );
  });
});
