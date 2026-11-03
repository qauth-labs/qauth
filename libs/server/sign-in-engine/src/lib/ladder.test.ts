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

describe('the password ladder’s known-IP bound (#968, ADR-017 Decision 7)', () => {
  it('lets a known IP skip the wait for 20 counted failures of a run', () => {
    expect(PASSWORD_LADDER_POLICY).toMatchObject({ knownIpMs: 30 * DAY, knownIpFreeFailures: 20 });
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

  it('refuses a known-IP bound below the free failures, or not a whole count', () => {
    expect(() => checkLadderPolicy(policy({ knownIpFreeFailures: 4 }))).toThrow(
      /knownIpFreeFailures below freeFailures/
    );
    // Equal to the free failures: the exemption skips no wait.
    expect(() => checkLadderPolicy(policy({ knownIpFreeFailures: 5 }))).not.toThrow();
    expect(() => checkLadderPolicy(policy({ knownIpFreeFailures: 20.5 }))).toThrow(
      /knownIpFreeFailures/
    );
    expect(() => checkLadderPolicy(policy({ knownIpFreeFailures: Number.NaN }))).toThrow(
      /knownIpFreeFailures/
    );
  });

  it('refuses a known-IP bound that skips more than half the waits before the hard ceiling', () => {
    // Below 56 failures a known IP skips 1,023 s of doubling waits and (B − 15) waits of 15
    // minutes, and still meets (100 − B) of them before the 100th.
    const tooMany = /skips more than half the waits before the hard ceiling/;
    expect(() => checkLadderPolicy(policy({ knownIpFreeFailures: 56 }))).not.toThrow();
    expect(() => checkLadderPolicy(policy({ knownIpFreeFailures: 57 }))).toThrow(tooMany);
    // At or past the ceiling a known IP would fire the hard action with no wait at all.
    expect(() => checkLadderPolicy(policy({ knownIpFreeFailures: 100 }))).toThrow(tooMany);
    expect(() => checkLadderPolicy(policy({ knownIpFreeFailures: 10 ** 12 }))).toThrow(tooMany);
    // With no hard ceiling there is none to reach.
    expect(() =>
      checkLadderPolicy(policy({ hardCeiling: null, knownIpFreeFailures: 1_000 }))
    ).not.toThrow();
  });
});
