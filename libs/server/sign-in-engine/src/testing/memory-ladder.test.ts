import { describe, expect, it } from 'vitest';

import type { LadderReservation, LadderSettlement, LadderVerdict } from '../lib/hooks';
import { ladderWaitMs, PASSWORD_LADDER_POLICY } from '../lib/ladder';
import { createMemoryLadder } from './memory-ladder';

const REALM = '0199fa20-0000-7000-8000-00000000aaaa';
const HMAC = 'identifier-hmac';
/** An address the owner signed in from: known to the account. */
const KNOWN = '203.0.113.7';
/** An address the account never signed in from. */
const OTHER = '198.51.100.9';
const BOUND = PASSWORD_LADDER_POLICY.knownIpFreeFailures;
const CEILING = PASSWORD_LADDER_POLICY.hardCeiling as number;

function setup() {
  let clock = Date.UTC(2026, 10, 3);
  const ladder = createMemoryLadder(() => clock);
  const attempt = (endUserIp?: string): Promise<LadderVerdict> =>
    ladder.reserve({
      realmId: REALM,
      identifierHmac: HMAC,
      factor: 'password',
      ...(endUserIp === undefined ? {} : { endUserIp }),
    });
  const reserved = async (endUserIp?: string): Promise<LadderReservation> => {
    const verdict = await attempt(endUserIp);
    if (verdict.kind !== 'reserved') throw new Error(`expected a reservation, got ${verdict.kind}`);
    return verdict;
  };
  /** `times` wrong passwords from `endUserIp`, on a clock that stands still. */
  const fail = async (times: number, endUserIp?: string) => {
    for (let i = 0; i < times; i += 1) await (await reserved(endUserIp)).settle('failure');
  };
  const failures = () => ladder.counter(REALM, HMAC, 'password')?.failures;
  return {
    attempt,
    reserved,
    fail,
    failures,
    advance: (ms: number) => {
      clock += ms;
    },
    /** The owner signs in from `endUserIp`, which makes it known. */
    signIn: async (endUserIp: string) => (await reserved(endUserIp)).settle('success'),
  };
}

describe('the in-memory ladder’s known-IP bound (#968, ADR-017 Decision 7)', () => {
  it('never refuses a known IP with a wait below the bound, on a clock that stands still', async () => {
    const { attempt, fail, failures, signIn } = setup();
    await signIn(KNOWN);
    expect(BOUND).toBe(20);
    await fail(BOUND, KNOWN);
    expect(failures()).toBe(BOUND);
    // Another address has been waiting since the 5th failure.
    expect(await attempt(OTHER)).toMatchObject({ kind: 'wait' });
  });

  it('gives a known IP at and above the bound the same wait as an unknown address', async () => {
    const { attempt, fail, signIn, advance, failures } = setup();
    await signIn(KNOWN);
    await fail(BOUND, KNOWN);
    for (let n = BOUND; n < BOUND + 5; n += 1) {
      const wait = ladderWaitMs(n, PASSWORD_LADDER_POLICY);
      const fromKnown = await attempt(KNOWN);
      expect(fromKnown).toEqual({ kind: 'wait', retryAfterSeconds: wait / 1000 });
      expect(await attempt(OTHER)).toEqual(fromKnown);
      // Refused, so not counted; the wait ends for both at once.
      expect(failures()).toBe(n);
      advance(wait - 1);
      expect(await attempt(KNOWN)).toMatchObject({ kind: 'wait', retryAfterSeconds: 1 });
      advance(1);
      await fail(1, KNOWN);
    }
  });

  it('lets a known IP reach the hard ceiling only through the waits', async () => {
    const { attempt, signIn, advance, failures } = setup();
    await signIn(KNOWN);
    let waited = 0;
    const settled: LadderSettlement[] = [];
    while (settled.length < CEILING) {
      const verdict = await attempt(KNOWN);
      if (verdict.kind === 'wait') {
        // The only way on is to let the wait pass.
        advance(verdict.retryAfterSeconds * 1000);
        waited += verdict.retryAfterSeconds * 1000;
        continue;
      }
      settled.push(await verdict.settle('failure'));
    }
    expect(failures()).toBe(CEILING);
    expect(settled.slice(0, CEILING - 1).every((result) => !result.ceilingReached)).toBe(true);
    expect(settled[CEILING - 1]).toEqual({ ceilingReached: true });
    // Every wait from the bound's failure to the ceiling's, 15 minutes each at the defaults: 20 hours.
    let expected = 0;
    for (let n = BOUND; n < CEILING; n += 1) expected += ladderWaitMs(n, PASSWORD_LADDER_POLICY);
    expect(waited).toBe(expected);
    expect(waited).toBe((CEILING - BOUND) * PASSWORD_LADDER_POLICY.maxWaitMs);
  });

  it('counts parallel attempts from a known IP one at a time: past the bound every one waits', async () => {
    const { attempt, signIn, failures } = setup();
    await signIn(KNOWN);
    const verdicts = await Promise.all(Array.from({ length: 50 }, () => attempt(KNOWN)));
    expect(verdicts.filter((verdict) => verdict.kind === 'reserved')).toHaveLength(BOUND);
    expect(failures()).toBe(BOUND);
  });

  it('counts only known IPs’ failures toward the bound: another address cannot take the owner’s exemption away', async () => {
    const { attempt, fail, signIn, advance, failures, reserved } = setup();
    await signIn(KNOWN);
    // A guesser elsewhere climbs to 30 failures through the waits.
    while ((failures() ?? 0) < 30) {
      const verdict = await attempt(OTHER);
      if (verdict.kind === 'wait') advance(verdict.retryAfterSeconds * 1000);
      else await verdict.settle('failure');
    }
    expect(await attempt(OTHER)).toMatchObject({ kind: 'wait' });
    // The owner still skips the wait from the known IP, and signs in: the run ends.
    await fail(BOUND - 1, KNOWN);
    expect(failures()).toBe(30 + BOUND - 1);
    await (await reserved(KNOWN)).settle('success');
    expect(failures()).toBeUndefined();
  });

  it('keeps a run that mixes known and other addresses to at least half the waits before the ceiling', async () => {
    const { attempt, signIn, advance, failures } = setup();
    await signIn(KNOWN);
    let waited = 0;
    const through = async (endUserIp: string, until: number) => {
      while ((failures() ?? 0) < until) {
        const verdict = await attempt(endUserIp);
        if (verdict.kind === 'wait') {
          advance(verdict.retryAfterSeconds * 1000);
          waited += verdict.retryAfterSeconds * 1000;
        } else {
          await verdict.settle('failure');
        }
      }
    };
    // The best use of the bound: climb elsewhere, then spend it on the last waits.
    await through(OTHER, CEILING - BOUND);
    await through(KNOWN, CEILING);
    let unknownOnly = 0;
    let rest = 0;
    for (let n = 0; n < CEILING; n += 1) {
      unknownOnly += ladderWaitMs(n, PASSWORD_LADDER_POLICY);
      if (n < CEILING - BOUND) rest += ladderWaitMs(n, PASSWORD_LADDER_POLICY);
    }
    expect(waited).toBe(rest);
    expect(waited * 2).toBeGreaterThanOrEqual(unknownOnly);
  });

  it('still clears the run on a success, after which a known IP skips the wait again', async () => {
    const { attempt, fail, signIn, advance, failures } = setup();
    await signIn(KNOWN);
    await fail(BOUND, KNOWN);
    // The owner waits too, the right password included, then signs in.
    expect(await attempt(KNOWN)).toMatchObject({ kind: 'wait' });
    advance(ladderWaitMs(BOUND, PASSWORD_LADDER_POLICY));
    await signIn(KNOWN);
    expect(failures()).toBeUndefined();
    await fail(BOUND, KNOWN);
    expect(failures()).toBe(BOUND);
  });
});
