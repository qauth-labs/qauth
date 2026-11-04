import { describe, expect, it, vi } from 'vitest';

import { type BreachCheckOutcome, createBreachedPasswordChecker } from './checker';
import { passwordSha1 } from './digest';
import { BreachLookupError,type BreachLookupFailureReason } from './errors';
import {
  type LocalBreachList,
  parseLocalBreachList,
  type ReloadableBreachList,
} from './local-list';
import type { BreachRangeLookup } from './range-lookup';

const BREACHED = 'password';
const UNBREACHED = 'a passphrase nobody has leaked yet';

function reloadable(list: LocalBreachList | null): ReloadableBreachList {
  return {
    current: () => list,
    reload: async () => ({ loaded: true, size: list?.size ?? 0 }),
  };
}

const LOADED = reloadable(parseLocalBreachList(`${passwordSha1(BREACHED)}:9659365\n`));
const NOT_LOADED = reloadable(null);

function rangeLookup(
  answer: (sha1Hex: string) => Promise<'listed' | 'not_listed'>
): BreachRangeLookup & { lookup: ReturnType<typeof vi.fn> } {
  return { lookup: vi.fn(answer) };
}

const LISTING_LOOKUP = () =>
  rangeLookup(async (sha1Hex) => (sha1Hex === passwordSha1(BREACHED) ? 'listed' : 'not_listed'));

describe('createBreachedPasswordChecker: off', () => {
  it('checks nothing, sends nothing and tells the metric nothing', async () => {
    const onResult = vi.fn();
    const lookup = LISTING_LOOKUP();
    const current = vi.fn(() => null);
    const checker = createBreachedPasswordChecker({
      localList: { current, reload: async () => ({ loaded: true, size: 0 }) },
      rangeLookup: lookup,
      onResult,
    });

    expect(await checker.check({ source: 'off', password: BREACHED })).toEqual({ kind: 'off' });
    expect(lookup.lookup).not.toHaveBeenCalled();
    expect(current).not.toHaveBeenCalled();
    expect(onResult).not.toHaveBeenCalled();
  });
});

describe('createBreachedPasswordChecker: local', () => {
  it('answers listed and not_listed from the list in use', async () => {
    const checker = createBreachedPasswordChecker({ localList: LOADED });
    expect(await checker.check({ source: 'local', password: BREACHED })).toEqual({
      kind: 'listed',
      source: 'local',
    });
    expect(await checker.check({ source: 'local', password: UNBREACHED })).toEqual({
      kind: 'not_listed',
      source: 'local',
    });
  });

  it('is failed with not_configured without a list, and list_not_loaded before one loaded', async () => {
    expect(
      await createBreachedPasswordChecker({}).check({ source: 'local', password: BREACHED })
    ).toEqual({ kind: 'failed', source: 'local', reason: 'not_configured' });
    expect(
      await createBreachedPasswordChecker({ localList: NOT_LOADED }).check({
        source: 'local',
        password: BREACHED,
      })
    ).toEqual({ kind: 'failed', source: 'local', reason: 'list_not_loaded' });
  });

  it('reads the list in use at each check, so a reload takes effect at once', async () => {
    let list: LocalBreachList | null = parseLocalBreachList('');
    const checker = createBreachedPasswordChecker({
      localList: { current: () => list, reload: async () => ({ loaded: true, size: 0 }) },
    });
    expect((await checker.check({ source: 'local', password: BREACHED })).kind).toBe('not_listed');
    list = parseLocalBreachList(passwordSha1(BREACHED));
    expect((await checker.check({ source: 'local', password: BREACHED })).kind).toBe('listed');
  });

  it('never calls the range lookup', async () => {
    const lookup = LISTING_LOOKUP();
    const checker = createBreachedPasswordChecker({ localList: LOADED, rangeLookup: lookup });
    await checker.check({ source: 'local', password: BREACHED });
    expect(lookup.lookup).not.toHaveBeenCalled();
  });
});

describe('createBreachedPasswordChecker: k_anonymity', () => {
  it('answers listed and not_listed from the lookup, given the digest and the realm', async () => {
    const lookup = LISTING_LOOKUP();
    const checker = createBreachedPasswordChecker({ rangeLookup: lookup, localList: LOADED });

    expect(
      await checker.check({ source: 'k_anonymity', password: BREACHED, realm: 'acme' })
    ).toEqual({ kind: 'listed', source: 'k_anonymity' });
    expect(lookup.lookup).toHaveBeenLastCalledWith(passwordSha1(BREACHED), { realm: 'acme' });

    expect(await checker.check({ source: 'k_anonymity', password: UNBREACHED })).toEqual({
      kind: 'not_listed',
      source: 'k_anonymity',
    });
    expect(lookup.lookup).toHaveBeenLastCalledWith(passwordSha1(UNBREACHED), undefined);
    // The lookup gets the digest, never the password.
    for (const call of lookup.lookup.mock.calls) {
      expect(JSON.stringify(call)).not.toContain(BREACHED);
      expect(JSON.stringify(call)).not.toContain(UNBREACHED);
    }
  });

  it('is failed with not_configured without a lookup', async () => {
    expect(
      await createBreachedPasswordChecker({ localList: LOADED }).check({
        source: 'k_anonymity',
        password: BREACHED,
      })
    ).toEqual({ kind: 'failed', source: 'k_anonymity', reason: 'not_configured' });
  });

  it("is failed with the lookup's reason, and never throws", async () => {
    const reasons: BreachLookupFailureReason[] = [
      'lookup_blocked',
      'lookup_failed',
      'bad_response',
    ];
    for (const reason of reasons) {
      const checker = createBreachedPasswordChecker({
        rangeLookup: rangeLookup(async () => {
          throw new BreachLookupError(reason, 'no answer');
        }),
      });
      expect(await checker.check({ source: 'k_anonymity', password: BREACHED })).toEqual({
        kind: 'failed',
        source: 'k_anonymity',
        reason,
      });
    }
  });

  it('is failed with lookup_failed for any other error of the lookup', async () => {
    for (const error of [new Error('boom'), new TypeError('bad'), 'a string']) {
      const checker = createBreachedPasswordChecker({
        rangeLookup: rangeLookup(async () => {
          throw error;
        }),
      });
      expect(await checker.check({ source: 'k_anonymity', password: BREACHED })).toEqual({
        kind: 'failed',
        source: 'k_anonymity',
        reason: 'lookup_failed',
      });
    }
  });
});

describe('createBreachedPasswordChecker: onResult', () => {
  it('is told every result but off', async () => {
    const seen: BreachCheckOutcome[] = [];
    const failing = rangeLookup(async () => {
      throw new BreachLookupError('lookup_failed', 'down');
    });
    const full = createBreachedPasswordChecker({
      localList: LOADED,
      rangeLookup: LISTING_LOOKUP(),
      onResult: (result) => seen.push(result),
    });
    const empty = createBreachedPasswordChecker({ onResult: (result) => seen.push(result) });
    const broken = createBreachedPasswordChecker({
      localList: NOT_LOADED,
      rangeLookup: failing,
      onResult: (result) => seen.push(result),
    });

    const results = [
      await full.check({ source: 'off', password: BREACHED }),
      await full.check({ source: 'local', password: BREACHED }),
      await full.check({ source: 'local', password: UNBREACHED }),
      await full.check({ source: 'k_anonymity', password: BREACHED }),
      await full.check({ source: 'k_anonymity', password: UNBREACHED }),
      await empty.check({ source: 'local', password: BREACHED }),
      await empty.check({ source: 'k_anonymity', password: BREACHED }),
      await broken.check({ source: 'local', password: BREACHED }),
      await broken.check({ source: 'k_anonymity', password: BREACHED }),
    ];

    expect(seen).toEqual(results.slice(1));
    expect(seen).toEqual([
      { kind: 'listed', source: 'local' },
      { kind: 'not_listed', source: 'local' },
      { kind: 'listed', source: 'k_anonymity' },
      { kind: 'not_listed', source: 'k_anonymity' },
      { kind: 'failed', source: 'local', reason: 'not_configured' },
      { kind: 'failed', source: 'k_anonymity', reason: 'not_configured' },
      { kind: 'failed', source: 'local', reason: 'list_not_loaded' },
      { kind: 'failed', source: 'k_anonymity', reason: 'lookup_failed' },
    ]);
  });

  it('changes nothing when it throws', async () => {
    const onResult = vi.fn(() => {
      throw new Error('the metric is broken');
    });
    const checker = createBreachedPasswordChecker({
      localList: LOADED,
      rangeLookup: LISTING_LOOKUP(),
      onResult,
    });

    expect(await checker.check({ source: 'local', password: BREACHED })).toEqual({
      kind: 'listed',
      source: 'local',
    });
    expect(await checker.check({ source: 'k_anonymity', password: UNBREACHED })).toEqual({
      kind: 'not_listed',
      source: 'k_anonymity',
    });
    expect(
      await createBreachedPasswordChecker({ onResult }).check({
        source: 'local',
        password: BREACHED,
      })
    ).toEqual({ kind: 'failed', source: 'local', reason: 'not_configured' });
    expect(onResult).toHaveBeenCalledTimes(3);
  });
});

describe('createBreachedPasswordChecker: the source', () => {
  it('refuses a source that is not one of the breach list sources', async () => {
    const checker = createBreachedPasswordChecker({ localList: LOADED });
    await expect(checker.check({ source: 'hibp' as never, password: BREACHED })).rejects.toThrow(
      TypeError
    );
  });
});
