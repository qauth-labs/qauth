import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  createKidDenylist,
  DEFAULT_KID_DENYLIST_REFRESH_INTERVAL_MS,
  type DeniedKid,
  KID_DENYLIST_MAX_STALENESS_MS,
  type KidDenylistRead,
} from './kid-denylist';

const REALM = '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e01';
const OTHER_REALM = '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e02';
const T0 = 1_800_000_000_000;

/** A complete read of `rows`, as the database answers. */
function complete(rows: readonly DeniedKid[]): KidDenylistRead {
  return { entries: [...rows], complete: true };
}

/** A read of the shared cache's snapshot, which only adds. */
function cached(rows: readonly DeniedKid[]): KidDenylistRead {
  return { entries: [...rows], complete: false };
}

/** A loader over a list the test changes, and a clock it moves. */
function fixture(initial: DeniedKid[] = []) {
  const clock = { now: T0 };
  const rows: DeniedKid[] = [...initial];
  const load = vi.fn(async (): Promise<KidDenylistRead> => complete(rows));
  const denylist = createKidDenylist({ load, now: () => clock.now });
  return { clock, rows, load, denylist };
}

afterEach(() => {
  vi.useRealTimers();
});

describe('createKidDenylist (#551)', () => {
  it('is not current, and denies nothing, before its first read: a verify site fails closed', () => {
    const { denylist } = fixture([{ realmId: REALM, kid: 'k1' }]);
    expect(denylist.isCurrent()).toBe(false);
    expect(denylist.isDenied(REALM, 'k1')).toBe(false);
    expect(denylist.revision()).toBe(0);
  });

  it('answers from the list it read, by realm and kid', async () => {
    const { denylist } = fixture([{ realmId: REALM, kid: 'k1' }]);
    await denylist.refresh();
    expect(denylist.isCurrent()).toBe(true);
    expect(denylist.isDenied(REALM, 'k1')).toBe(true);
    // The realm id in upper case is the same realm; a kid is compared byte for byte.
    expect(denylist.isDenied(REALM.toUpperCase(), 'k1')).toBe(true);
    expect(denylist.isDenied(REALM, 'K1')).toBe(false);
    expect(denylist.isDenied(OTHER_REALM, 'k1')).toBe(false);
  });

  it('raises its revision only when the set of denied keys changes', async () => {
    const { denylist, rows } = fixture([{ realmId: REALM, kid: 'k1' }]);
    await denylist.refresh();
    const first = denylist.revision();
    await denylist.refresh();
    expect(denylist.revision()).toBe(first);
    rows.push({ realmId: REALM, kid: 'k2' });
    await denylist.refresh();
    expect(denylist.revision()).toBe(first + 1);
    expect(denylist.isDenied(REALM, 'k2')).toBe(true);
    // The same set in another order is no change.
    rows.reverse();
    await denylist.refresh();
    expect(denylist.revision()).toBe(first + 1);
  });

  it('only adds from the shared cache: a snapshot that lacks a kid it knew, stale or tampered with, does not let the key back', async () => {
    const { denylist, load } = fixture([{ realmId: REALM, kid: 'k1' }]);
    await denylist.refresh();
    const revision = denylist.revision();
    load.mockResolvedValueOnce(cached([]));
    await denylist.refresh();
    expect(denylist.isDenied(REALM, 'k1')).toBe(true);
    expect(denylist.revision()).toBe(revision);
  });

  it('drops a kid only the shared cache named at the next database read that began after it learned it', async () => {
    const { denylist, load, clock } = fixture();
    await denylist.refresh();
    // A snapshot names a kid the table never held: written into the cache.
    load.mockResolvedValueOnce(cached([{ realmId: REALM, kid: 'forged' }]));
    await denylist.refresh();
    expect(denylist.isDenied(REALM, 'forged')).toBe(true);
    clock.now += 1;
    await denylist.refresh();
    expect(denylist.isDenied(REALM, 'forged')).toBe(false);
  });

  it('keeps what it learned after a database read began, which the read may have missed', async () => {
    const { denylist, load, clock } = fixture();
    await denylist.refresh();
    let release: () => void = () => undefined;
    load.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          release = () => resolve(complete([]));
        })
    );
    const running = denylist.refresh();
    clock.now += 10;
    // The retiring node's own kid, after the read began.
    denylist.add([{ realmId: REALM, kid: 'retired' }]);
    release();
    await running;
    expect(denylist.isDenied(REALM, 'retired')).toBe(true);
  });

  it('ignores a database read older than one it took already', async () => {
    const { denylist, load, clock, rows } = fixture();
    let release: () => void = () => undefined;
    load.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          release = () => resolve(complete([]));
        })
    );
    const slow = denylist.refresh();
    clock.now += KID_DENYLIST_MAX_STALENESS_MS + 1;
    // The slow read hangs past the bound: a new one runs, and sees the kid.
    rows.push({ realmId: REALM, kid: 'k1' });
    await denylist.refresh();
    expect(denylist.isDenied(REALM, 'k1')).toBe(true);
    release();
    await slow;
    expect(denylist.isDenied(REALM, 'k1')).toBe(true);
  });

  it('counts a read from when its query began: an older query drops nothing learned since, and is no fresher', async () => {
    const { denylist, load, clock } = fixture();
    await denylist.refresh();
    // The snapshot names the retired kid a second later.
    clock.now += 1_000;
    load.mockResolvedValueOnce(cached([{ realmId: REALM, kid: 'retired' }]));
    await denylist.refresh();
    // A call a second after that waits for a database query an earlier call
    // started before the retirement: it lacks the kid.
    clock.now += 1_000;
    load.mockResolvedValueOnce({ entries: [], complete: true, ageMs: 1_500 });
    await denylist.refresh();
    expect(denylist.isDenied(REALM, 'retired')).toBe(true);
    // A query that began after the copy learned it drops it, if the table lacks it.
    clock.now += 1;
    await denylist.refresh();
    expect(denylist.isDenied(REALM, 'retired')).toBe(false);

    // A query older than the bound leaves the copy as stale as it was.
    clock.now += KID_DENYLIST_MAX_STALENESS_MS + 10;
    expect(denylist.isCurrent()).toBe(false);
    load.mockResolvedValueOnce({ entries: [], complete: true, ageMs: 5 });
    await denylist.refresh();
    expect(denylist.isCurrent()).toBe(true);
    clock.now += KID_DENYLIST_MAX_STALENESS_MS + 10;
    load.mockResolvedValueOnce({
      entries: [],
      complete: true,
      ageMs: KID_DENYLIST_MAX_STALENESS_MS + 5,
    });
    await denylist.refresh();
    expect(denylist.isCurrent()).toBe(false);
  });

  it('denies what the node that retired a key adds, at once and without a read', async () => {
    const { denylist, load } = fixture();
    await denylist.refresh();
    const revision = denylist.revision();
    denylist.add([{ realmId: REALM, kid: 'k1' }]);
    expect(denylist.isDenied(REALM, 'k1')).toBe(true);
    expect(denylist.revision()).toBe(revision + 1);
    denylist.add([{ realmId: REALM, kid: 'k1' }]);
    expect(denylist.revision()).toBe(revision + 1);
    expect(load).toHaveBeenCalledTimes(1);
    expect(() => denylist.add([{ realmId: REALM, kid: '' }])).toThrow(TypeError);
  });

  it('goes stale past the bound when no read succeeds, and keeps what it knew', async () => {
    const { denylist, load, clock } = fixture([{ realmId: REALM, kid: 'k1' }]);
    await denylist.refresh();
    load.mockRejectedValue(new Error('database down'));
    clock.now = T0 + KID_DENYLIST_MAX_STALENESS_MS;
    await expect(denylist.refresh()).rejects.toThrow('database down');
    expect(denylist.isCurrent()).toBe(true);
    clock.now += 1;
    expect(denylist.isCurrent()).toBe(false);
    expect(denylist.isDenied(REALM, 'k1')).toBe(true);
    // One read that succeeds makes it current again.
    load.mockResolvedValue(complete([{ realmId: REALM, kid: 'k1' }]));
    await denylist.refresh();
    expect(denylist.isCurrent()).toBe(true);
  });

  it('refuses a read that is not a list of denied keys, and keeps the copy', async () => {
    const { denylist, load } = fixture([{ realmId: REALM, kid: 'k1' }]);
    await denylist.refresh();
    for (const answer of [
      null,
      [{ realmId: REALM, kid: 'k1' }],
      { entries: [{ realmId: REALM }], complete: true },
      { entries: [{ realmId: REALM, kid: '' }], complete: false },
      { entries: [{ realmId: REALM, kid: 'k1' }] },
      { entries: [], complete: true, ageMs: -1 },
      { entries: [], complete: true, ageMs: '5' },
      'k1',
    ]) {
      load.mockResolvedValueOnce(answer as never);
      await expect(denylist.refresh()).rejects.toThrow(TypeError);
    }
    expect(denylist.isDenied(REALM, 'k1')).toBe(true);
  });

  it('reads again after a read that was running when refresh was asked', async () => {
    const { denylist, load, rows } = fixture();
    let release: () => void = () => undefined;
    load.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          release = () => resolve(complete([]));
        })
    );
    const running = denylist.refresh();
    // The change lands while the first read runs: it may have missed it.
    rows.push({ realmId: REALM, kid: 'k1' });
    const after = denylist.refresh();
    const alsoAfter = denylist.refresh();
    release();
    await running;
    await Promise.all([after, alsoAfter]);
    expect(load).toHaveBeenCalledTimes(2);
    expect(denylist.isDenied(REALM, 'k1')).toBe(true);
  });

  it('times its staleness from when the read began, not when it ended', async () => {
    const { denylist, load, clock } = fixture();
    load.mockImplementationOnce(async () => {
      clock.now += 10_000;
      return complete([]);
    });
    await denylist.refresh();
    clock.now = T0 + KID_DENYLIST_MAX_STALENESS_MS + 1;
    expect(denylist.isCurrent()).toBe(false);
  });

  it('reads on a timer once started, tells of a failed read, and stops', async () => {
    vi.useFakeTimers();
    const errors: unknown[] = [];
    const rows: DeniedKid[] = [];
    const load = vi.fn(async () => complete(rows));
    const denylist = createKidDenylist({ load, onError: (error) => errors.push(error) });
    denylist.start();
    denylist.start();
    await vi.advanceTimersByTimeAsync(DEFAULT_KID_DENYLIST_REFRESH_INTERVAL_MS);
    expect(load).toHaveBeenCalledTimes(1);
    rows.push({ realmId: REALM, kid: 'k1' });
    await vi.advanceTimersByTimeAsync(DEFAULT_KID_DENYLIST_REFRESH_INTERVAL_MS);
    expect(denylist.isDenied(REALM, 'k1')).toBe(true);
    load.mockRejectedValueOnce(new Error('redis and database down'));
    await vi.advanceTimersByTimeAsync(DEFAULT_KID_DENYLIST_REFRESH_INTERVAL_MS);
    expect(errors).toEqual([new Error('redis and database down')]);
    denylist.stop();
    await vi.advanceTimersByTimeAsync(10 * DEFAULT_KID_DENYLIST_REFRESH_INTERVAL_MS);
    expect(load).toHaveBeenCalledTimes(3);
  });

  it.each([
    [{ refreshIntervalMs: 0 }],
    [{ maxStalenessMs: -1 }],
    [{ refreshIntervalMs: 1.5 }],
    [{ refreshIntervalMs: 30_000, maxStalenessMs: 30_000 }],
    [{ load: undefined }],
  ])('refuses the options %j', (overrides) => {
    expect(() =>
      createKidDenylist({ load: async () => complete([]), ...overrides } as never)
    ).toThrow(TypeError);
  });
});
