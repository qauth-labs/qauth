import { randomBytes } from 'node:crypto';

import { grammarStep } from '@qauth-labs/server-step-grammar';
import { describe, expect, it } from 'vitest';

import {
  createCountingHasher,
  createMemoryRecoveryCodeStore,
} from '../testing/memory-recovery-codes';
import {
  createRecoveryCodeService,
  generateRecoveryCode,
  generateRecoveryCodeSet,
  normalizeRecoveryCode,
  RECOVERY_CODE_BITS,
  RECOVERY_CODE_COUNT,
  RECOVERY_CODE_PATTERN,
} from './recovery-codes';

/** Recovery codes (#649; ADR-017 Decision 8, ADR-018 §3). */

const ACCOUNT = { realmId: 'realm-1', userId: 'user-1' } as const;
const OTHER = { realmId: 'realm-1', userId: 'user-2' } as const;
const CLIENT = 'web-client';

function service() {
  const store = createMemoryRecoveryCodeStore();
  const hasher = createCountingHasher();
  let now = 1_800_000_000_000;
  const codes = createRecoveryCodeService({
    store,
    hasher,
    clock: { now: () => (now += 1), sleep: async () => undefined },
  });
  return { store, hasher, codes };
}

/** A new set for an account that holds no confirmed one. */
async function issue(
  codes: ReturnType<typeof service>['codes'],
  account: typeof ACCOUNT | typeof OTHER
) {
  const set = await codes.issue(account);
  if (set === null) throw new Error('no set issued');
  return set;
}

describe('a recovery code', () => {
  it('carries 80 bits of the CSPRNG, shown as four groups of four base32 characters', () => {
    expect(RECOVERY_CODE_BITS).toBeGreaterThanOrEqual(64);
    const code = generateRecoveryCode();
    expect(code).toMatch(RECOVERY_CODE_PATTERN);
    // Every bit of the 10 random bytes is in the code: 16 characters of 5 bits.
    expect(code.replace(/-/g, '')).toHaveLength(RECOVERY_CODE_BITS / 5);
    expect(generateRecoveryCode(() => new Uint8Array(10))).toBe('aaaa-aaaa-aaaa-aaaa');
    expect(generateRecoveryCode(() => new Uint8Array(10).fill(255))).toBe('7777-7777-7777-7777');
    expect(
      generateRecoveryCode(() => Uint8Array.from([0, 68, 50, 20, 199, 66, 84, 182, 53, 207]))
    ).toBe('abcd-efgh-ijkl-mnop');
  });

  it('refuses a source that gives fewer bytes than a code needs', () => {
    expect(() => generateRecoveryCode(() => new Uint8Array(8))).toThrow();
  });

  it('is typed back with any case, spaces and dashes', () => {
    expect(normalizeRecoveryCode('k7qd-2mvw-x4ra-p6tn')).toBe('k7qd2mvwx4rap6tn');
    expect(normalizeRecoveryCode(' K7QD 2MVW X4RA P6TN ')).toBe('k7qd2mvwx4rap6tn');
    expect(normalizeRecoveryCode('k7qd2mvwx4rap6tn')).toBe('k7qd2mvwx4rap6tn');
    // Not base32, too short, too long.
    expect(normalizeRecoveryCode('k7qd-2mvw-x4ra-p6t0')).toBeNull();
    expect(normalizeRecoveryCode('k7qd-2mvw-x4ra')).toBeNull();
    expect(normalizeRecoveryCode('k7qd-2mvw-x4ra-p6tn-a')).toBeNull();
    expect(normalizeRecoveryCode('x'.repeat(100))).toBeNull();
  });
});

describe('a set of recovery codes', () => {
  it('holds 10 distinct codes the step grammar can show', () => {
    const set = generateRecoveryCodeSet();
    expect(set).toHaveLength(RECOVERY_CODE_COUNT);
    expect(new Set(set).size).toBe(RECOVERY_CODE_COUNT);
    expect(grammarStep('recovery_codes').personal.safeParse({ codes: set }).success).toBe(true);
  });

  it('refuses a source that repeats itself', () => {
    const same = randomBytes(10);
    expect(() => generateRecoveryCodeSet(() => same)).toThrow();
  });

  it('is stored only as salted hashes from the hasher, and shown once', async () => {
    const { store, hasher, codes } = service();
    const issued = await issue(codes, ACCOUNT);
    expect(issued.codes).toHaveLength(10);
    expect(hasher.hashes).toBe(10 + 1); // the set, and the decoy
    expect(store.rows).toHaveLength(10);
    const stored = JSON.stringify(store.rows);
    for (const code of issued.codes) {
      expect(stored).not.toContain(code);
      expect(stored).not.toContain(normalizeRecoveryCode(code));
    }
    // Salted: no two hashes alike, even of one code.
    expect(new Set(store.rows.map((row) => row.hash)).size).toBe(10);
    expect(await codes.status(ACCOUNT)).toEqual({ issued: true, unused: 10, confirmed: false });
    expect(await codes.status(OTHER)).toEqual({ issued: false, unused: 0, confirmed: false });
  });
});

describe('confirming a set', () => {
  it('confirms the set shown, by its id, only while it is the account’s', async () => {
    const { codes } = service();
    const shown = await issue(codes, ACCOUNT);
    // Another sign-in replaced it before the confirmation: nothing is confirmed.
    const replacement = await issue(codes, ACCOUNT);
    expect(replacement.setId).not.toBe(shown.setId);
    expect(await codes.confirm({ ...ACCOUNT, setId: shown.setId })).toBe(false);
    expect(await codes.status(ACCOUNT)).toMatchObject({ confirmed: false });
    // Another account's set is never this one's.
    const theirs = await issue(codes, OTHER);
    expect(await codes.confirm({ ...ACCOUNT, setId: theirs.setId })).toBe(false);
    expect(await codes.confirm({ ...ACCOUNT, setId: replacement.setId })).toBe(true);
    expect(await codes.status(ACCOUNT)).toMatchObject({ confirmed: true });
    expect(await codes.status(OTHER)).toMatchObject({ confirmed: false });
  });

  it('issues no set over one the person confirmed, and a regeneration replaces it', async () => {
    const { codes } = service();
    const saved = await issue(codes, ACCOUNT);
    await codes.confirm({ ...ACCOUNT, setId: saved.setId });
    expect(await codes.issue(ACCOUNT)).toBeNull();
    expect(
      await codes.redeem({ ...ACCOUNT, clientId: CLIENT, code: saved.codes[0] as string })
    ).toEqual({ kind: 'redeemed' });

    const regenerated = await codes.replace(ACCOUNT);
    expect(await codes.status(ACCOUNT)).toEqual({ issued: true, unused: 10, confirmed: false });
    expect(
      await codes.redeem({ ...ACCOUNT, clientId: CLIENT, code: saved.codes[1] as string })
    ).toEqual({ kind: 'refused' });
    expect(
      await codes.redeem({ ...ACCOUNT, clientId: CLIENT, code: regenerated.codes[0] as string })
    ).toEqual({ kind: 'redeemed' });
  });
});

describe('redeeming a recovery code', () => {
  it('accepts a code once and then refuses it', async () => {
    const { codes } = service();
    const { codes: set } = await issue(codes, ACCOUNT);
    const code = set[3] as string;
    expect(await codes.redeem({ ...ACCOUNT, clientId: CLIENT, code })).toEqual({
      kind: 'redeemed',
    });
    expect(await codes.redeem({ ...ACCOUNT, clientId: CLIENT, code })).toEqual({
      kind: 'refused',
    });
    expect(await codes.status(ACCOUNT)).toEqual({ issued: true, unused: 9, confirmed: false });
    // The others still work, typed as the person may type them.
    const other = (set[7] as string).toUpperCase().replace(/-/g, ' ');
    expect(await codes.redeem({ ...ACCOUNT, clientId: CLIENT, code: other })).toEqual({
      kind: 'redeemed',
    });
  });

  it("refuses a wrong code, another account's code and one that cannot be a code", async () => {
    const { codes } = service();
    const { codes: mine } = await issue(codes, ACCOUNT);
    const { codes: theirs } = await issue(codes, OTHER);
    for (const code of [generateRecoveryCode(), theirs[0] as string, 'not-a-code-at-all']) {
      expect(await codes.redeem({ ...ACCOUNT, clientId: CLIENT, code })).toEqual({
        kind: 'refused',
      });
    }
    expect(await codes.status(ACCOUNT)).toEqual({ issued: true, unused: 10, confirmed: false });
    expect(await codes.redeem({ ...ACCOUNT, clientId: CLIENT, code: mine[0] as string })).toEqual({
      kind: 'redeemed',
    });
  });

  it('checks 10 hashes whatever is left and whatever is typed', async () => {
    const { hasher, codes } = service();
    const { codes: set } = await issue(codes, ACCOUNT);
    const checked = async (code: string) => {
      const before = hasher.verifications;
      await codes.redeem({ ...ACCOUNT, clientId: CLIENT, code });
      return hasher.verifications - before;
    };
    expect(await checked(set[0] as string)).toBe(10);
    expect(await checked(generateRecoveryCode())).toBe(10);
    expect(await checked('not-a-code-at-all')).toBe(10);
    for (const code of set.slice(1, 9)) await codes.redeem({ ...ACCOUNT, clientId: CLIENT, code });
    // One code left, and an account with none: still 10.
    expect(await checked(generateRecoveryCode())).toBe(10);
    expect(await checked(set[9] as string)).toBe(10);
    expect(await checked(generateRecoveryCode())).toBe(10);
    const none = service();
    const before = none.hasher.verifications;
    await none.codes.redeem({ ...ACCOUNT, clientId: CLIENT, code: generateRecoveryCode() });
    expect(none.hasher.verifications - before).toBe(10);
  });

  it('refuses a code another round took first', async () => {
    const { store, codes } = service();
    const { codes: set } = await issue(codes, ACCOUNT);
    store.loseNextRace = true;
    expect(await codes.redeem({ ...ACCOUNT, clientId: CLIENT, code: set[0] as string })).toEqual({
      kind: 'refused',
    });
    expect(await codes.redeem({ ...ACCOUNT, clientId: CLIENT, code: set[0] as string })).toEqual({
      kind: 'refused',
    });
  });

  it('refuses every code of a set a new one replaced', async () => {
    const { codes } = service();
    const { codes: old } = await issue(codes, ACCOUNT);
    await codes.redeem({ ...ACCOUNT, clientId: CLIENT, code: old[0] as string });
    const { codes: fresh } = await issue(codes, ACCOUNT);
    expect(await codes.status(ACCOUNT)).toEqual({ issued: true, unused: 10, confirmed: false });
    for (const code of old) {
      expect(await codes.redeem({ ...ACCOUNT, clientId: CLIENT, code })).toEqual({
        kind: 'refused',
      });
    }
    expect(await codes.redeem({ ...ACCOUNT, clientId: CLIENT, code: fresh[0] as string })).toEqual({
      kind: 'redeemed',
    });
  });
});

describe('a code found by itself (#655)', () => {
  /** A service whose lookup finds `findable`'s sets, counting its digests. */
  function lookupService(findable: ReadonlySet<string>) {
    const store = createMemoryRecoveryCodeStore();
    const hasher = createCountingHasher();
    const digests: string[] = [];
    const codes = createRecoveryCodeService({
      store,
      hasher,
      clock: { now: () => 1_800_000_000_000, sleep: async () => undefined },
      lookup: {
        digest: async ({ realmId, code }) => {
          digests.push(code);
          return `${realmId}:${code}`;
        },
        findable: async ({ userId }) => findable.has(userId),
      },
    });
    return { store, codes, digests };
  }

  it('carries a lookup digest of each code only in the sets of a findable account', async () => {
    const { store, codes } = lookupService(new Set([ACCOUNT.userId]));
    const found = await issue(codes, ACCOUNT);
    await issue(codes, OTHER);
    const of = (userId: string) => store.rows.filter((row) => row.userId === userId);
    expect(of(ACCOUNT.userId).map((row) => row.lookupDigest)).toEqual(
      found.codes.map((code) => `${ACCOUNT.realmId}:${code.replaceAll('-', '')}`)
    );
    expect(of(OTHER.userId).every((row) => row.lookupDigest === null)).toBe(true);
  });

  it("names the code's account, typed in any case or spacing, and takes nothing", async () => {
    const { store, codes } = lookupService(new Set([ACCOUNT.userId]));
    const set = await issue(codes, ACCOUNT);
    const typed = ` ${(set.codes[3] ?? '').toUpperCase().replaceAll('-', ' ')} `;
    expect(await codes.findAccount?.({ realmId: ACCOUNT.realmId, code: typed })).toEqual({
      userId: ACCOUNT.userId,
    });
    expect(store.rows.every((row) => row.usedAt === null)).toBe(true);
    // Another realm's lookup finds nothing.
    expect(await codes.findAccount?.({ realmId: 'realm-2', code: typed })).toBeNull();
  });

  it('finds nothing for a used code, a wrong one or a code of an account that is not findable', async () => {
    const { codes, digests } = lookupService(new Set([ACCOUNT.userId]));
    const set = await issue(codes, ACCOUNT);
    const other = await issue(codes, OTHER);
    const [first] = set.codes;
    await codes.redeem({ ...ACCOUNT, clientId: CLIENT, code: first ?? '' });
    for (const code of [first, 'aaaa-bbbb-cccc-dddd', other.codes[0]]) {
      expect(await codes.findAccount?.({ realmId: ACCOUNT.realmId, code: code ?? '' })).toBeNull();
    }
    // An answer that cannot be a code costs one digest too.
    const before = digests.length;
    expect(await codes.findAccount?.({ realmId: ACCOUNT.realmId, code: 'not a code' })).toBeNull();
    expect(digests.length).toBe(before + 1);
  });

  it('offers no lookup without one', () => {
    expect(service().codes.findAccount).toBeUndefined();
  });
});
