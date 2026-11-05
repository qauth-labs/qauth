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
    const issued = await codes.issue(ACCOUNT);
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
    expect(await codes.status(ACCOUNT)).toEqual({ issued: true, unused: 10 });
    expect(await codes.status(OTHER)).toEqual({ issued: false, unused: 0 });
  });
});

describe('redeeming a recovery code', () => {
  it('accepts a code once and then refuses it', async () => {
    const { codes } = service();
    const { codes: set } = await codes.issue(ACCOUNT);
    const code = set[3] as string;
    expect(await codes.redeem({ ...ACCOUNT, clientId: CLIENT, code })).toEqual({
      kind: 'redeemed',
    });
    expect(await codes.redeem({ ...ACCOUNT, clientId: CLIENT, code })).toEqual({
      kind: 'refused',
    });
    expect(await codes.status(ACCOUNT)).toEqual({ issued: true, unused: 9 });
    // The others still work, typed as the person may type them.
    const other = (set[7] as string).toUpperCase().replace(/-/g, ' ');
    expect(await codes.redeem({ ...ACCOUNT, clientId: CLIENT, code: other })).toEqual({
      kind: 'redeemed',
    });
  });

  it("refuses a wrong code, another account's code and one that cannot be a code", async () => {
    const { codes } = service();
    const { codes: mine } = await codes.issue(ACCOUNT);
    const { codes: theirs } = await codes.issue(OTHER);
    for (const code of [generateRecoveryCode(), theirs[0] as string, 'not-a-code-at-all']) {
      expect(await codes.redeem({ ...ACCOUNT, clientId: CLIENT, code })).toEqual({
        kind: 'refused',
      });
    }
    expect(await codes.status(ACCOUNT)).toEqual({ issued: true, unused: 10 });
    expect(await codes.redeem({ ...ACCOUNT, clientId: CLIENT, code: mine[0] as string })).toEqual({
      kind: 'redeemed',
    });
  });

  it('checks 10 hashes whatever is left and whatever is typed', async () => {
    const { hasher, codes } = service();
    const { codes: set } = await codes.issue(ACCOUNT);
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
    const { codes: set } = await codes.issue(ACCOUNT);
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
    const { codes: old } = await codes.issue(ACCOUNT);
    await codes.redeem({ ...ACCOUNT, clientId: CLIENT, code: old[0] as string });
    const { codes: fresh } = await codes.issue(ACCOUNT);
    expect(await codes.status(ACCOUNT)).toEqual({ issued: true, unused: 10 });
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
