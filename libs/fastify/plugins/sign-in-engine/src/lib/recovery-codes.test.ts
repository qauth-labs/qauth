import { createHash, randomBytes } from 'node:crypto';

import {
  RECOVERY_CODE_COUNT,
  RECOVERY_CODE_PATTERN,
  type RecoveryCodeHasher,
  type RecoveryCodeLookup,
} from '@qauth-labs/server-sign-in-engine';
import { describe, expect, it, vi } from 'vitest';

import {
  createRepositoryRecoveryCodes,
  type RecoveryCodeRepositories,
  type RecoveryCodeUse,
} from './recovery-codes';

const REALM = '0199fa20-0000-7000-8000-00000000aaaa';
const USER = '0199fa20-5e1a-7000-8000-000000000001';
const ACCOUNT = { realmId: REALM, userId: USER };

/** A salted hash that is not Argon2id, for speed: `salt$sha256(salt|code)`. */
const hasher: RecoveryCodeHasher = {
  async hash(code) {
    const salt = randomBytes(8).toString('hex');
    return `${salt}$${createHash('sha256').update(`${salt}|${code}`).digest('hex')}`;
  },
  async verify(hash, code) {
    const [salt, digest] = hash.split('$');
    return createHash('sha256').update(`${salt}|${code}`).digest('hex') === digest;
  },
};

/** A transaction id, so a test sees which writes shared one. */
interface FakeTx {
  readonly id: number;
}

interface FakeRow {
  id: string;
  realmId: string;
  userId: string;
  codeHash: string;
  lookupDigest?: string;
  usedAt?: number;
  confirmedAt?: number;
}

function setup(options: { readonly lookup?: RecoveryCodeLookup } = {}) {
  const rows: FakeRow[] = [];
  const writesIn: (FakeTx | undefined)[] = [];
  let next = 0;
  const repos: RecoveryCodeRepositories<FakeTx> = {
    userRecoveryCodes: {
      async status(realmId, userId) {
        const mine = rows.filter((row) => row.realmId === realmId && row.userId === userId);
        return {
          issued: mine.length > 0,
          unused: mine.filter((row) => row.usedAt === undefined).length,
          confirmed: mine.length > 0 && mine.every((row) => row.confirmedAt !== undefined),
        };
      },
      async confirmSet({ realmId, userId, setId, confirmedAt }, tx) {
        writesIn.push(tx);
        const mine = rows.filter((row) => row.realmId === realmId && row.userId === userId);
        if (!mine.some((row) => row.id === setId)) return false;
        for (const row of mine) row.confirmedAt ??= confirmedAt;
        return true;
      },
      async findUnused(realmId, userId) {
        return rows
          .filter(
            (row) => row.realmId === realmId && row.userId === userId && row.usedAt === undefined
          )
          .map(({ id, codeHash }) => ({ id, codeHash }));
      },
      async findByLookupDigest(realmId, digest) {
        const owners = new Set(
          rows
            .filter(
              (row) =>
                row.realmId === realmId && row.lookupDigest === digest && row.usedAt === undefined
            )
            .map((row) => row.userId)
        );
        const [userId] = owners;
        return owners.size === 1 && userId !== undefined ? { userId } : null;
      },
      async replaceSet({ realmId, userId, codeHashes, lookupDigests, keepConfirmed }, tx) {
        writesIn.push(tx);
        const mine = (row: FakeRow) => row.realmId === realmId && row.userId === userId;
        if (
          keepConfirmed === true &&
          rows.some((row) => mine(row) && row.confirmedAt !== undefined)
        ) {
          return null;
        }
        const kept = rows.filter((row) => !mine(row));
        rows.splice(0, rows.length, ...kept);
        const setId = `code-${next + 1}`;
        for (const [index, codeHash] of codeHashes.entries()) {
          next += 1;
          const lookupDigest = lookupDigests?.[index];
          rows.push({
            id: `code-${next}`,
            realmId,
            userId,
            codeHash,
            ...(lookupDigest === undefined ? {} : { lookupDigest }),
          });
        }
        return setId;
      },
      async markUsed({ realmId, userId, id, usedAt }, tx) {
        writesIn.push(tx);
        const row = rows.find(
          (candidate) =>
            candidate.id === id && candidate.realmId === realmId && candidate.userId === userId
        );
        if (row === undefined || row.usedAt !== undefined) return false;
        row.usedAt = usedAt;
        return true;
      },
    },
  };
  let txs = 0;
  let failNextCommit = false;
  const transaction = async <T>(work: (tx: FakeTx) => Promise<T>): Promise<T> => {
    const snapshot = rows.map((row) => ({ ...row }));
    try {
      txs += 1;
      const result = await work({ id: txs });
      if (failNextCommit) {
        failNextCommit = false;
        throw new Error('commit failed');
      }
      return result;
    } catch (error) {
      rows.splice(0, rows.length, ...snapshot);
      throw error;
    }
  };
  const used = vi.fn(async (_use: RecoveryCodeUse, _tx: FakeTx) => undefined);
  const committed = vi.fn(async (_use: RecoveryCodeUse) => undefined);
  const regenerated = vi.fn(async (_account: typeof ACCOUNT) => undefined);
  const ceilingReached = vi.fn(async (_account: typeof ACCOUNT) => undefined);
  const report = vi.fn();
  const codes = createRepositoryRecoveryCodes(repos, transaction, {
    hasher,
    used,
    committed,
    regenerated,
    ceilingReached,
    report,
    ...(options.lookup === undefined ? {} : { lookup: options.lookup }),
  });
  return {
    codes,
    rows,
    writesIn,
    used,
    committed,
    regenerated,
    ceilingReached,
    report,
    failCommit: () => {
      failNextCommit = true;
    },
  };
}

/** A new set for the account, which holds no confirmed one. */
async function issue(codes: ReturnType<typeof setup>['codes']) {
  const set = await codes.issue(ACCOUNT);
  if (set === null) throw new Error('no set issued');
  return set;
}

const redeem = (codes: ReturnType<typeof setup>['codes'], code: string) =>
  codes.redeem({ ...ACCOUNT, clientId: 'client-a', code });

describe('the recovery codes over the repository (#649)', () => {
  it('issues 10 codes of the shown form and stores only their hashes', async () => {
    const { codes, rows } = setup();
    const { codes: set } = await issue(codes);
    expect(set).toHaveLength(RECOVERY_CODE_COUNT);
    for (const code of set) expect(code).toMatch(RECOVERY_CODE_PATTERN);
    expect(rows).toHaveLength(RECOVERY_CODE_COUNT);
    const stored = JSON.stringify(rows);
    for (const code of set) {
      expect(stored).not.toContain(code);
      expect(stored).not.toContain(code.replaceAll('-', ''));
    }
    await expect(codes.status(ACCOUNT)).resolves.toEqual({
      issued: true,
      unused: 10,
      confirmed: false,
    });
  });

  it('takes a code once, records its use in the take’s transaction, and tells the user after', async () => {
    const { codes, used, committed, writesIn } = setup();
    const { codes: set } = await issue(codes);
    await expect(redeem(codes, set[3])).resolves.toEqual({ kind: 'redeemed' });
    await expect(redeem(codes, set[3])).resolves.toEqual({ kind: 'refused' });
    const use = { ...ACCOUNT, clientId: 'client-a', unusedCodes: 9 };
    expect(used).toHaveBeenCalledTimes(1);
    expect(used).toHaveBeenCalledWith(use, expect.objectContaining({ id: expect.any(Number) }));
    // The use is recorded in the transaction that took the code.
    const [, takenIn] = used.mock.calls[0];
    expect(writesIn).toContain(takenIn);
    expect(committed).toHaveBeenCalledTimes(1);
    expect(committed).toHaveBeenCalledWith(use);
    await expect(codes.status(ACCOUNT)).resolves.toEqual({
      issued: true,
      unused: 9,
      confirmed: false,
    });
  });

  it('refuses a wrong code with no record and no notice', async () => {
    const { codes, used, committed } = setup();
    await issue(codes);
    await expect(redeem(codes, 'aaaa-aaaa-aaaa-aaaa')).resolves.toEqual({ kind: 'refused' });
    await expect(redeem(codes, 'not a code')).resolves.toEqual({ kind: 'refused' });
    expect(used).not.toHaveBeenCalled();
    expect(committed).not.toHaveBeenCalled();
  });

  it('keeps the code unused when its record fails, and refuses the round', async () => {
    const { codes, used, committed } = setup();
    const { codes: set } = await issue(codes);
    used.mockRejectedValueOnce(new Error('event store down'));
    await expect(redeem(codes, set[0])).rejects.toThrow('event store down');
    expect(committed).not.toHaveBeenCalled();
    await expect(codes.status(ACCOUNT)).resolves.toEqual({
      issued: true,
      unused: 10,
      confirmed: false,
    });
    await expect(redeem(codes, set[0])).resolves.toEqual({ kind: 'redeemed' });
  });

  it('keeps the code unused when the take does not commit', async () => {
    const { codes, committed, failCommit } = setup();
    const { codes: set } = await issue(codes);
    failCommit();
    await expect(redeem(codes, set[0])).rejects.toThrow('commit failed');
    expect(committed).not.toHaveBeenCalled();
    await expect(codes.status(ACCOUNT)).resolves.toEqual({
      issued: true,
      unused: 10,
      confirmed: false,
    });
  });

  it('reports a notice that fails after the take, and the code stays used', async () => {
    const { codes, committed, report } = setup();
    const { codes: set } = await issue(codes);
    committed.mockRejectedValueOnce(new Error('mail down'));
    await expect(redeem(codes, set[0])).resolves.toEqual({ kind: 'redeemed' });
    expect(report).toHaveBeenCalledWith(expect.any(Error), 'the recovery-code-used notice');
    await expect(codes.status(ACCOUNT)).resolves.toEqual({
      issued: true,
      unused: 9,
      confirmed: false,
    });
  });

  it('regenerates: every code of the old set stops working, and the user is told', async () => {
    const { codes, regenerated } = setup();
    const { codes: old } = await issue(codes);
    expect(regenerated).not.toHaveBeenCalled();
    const { codes: fresh } = await codes.regenerate(ACCOUNT);
    expect(regenerated).toHaveBeenCalledWith(ACCOUNT);
    for (const code of old) {
      await expect(redeem(codes, code)).resolves.toEqual({ kind: 'refused' });
    }
    await expect(redeem(codes, fresh[0])).resolves.toEqual({ kind: 'redeemed' });
  });

  it('confirms the set the person saved, and a regenerated set waits for its own confirmation', async () => {
    const { codes } = setup();
    const { setId } = await issue(codes);
    await expect(codes.confirm({ ...ACCOUNT, setId })).resolves.toBe(true);
    await expect(codes.status(ACCOUNT)).resolves.toEqual({
      issued: true,
      unused: 10,
      confirmed: true,
    });
    // A sign-in's issuance keeps the confirmed set; a regeneration replaces it.
    await expect(codes.issue(ACCOUNT)).resolves.toBeNull();
    const regenerated = await codes.regenerate(ACCOUNT);
    await expect(codes.status(ACCOUNT)).resolves.toMatchObject({ confirmed: false });
    // The set confirmed before is gone: confirming it again confirms nothing.
    await expect(codes.confirm({ ...ACCOUNT, setId })).resolves.toBe(false);
    await expect(codes.confirm({ ...ACCOUNT, setId: regenerated.setId })).resolves.toBe(true);
  });

  it('passes the ceiling on to the caller', async () => {
    const { codes, ceilingReached } = setup();
    await codes.ceilingReached(ACCOUNT);
    expect(ceilingReached).toHaveBeenCalledWith(ACCOUNT);
  });
});

describe('the recovery codes found by a code alone (#655)', () => {
  const lookup: RecoveryCodeLookup = {
    digest: async ({ realmId, code }) =>
      createHash('sha256').update(`${realmId}|${code}`).digest('hex'),
    findable: async ({ userId }) => userId === USER,
  };

  it('stores a lookup digest of each code of a findable account, and finds the account by one', async () => {
    const { codes, rows } = setup({ lookup });
    const { codes: set } = await issue(codes);
    expect(rows.every((row) => typeof row.lookupDigest === 'string')).toBe(true);
    const stored = JSON.stringify(rows);
    for (const code of set) expect(stored).not.toContain(code.replaceAll('-', ''));
    await expect(codes.findAccount?.({ realmId: REALM, code: set[5] })).resolves.toEqual({
      userId: USER,
    });
    await expect(
      codes.findAccount?.({ realmId: REALM, code: 'aaaa-aaaa-aaaa-aaaa' })
    ).resolves.toBeNull();
  });

  it('has no lookup without one', () => {
    expect(setup().codes.findAccount).toBeUndefined();
  });
});
