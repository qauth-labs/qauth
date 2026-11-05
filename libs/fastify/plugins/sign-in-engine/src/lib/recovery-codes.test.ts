import { createHash, randomBytes } from 'node:crypto';

import {
  RECOVERY_CODE_COUNT,
  RECOVERY_CODE_PATTERN,
  type RecoveryCodeHasher,
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
  usedAt?: number;
}

function setup() {
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
        };
      },
      async findUnused(realmId, userId) {
        return rows
          .filter(
            (row) => row.realmId === realmId && row.userId === userId && row.usedAt === undefined
          )
          .map(({ id, codeHash }) => ({ id, codeHash }));
      },
      async replaceSet({ realmId, userId, codeHashes }, tx) {
        writesIn.push(tx);
        const kept = rows.filter((row) => row.realmId !== realmId || row.userId !== userId);
        rows.splice(0, rows.length, ...kept);
        for (const codeHash of codeHashes) {
          next += 1;
          rows.push({ id: `code-${next}`, realmId, userId, codeHash });
        }
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

const redeem = (codes: ReturnType<typeof setup>['codes'], code: string) =>
  codes.redeem({ ...ACCOUNT, clientId: 'client-a', code });

describe('the recovery codes over the repository (#649)', () => {
  it('issues 10 codes of the shown form and stores only their hashes', async () => {
    const { codes, rows } = setup();
    const { codes: set } = await codes.issue(ACCOUNT);
    expect(set).toHaveLength(RECOVERY_CODE_COUNT);
    for (const code of set) expect(code).toMatch(RECOVERY_CODE_PATTERN);
    expect(rows).toHaveLength(RECOVERY_CODE_COUNT);
    const stored = JSON.stringify(rows);
    for (const code of set) {
      expect(stored).not.toContain(code);
      expect(stored).not.toContain(code.replaceAll('-', ''));
    }
    await expect(codes.status(ACCOUNT)).resolves.toEqual({ issued: true, unused: 10 });
  });

  it('takes a code once, records its use in the take’s transaction, and tells the user after', async () => {
    const { codes, used, committed, writesIn } = setup();
    const { codes: set } = await codes.issue(ACCOUNT);
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
    await expect(codes.status(ACCOUNT)).resolves.toEqual({ issued: true, unused: 9 });
  });

  it('refuses a wrong code with no record and no notice', async () => {
    const { codes, used, committed } = setup();
    await codes.issue(ACCOUNT);
    await expect(redeem(codes, 'aaaa-aaaa-aaaa-aaaa')).resolves.toEqual({ kind: 'refused' });
    await expect(redeem(codes, 'not a code')).resolves.toEqual({ kind: 'refused' });
    expect(used).not.toHaveBeenCalled();
    expect(committed).not.toHaveBeenCalled();
  });

  it('keeps the code unused when its record fails, and refuses the round', async () => {
    const { codes, used, committed } = setup();
    const { codes: set } = await codes.issue(ACCOUNT);
    used.mockRejectedValueOnce(new Error('event store down'));
    await expect(redeem(codes, set[0])).rejects.toThrow('event store down');
    expect(committed).not.toHaveBeenCalled();
    await expect(codes.status(ACCOUNT)).resolves.toEqual({ issued: true, unused: 10 });
    await expect(redeem(codes, set[0])).resolves.toEqual({ kind: 'redeemed' });
  });

  it('keeps the code unused when the take does not commit', async () => {
    const { codes, committed, failCommit } = setup();
    const { codes: set } = await codes.issue(ACCOUNT);
    failCommit();
    await expect(redeem(codes, set[0])).rejects.toThrow('commit failed');
    expect(committed).not.toHaveBeenCalled();
    await expect(codes.status(ACCOUNT)).resolves.toEqual({ issued: true, unused: 10 });
  });

  it('reports a notice that fails after the take, and the code stays used', async () => {
    const { codes, committed, report } = setup();
    const { codes: set } = await codes.issue(ACCOUNT);
    committed.mockRejectedValueOnce(new Error('mail down'));
    await expect(redeem(codes, set[0])).resolves.toEqual({ kind: 'redeemed' });
    expect(report).toHaveBeenCalledWith(expect.any(Error), 'the recovery-code-used notice');
    await expect(codes.status(ACCOUNT)).resolves.toEqual({ issued: true, unused: 9 });
  });

  it('regenerates: every code of the old set stops working, and the user is told', async () => {
    const { codes, regenerated } = setup();
    const { codes: old } = await codes.issue(ACCOUNT);
    expect(regenerated).not.toHaveBeenCalled();
    const { codes: fresh } = await codes.regenerate(ACCOUNT);
    expect(regenerated).toHaveBeenCalledWith(ACCOUNT);
    for (const code of old) {
      await expect(redeem(codes, code)).resolves.toEqual({ kind: 'refused' });
    }
    await expect(redeem(codes, fresh[0])).resolves.toEqual({ kind: 'redeemed' });
  });

  it('passes the ceiling on to the caller', async () => {
    const { codes, ceilingReached } = setup();
    await codes.ceilingReached(ACCOUNT);
    expect(ceilingReached).toHaveBeenCalledWith(ACCOUNT);
  });
});
