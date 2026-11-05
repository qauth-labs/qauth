import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

import type { RecoveryCodeAccount, RecoveryCodes } from '../lib/ports';
import {
  createRecoveryCodeService,
  type RecoveryCodeHasher,
  type RecoveryCodeStore,
} from '../lib/recovery-codes';

/**
 * TEST SUPPORT — recovery codes in memory (#649): a store with the auth
 * server's rules (`user_recovery_codes`: one set per account, a code used
 * once), and a salted hasher that counts its work. Not for production: the
 * hasher is a plain SHA-256, and nothing is shared between processes.
 */

/** One stored code. */
export interface MemoryRecoveryCodeRow {
  readonly id: string;
  readonly realmId: string;
  readonly userId: string;
  readonly hash: string;
  readonly createdAt: number;
  usedAt: number | null;
  usedBy: string | null;
  confirmedAt: number | null;
}

export interface MemoryRecoveryCodeStore extends RecoveryCodeStore {
  /** Every row, used or not, of every account. */
  readonly rows: MemoryRecoveryCodeRow[];
}

/** A store in memory. `take` may be told to lose a race: another round took the code first. */
export function createMemoryRecoveryCodeStore(): MemoryRecoveryCodeStore & {
  loseNextRace: boolean;
} {
  const rows: MemoryRecoveryCodeRow[] = [];
  let next = 0;
  const of = ({ realmId, userId }: RecoveryCodeAccount) =>
    rows.filter((row) => row.realmId === realmId && row.userId === userId);
  const store = {
    rows,
    loseNextRace: false,
    async status(account: RecoveryCodeAccount) {
      const set = of(account);
      return {
        issued: set.length > 0,
        unused: set.filter((row) => row.usedAt === null).length,
        confirmed: set.length > 0 && set.every((row) => row.confirmedAt !== null),
      };
    },
    async confirm({ realmId, userId, at }: RecoveryCodeAccount & { at: number }) {
      for (const row of of({ realmId, userId })) row.confirmedAt ??= at;
    },
    async unused(account: RecoveryCodeAccount) {
      return of(account)
        .filter((row) => row.usedAt === null)
        .map(({ id, hash }) => ({ id, hash }));
    },
    async replace({
      realmId,
      userId,
      hashes,
      at,
    }: RecoveryCodeAccount & { hashes: readonly string[]; at: number }) {
      for (const row of of({ realmId, userId })) rows.splice(rows.indexOf(row), 1);
      for (const hash of hashes) {
        next += 1;
        rows.push({
          id: `code-${next}`,
          realmId,
          userId,
          hash,
          createdAt: at,
          usedAt: null,
          usedBy: null,
          confirmedAt: null,
        });
      }
    },
    async take({
      realmId,
      userId,
      id,
      at,
      clientId,
    }: RecoveryCodeAccount & { id: string; at: number; clientId: string }) {
      const row = of({ realmId, userId }).find((candidate) => candidate.id === id);
      if (store.loseNextRace) {
        store.loseNextRace = false;
        if (row !== undefined) row.usedAt = at;
        return false;
      }
      if (row === undefined || row.usedAt !== null) return false;
      row.usedAt = at;
      row.usedBy = clientId;
      return true;
    },
  };
  return store;
}

/** A salted hasher: `salt$sha256(salt, code)`, counting every hash and verification. */
export function createCountingHasher(): RecoveryCodeHasher & {
  hashes: number;
  verifications: number;
} {
  const digest = (salt: string, code: string) =>
    createHash('sha256').update(`${salt}\u0000${code}`).digest('base64url');
  const hasher = {
    hashes: 0,
    verifications: 0,
    async hash(code: string) {
      hasher.hashes += 1;
      const salt = randomBytes(16).toString('base64url');
      return `${salt}$${digest(salt, code)}`;
    },
    async verify(hash: string, code: string) {
      hasher.verifications += 1;
      const [salt, stored] = hash.split('$');
      if (salt === undefined || stored === undefined) return false;
      const presented = Buffer.from(digest(salt, code));
      const expected = Buffer.from(stored);
      return presented.length === expected.length && timingSafeEqual(presented, expected);
    },
  };
  return hasher;
}

/** The engine's recovery-code port over a memory store, recording each notice. */
export interface MemoryRecoveryCodes extends RecoveryCodes {
  readonly store: ReturnType<typeof createMemoryRecoveryCodeStore>;
  readonly hasher: ReturnType<typeof createCountingHasher>;
  /** Every "a recovery code was used" notice, by account. */
  readonly usedNotices: RecoveryCodeAccount[];
  /** Every ceiling notice, by account. */
  readonly ceilingNotices: RecoveryCodeAccount[];
}

/** The engine's recovery-code port in memory, with the service's rules. */
export function createMemoryRecoveryCodes(now: () => number = Date.now): MemoryRecoveryCodes {
  const store = createMemoryRecoveryCodeStore();
  const hasher = createCountingHasher();
  const service = createRecoveryCodeService({
    store,
    hasher,
    clock: { now, sleep: async () => undefined },
  });
  const usedNotices: RecoveryCodeAccount[] = [];
  const ceilingNotices: RecoveryCodeAccount[] = [];
  return {
    store,
    hasher,
    usedNotices,
    ceilingNotices,
    status: service.status,
    issue: service.issue,
    confirm: service.confirm,
    async redeem(input) {
      const redeemed = await service.redeem(input);
      if (redeemed.kind === 'redeemed') {
        usedNotices.push({ realmId: input.realmId, userId: input.userId });
      }
      return redeemed;
    },
    async ceilingReached(account) {
      ceilingNotices.push({ realmId: account.realmId, userId: account.userId });
    },
  };
}
