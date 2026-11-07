import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

import type { RecoveryCodeAccount, RecoveryCodes, RecoveryCodeSet } from '../lib/ports';
import {
  createRecoveryCodeService,
  type RecoveryCodeHasher,
  type RecoveryCodeLookup,
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
  /** The code's lookup digest (#655), for an account found by its code alone. */
  readonly lookupDigest: string | null;
  readonly createdAt: number;
  usedAt: number | null;
  usedBy: string | null;
  confirmedAt: number | null;
}

export interface MemoryRecoveryCodeStore extends RecoveryCodeStore {
  /** Every row, used or not, of every account. */
  readonly rows: MemoryRecoveryCodeRow[];
  findByLookupDigest(input: {
    readonly realmId: string;
    readonly digest: string;
  }): Promise<{ readonly userId: string } | null>;
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
    async confirm({
      realmId,
      userId,
      setId,
      at,
    }: RecoveryCodeAccount & { setId: string; at: number }) {
      const set = of({ realmId, userId });
      if (!set.some((row) => row.id === setId)) return false;
      for (const row of set) row.confirmedAt ??= at;
      return true;
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
      lookupDigests,
      at,
      keepConfirmed,
    }: RecoveryCodeAccount & {
      hashes: readonly string[];
      lookupDigests?: readonly string[];
      at: number;
      keepConfirmed: boolean;
    }) {
      const held = of({ realmId, userId });
      if (keepConfirmed && held.some((row) => row.confirmedAt !== null)) return null;
      if (lookupDigests !== undefined && lookupDigests.length !== hashes.length) {
        throw new Error('a lookup digest for each hash');
      }
      for (const row of held) rows.splice(rows.indexOf(row), 1);
      const setId = `code-${next + 1}`;
      for (const [index, hash] of hashes.entries()) {
        next += 1;
        rows.push({
          id: `code-${next}`,
          realmId,
          userId,
          hash,
          lookupDigest: lookupDigests?.[index] ?? null,
          createdAt: at,
          usedAt: null,
          usedBy: null,
          confirmedAt: null,
        });
      }
      return setId;
    },
    async findByLookupDigest({ realmId, digest }: { realmId: string; digest: string }) {
      const owners = new Set(
        rows
          .filter(
            (row) => row.realmId === realmId && row.usedAt === null && row.lookupDigest === digest
          )
          .map((row) => row.userId)
      );
      const [userId] = owners;
      return owners.size === 1 && userId !== undefined ? { userId } : null;
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
  /** A new set in place of the account's, confirmed or not: a regeneration, or a test's seed. */
  replace(account: RecoveryCodeAccount): Promise<RecoveryCodeSet>;
  readonly store: ReturnType<typeof createMemoryRecoveryCodeStore>;
  readonly hasher: ReturnType<typeof createCountingHasher>;
  /** Every "a recovery code was used" notice, by account. */
  readonly usedNotices: RecoveryCodeAccount[];
  /** Every ceiling notice, by account. */
  readonly ceilingNotices: RecoveryCodeAccount[];
}

/** The lookup digest of the memory: a plain SHA-256 of the realm and the code, never for production. */
export function memoryLookupDigest(realmId: string, code: string): string {
  return createHash('sha256').update(`${realmId}\u0000${code}`).digest('hex');
}

/** Options of {@link createMemoryRecoveryCodes}. */
export interface MemoryRecoveryCodeOptions {
  /**
   * Which accounts' sets carry lookup digests (#655): the accounts a code
   * alone finds. None by default.
   */
  readonly findable?: (account: RecoveryCodeAccount) => boolean;
  /** Build the port with no lookup at all, as before #655: no `findAccount`. */
  readonly noLookup?: boolean;
}

/** The engine's recovery-code port in memory, with the service's rules. */
export function createMemoryRecoveryCodes(
  now: () => number = Date.now,
  options: MemoryRecoveryCodeOptions = {}
): MemoryRecoveryCodes {
  const store = createMemoryRecoveryCodeStore();
  const hasher = createCountingHasher();
  const lookup: RecoveryCodeLookup = {
    digest: async ({ realmId, code }) => memoryLookupDigest(realmId, code),
    findable: async (account) => options.findable?.(account) ?? false,
  };
  const service = createRecoveryCodeService({
    store,
    hasher,
    clock: { now, sleep: async () => undefined },
    ...(options.noLookup === true ? {} : { lookup }),
  });
  const usedNotices: RecoveryCodeAccount[] = [];
  const ceilingNotices: RecoveryCodeAccount[] = [];
  return {
    store,
    hasher,
    usedNotices,
    ceilingNotices,
    ...(service.findAccount === undefined ? {} : { findAccount: service.findAccount }),
    status: service.status,
    issue: service.issue,
    replace: service.replace,
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
