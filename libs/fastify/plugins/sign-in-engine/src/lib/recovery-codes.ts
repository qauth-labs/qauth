import {
  type Clock,
  createRecoveryCodeService,
  type RecoveryCodeAccount,
  type RecoveryCodeHasher,
  type RecoveryCodes,
  type RecoveryCodeSet,
  type RecoveryCodeStore,
} from '@qauth-labs/server-sign-in-engine';

/**
 * THE RECOVERY CODES OVER THE AUTH SERVER'S REPOSITORY (#649; ADR-017
 * Decisions 7 and 8, ADR-018 §3).
 *
 * The engine's `RecoveryCodes` port over `user_recovery_codes`: the
 * engine library's rules (`createRecoveryCodeService`: 10 codes of 80 bits
 * from a CSPRNG, salted hashes from the password hasher, every hash checked on
 * every redemption) over the repository, and the notices around the writes.
 *
 * - A code is taken in a transaction that also records its use (the
 *   `user.recovery_code_used` event), so a taken code always has its record
 *   and a rolled-back take leaves none; the "a recovery code was used" notice
 *   follows the commit.
 * - {@link RepositoryRecoveryCodes.regenerate} replaces the account's set and
 *   then sends the "recovery codes were regenerated" notice. The account
 *   API's regeneration (ACC-02, #687) calls it, after a fresh authentication.
 * - The 100th wrong code in a row, and every one after it, reaches
 *   `ceilingReached`: the caller tells the user and the operator.
 *
 * A realm switches none of these notices off: nothing here asks it.
 */

/** The repository the codes live in, by shape, so this library depends on no database library. */
export interface RecoveryCodeRepositories<Tx> {
  readonly userRecoveryCodes: {
    status(
      realmId: string,
      userId: string,
      tx?: Tx
    ): Promise<{ readonly issued: boolean; readonly unused: number; readonly confirmed: boolean }>;
    findUnused(
      realmId: string,
      userId: string,
      tx?: Tx
    ): Promise<readonly { readonly id: string; readonly codeHash: string }[]>;
    replaceSet(
      input: {
        readonly realmId: string;
        readonly userId: string;
        readonly codeHashes: readonly string[];
        readonly createdAt: number;
        readonly keepConfirmed?: boolean;
      },
      tx?: Tx
    ): Promise<string | null>;
    markUsed(
      input: {
        readonly realmId: string;
        readonly userId: string;
        readonly id: string;
        readonly usedAt: number;
      },
      tx?: Tx
    ): Promise<boolean>;
    confirmSet(
      input: {
        readonly realmId: string;
        readonly userId: string;
        readonly setId: string;
        readonly confirmedAt: number;
      },
      tx?: Tx
    ): Promise<boolean>;
  };
}

/** One database transaction: `work` commits with it, and a throw rolls it back. */
export type RecoveryCodeTransaction<Tx> = <T>(work: (tx: Tx) => Promise<T>) => Promise<T>;

/** A code taken at sign-in. */
export interface RecoveryCodeUse extends RecoveryCodeAccount {
  /** The client the sign-in is for. */
  readonly clientId: string;
  /** How many codes of the set are left unused after this one. */
  readonly unusedCodes: number;
}

/** What the codes do around their writes. */
export interface RecoveryCodeNotices<Tx> {
  /**
   * Record the use in the transaction that takes the code (the
   * `user.recovery_code_used` event), so it commits with the take. A throw
   * rolls the take back and refuses the round.
   */
  used(use: RecoveryCodeUse, tx: Tx): Promise<void>;
  /**
   * After the take commits: the "a recovery code was used" notice. A throw is
   * reported and changes no answer: the code is used either way.
   */
  committed(use: RecoveryCodeUse): Promise<void>;
  /** After a regenerated set commits: the "recovery codes were regenerated" notice. */
  regenerated(account: RecoveryCodeAccount): Promise<void>;
  /** The 100th wrong code in a row, or one after it: tell the user and the operator. */
  ceilingReached(account: RecoveryCodeAccount): Promise<void>;
  /** Where a notice that failed after its write committed is reported. */
  report(error: unknown, what: string): void;
}

/** Options of {@link createRepositoryRecoveryCodes}. */
export interface RepositoryRecoveryCodesOptions<Tx> extends RecoveryCodeNotices<Tx> {
  /** The password hasher (Argon2id), by shape. */
  readonly hasher: RecoveryCodeHasher;
  /** The clock a code is taken and a set issued by. The system's by default. */
  readonly clock?: Clock;
}

/** The engine's port, and the regeneration the account API calls. */
export interface RepositoryRecoveryCodes extends RecoveryCodes {
  /**
   * Replace the account's set with a new one and return its codes, to be
   * shown once; every code of the old set stops working, and the
   * "recovery codes were regenerated" notice goes out once the new set is
   * stored. The caller requires a fresh authentication first (ACC-02, #687),
   * and calls `confirm` with the set's id once the person says they saved
   * the codes: an unconfirmed set is replaced by the next sign-in that owes
   * one.
   */
  regenerate(account: RecoveryCodeAccount): Promise<RecoveryCodeSet>;
}

/**
 * The recovery codes over the auth server's `user_recovery_codes`.
 *
 * @param repos - The decorated repository.
 * @param transaction - The database's transaction.
 */
export function createRepositoryRecoveryCodes<Tx>(
  repos: RecoveryCodeRepositories<Tx>,
  transaction: RecoveryCodeTransaction<Tx>,
  options: RepositoryRecoveryCodesOptions<Tx>
): RepositoryRecoveryCodes {
  const codes = repos.userRecoveryCodes;
  const after = async (what: string, work: () => Promise<void>): Promise<void> => {
    try {
      await work();
    } catch (error) {
      options.report(error, what);
    }
  };

  const store: RecoveryCodeStore = {
    status: ({ realmId, userId }) => codes.status(realmId, userId),
    async unused({ realmId, userId }) {
      const rows = await codes.findUnused(realmId, userId);
      return rows.map((row) => ({ id: row.id, hash: row.codeHash }));
    },
    confirm: ({ realmId, userId, setId, at }) =>
      codes.confirmSet({ realmId, userId, setId, confirmedAt: at }),
    replace: ({ realmId, userId, hashes, at, keepConfirmed }) =>
      codes.replaceSet({ realmId, userId, codeHashes: hashes, createdAt: at, keepConfirmed }),
    async take({ realmId, userId, id, at, clientId }) {
      const use = await transaction(async (tx) => {
        if (!(await codes.markUsed({ realmId, userId, id, usedAt: at }, tx))) return undefined;
        const { unused } = await codes.status(realmId, userId, tx);
        const taken: RecoveryCodeUse = { realmId, userId, clientId, unusedCodes: unused };
        await options.used(taken, tx);
        return taken;
      });
      if (use === undefined) return false;
      await after('the recovery-code-used notice', () => options.committed(use));
      return true;
    },
  };
  const service = createRecoveryCodeService({
    store,
    hasher: options.hasher,
    ...(options.clock === undefined ? {} : { clock: options.clock }),
  });

  return Object.freeze({
    status: service.status,
    issue: service.issue,
    redeem: service.redeem,
    confirm: service.confirm,
    async regenerate(account: RecoveryCodeAccount) {
      const issued = await service.replace(account);
      await after('the recovery-codes-regenerated notice', () => options.regenerated(account));
      return issued;
    },
    async ceilingReached(account: RecoveryCodeAccount) {
      await options.ceilingReached(account);
    },
  });
}
