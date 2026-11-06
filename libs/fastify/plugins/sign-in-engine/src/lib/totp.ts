import {
  isUpstreamCredentialData,
  PASSWORD_PROVIDER_TYPE,
  passwordCredentialDataSchema,
  upstreamCredentialDataSchema,
} from '@qauth-labs/server-federation';
import {
  type Clock,
  createTotpService,
  type StoredTotp,
  SYSTEM_CLOCK,
  TOTP_SEALED_MAX_LENGTH,
  type TotpAccount,
  type TotpBinding,
  type TotpCipher,
  type TotpCredentials,
  type TotpStore,
} from '@qauth-labs/server-sign-in-engine';

/**
 * TOTP OVER THE AUTH SERVER'S REPOSITORY (#653; ADR-017 Decisions 7 and 8,
 * ADR-020 §3).
 *
 * The engine's `TotpCredentials` port over `user_credentials`: the engine
 * library's rules (`createTotpService`: the fixed parameters, a 160-bit
 * secret from a CSPRNG, a time step accepted once) over the repository, and
 * the hard action and notices around the writes.
 *
 * - **The row.** One per account and realm: `provider_type` `totp`,
 *   `external_sub` the user id, `credential_data` `{ secret, last_step }`.
 *   `secret` is the secret sealed under the realm's `data_at_rest` key, by
 *   the caller's {@link TotpCipher}, never the secret itself; `last_step`
 *   is the last time step the TOTP accepted. `disabled_at` is the hard
 *   action's mark.
 * - **A code** takes its step in one conditional UPDATE
 *   (`acceptTotpStep`): only an enabled TOTP whose last step is lower
 *   passes, so two rounds with the same code take it once.
 * - **A binding** is one transaction: the account is read (enabled, and
 *   claimed: every password credential's address and every upstream
 *   credential verified, ADR-017 Decision 8), then one INSERT binds the
 *   TOTP or rewrites the account's own row, clearing its mark. After the
 *   commit, `bound` ends the TOTP counter's run and sends the "TOTP added"
 *   notice.
 * - **The hard action** at the ladder's ceiling: while `hardActionArmed`
 *   says so, the TOTP's mark is set in one statement that only an unmarked
 *   row passes, and once it is set the "second factor disabled" notice goes
 *   out. While it is not armed nothing changes: the ladder alone holds the
 *   guesses back.
 *
 * A realm switches none of these notices off: nothing here asks it.
 */

/** The `provider_type` of a TOTP credential. */
export const TOTP_PROVIDER_TYPE = 'totp';

/** A `user_credentials` row, as far as the TOTP reads it. */
interface TotpCredentialRow {
  readonly id: string;
  readonly userId: string;
  readonly realmId: string;
  readonly providerType: string;
  readonly credentialData: Record<string, unknown>;
  readonly disabledAt?: number | null;
}

/** The repositories the TOTP lives in, by shape, so this library depends on no database library. */
export interface TotpRepositories<Tx> {
  readonly userCredentials: {
    findByRealmProviderSub(
      realmId: string,
      providerType: string,
      externalSub: string,
      tx?: Tx
    ): Promise<TotpCredentialRow | undefined>;
    findAllByUserId(userId: string, tx?: Tx): Promise<TotpCredentialRow[]>;
    acceptTotpStep(realmId: string, userId: string, step: number, tx?: Tx): Promise<boolean>;
    upsertTotp(
      input: {
        readonly realmId: string;
        readonly userId: string;
        readonly credentialData: Readonly<Record<string, unknown>>;
        readonly at: number;
      },
      tx?: Tx
    ): Promise<unknown>;
    setDisabledAt(
      realmId: string,
      providerType: string,
      externalSub: string,
      disabledAt: number,
      tx?: Tx
    ): Promise<unknown>;
  };
  readonly users: {
    findById(
      realmId: string,
      id: string,
      tx?: Tx
    ): Promise<{ readonly id: string; readonly enabled: boolean } | undefined>;
  };
}

/** One database transaction: `work` commits with it, and a throw rolls it back. */
export type TotpTransaction<Tx> = <T>(work: (tx: Tx) => Promise<T>) => Promise<T>;

/** Options of {@link createRepositoryTotp}. */
export interface RepositoryTotpOptions {
  /** Seals and opens a secret under the realm's `data_at_rest` key. */
  readonly cipher: TotpCipher;
  /** The issuer an authenticator app shows beside the account: the realm's. */
  readonly issuerOf: (realmId: string) => Promise<string>;
  /**
   * Whether the TOTP's hard action is armed for the account, asked at the
   * ceiling (ADR-017 Decision 7): the hosted pages are on, and the account
   * keeps an unused recovery code or another usable second factor. A throw
   * is reported and disables nothing.
   */
  readonly hardActionArmed: (account: TotpAccount) => Promise<boolean>;
  /**
   * After a binding committed: end the TOTP counter's run (it counted the old
   * secret's codes) and send the "TOTP added" notice. A throw is reported and
   * the binding stands.
   */
  readonly bound: (input: TotpAccount & { readonly clientId: string }) => Promise<void>;
  /** After the hard action set the mark: the "second factor disabled" notice. */
  readonly disabled: (account: TotpAccount) => Promise<void>;
  /**
   * A wrong code after a correct password: the "wrong second factor" notice,
   * at most once per 24 hours per account (the caller holds the claim).
   */
  readonly failedAfterPassword: (
    input: TotpAccount & { readonly clientId: string }
  ) => Promise<void>;
  /** Where a step after a committed write that failed is reported. */
  readonly report: (error: unknown, what: string) => void;
  /** The clock a code is matched and a mark set by. The system's by default. */
  readonly clock?: Clock;
}

/** The stored TOTP a row holds, or `null` for a row whose data cannot be one. */
function storedOf(row: TotpCredentialRow): StoredTotp | null {
  const { secret, last_step: lastStep } = row.credentialData;
  if (
    typeof secret !== 'string' ||
    secret.length === 0 ||
    secret.length > TOTP_SEALED_MAX_LENGTH ||
    typeof lastStep !== 'number' ||
    !Number.isSafeInteger(lastStep) ||
    lastStep < 0
  ) {
    return null;
  }
  return Object.freeze({
    sealed: secret,
    lastStep,
    disabled: row.disabledAt !== undefined && row.disabledAt !== null,
  });
}

/**
 * Whether the account's address is proved (ADR-017 Decision 8): every password
 * credential's `email_verified`, and every upstream provider's credential
 * its `verified`, as the account directory reads it. An account without
 * either has no address to claim.
 */
function claimed(credentials: readonly TotpCredentialRow[]): boolean {
  return credentials.every((row) => {
    if (row.providerType === PASSWORD_PROVIDER_TYPE) {
      const data = passwordCredentialDataSchema.safeParse(row.credentialData);
      return data.success && data.data.email_verified;
    }
    if (isUpstreamCredentialData(row.credentialData)) {
      const data = upstreamCredentialDataSchema.safeParse(row.credentialData);
      return data.success && data.data.verified;
    }
    return true;
  });
}

/**
 * The TOTPs over the auth server's `user_credentials`.
 *
 * @param repos - The decorated repositories.
 * @param transaction - The database's transaction.
 */
export function createRepositoryTotp<Tx>(
  repos: TotpRepositories<Tx>,
  transaction: TotpTransaction<Tx>,
  options: RepositoryTotpOptions
): TotpCredentials {
  const credentials = repos.userCredentials;
  const clock = options.clock ?? SYSTEM_CLOCK;
  const after = async (what: string, work: () => Promise<void>): Promise<void> => {
    try {
      await work();
    } catch (error) {
      options.report(error, what);
    }
  };

  const store: TotpStore = {
    async read({ realmId, userId }) {
      const row = await credentials.findByRealmProviderSub(realmId, TOTP_PROVIDER_TYPE, userId);
      if (row === undefined || row.realmId !== realmId || row.userId !== userId) return null;
      const stored = storedOf(row);
      // A row the TOTP cannot read is a store fault, never a code to refuse quietly.
      if (stored === null) throw new Error('a TOTP credential whose data is not one');
      return stored;
    },
    accept: ({ realmId, userId, step }) => credentials.acceptTotpStep(realmId, userId, step),
    bind: ({ realmId, userId, sealed, step }) =>
      transaction(async (tx): Promise<TotpBinding> => {
        const user = await repos.users.findById(realmId, userId, tx);
        if (user === undefined || user.id !== userId) {
          return { kind: 'refused', reason: 'subject_mismatch' };
        }
        if (!user.enabled) return { kind: 'refused', reason: 'account_disabled' };
        const held = (await credentials.findAllByUserId(userId, tx)).filter(
          (row) => row.realmId === realmId
        );
        if (!claimed(held)) return { kind: 'refused', reason: 'account_unclaimed' };
        const row = await credentials.upsertTotp(
          { realmId, userId, credentialData: { secret: sealed, last_step: step }, at: clock.now() },
          tx
        );
        return row === undefined
          ? { kind: 'refused', reason: 'subject_mismatch' }
          : { kind: 'bound' };
      }),
  };

  return createTotpService({
    store,
    cipher: options.cipher,
    issuerOf: options.issuerOf,
    clock,
    notices: {
      bound: (input) => after('the TOTP-added notice', () => options.bound(input)),
      async ceilingReached(account) {
        let armed: boolean;
        try {
          armed = await options.hardActionArmed(account);
        } catch (error) {
          options.report(error, 'the TOTP hard action');
          return;
        }
        if (!armed) return;
        const marked = await credentials.setDisabledAt(
          account.realmId,
          TOTP_PROVIDER_TYPE,
          account.userId,
          clock.now()
        );
        // Marked already, or none: the notice went out with the first mark.
        if (marked === undefined) return;
        await after('the second-factor-disabled notice', () => options.disabled(account));
      },
      failedAfterPassword: (input) => options.failedAfterPassword(input),
    },
    report: options.report,
  });
}
