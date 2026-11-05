import {
  buildPasswordCredentialData,
  EMAIL_ATTR_KEY,
  PASSWORD_PROVIDER_TYPE,
  passwordCredentialDataSchema,
  SELF_REPORTED_SOURCE,
} from '@qauth-labs/server-federation';
import type {
  AccountReset,
  AccountResetOutcome,
  AccountResets,
} from '@qauth-labs/server-sign-in-engine';

/**
 * The repositories a reset writes through, by shape, so this library takes
 * the auth server's decorated repositories as they are and depends on no
 * database library. `Tx` is the database transaction they share.
 */
export interface AccountResetRepositories<Tx> {
  readonly userCredentials: {
    findByRealmProviderSub(
      realmId: string,
      providerType: string,
      externalSub: string,
      tx?: Tx
    ): Promise<
      | {
          readonly id: string;
          readonly userId: string;
          readonly credentialData: Record<string, unknown>;
        }
      | undefined
    >;
    /**
     * Replace the password's keys of one `password` credential and clear its
     * disabled mark; `undefined` when the realm holds no such password row.
     */
    updatePassword(
      realmId: string,
      id: string,
      passwordData: Record<string, unknown>,
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
  readonly userAttributes: {
    setVerified(
      userId: string,
      source: string,
      attrKey: string,
      verified: boolean,
      tx?: Tx
    ): Promise<unknown>;
  };
  readonly userRequiredActions: {
    remove(realmId: string, userId: string, action: 'update_password', tx?: Tx): Promise<unknown>;
  };
  readonly refreshTokens: {
    revokeAllForUser(userId: string, reason?: string, tx?: Tx): Promise<void>;
  };
  readonly userSessionEpochs: {
    advance(
      input: { readonly realmId: string; readonly userId: string; readonly at: number },
      tx?: Tx
    ): Promise<{ readonly epoch: number; readonly advancedAt: number }>;
  };
}

/** One database transaction: `work` commits with it, and a throw rolls it back. */
export type AccountResetTransaction<Tx> = <T>(work: (tx: Tx) => Promise<T>) => Promise<T>;

/** A reset that committed: whose, and the session epoch it advanced to. */
export interface CommittedReset {
  readonly realmId: string;
  readonly clientId: string;
  readonly userId: string;
  /** The normalised address: the password credential's `external_sub`. */
  readonly identifier: string;
  readonly epoch: number;
  /** When the epoch advanced, in epoch ms: no browser session created by then is kept. */
  readonly advancedAt: number;
}

/** What a reset reads of the realm and the client, and what it does around its transaction. */
export interface AccountResetPolicy<Tx> {
  /** Whether the realm and the client allow the reset flow (#642). */
  allowed(input: { readonly realmId: string; readonly clientId: string }): Promise<boolean>;
  /** The Argon2id hash of a password already in its stored form. */
  hash(password: string): Promise<string>;
  /** The time the epoch advances to, in epoch ms. `Date.now` by default. */
  now?(): number;
  /**
   * Record the reset's `user.password_reset` event in its transaction, so it
   * commits with the new password and a rolled-back reset leaves none
   * (ADR-019 Decision 8).
   */
  recorded(reset: CommittedReset, tx: Tx): Promise<void>;
  /**
   * What follows the commit, none of which can roll it back: end the user's
   * browser sessions, publish the new epoch to its cache, clear the
   * password's failure ladder and send the "password changed" notice. It
   * must not throw: a failure is the policy's to report. The epoch in
   * Postgres already refuses every older session and transaction.
   */
  committed(reset: CommittedReset): Promise<void>;
}

/** Why a refresh family ends at a reset: the reason its rows record. */
export const RESET_REFRESH_REVOCATION_REASON = 'password_reset';

/**
 * The sign-in engine's password reset over the auth server's repositories
 * (#642; ADR-017 Decision 8; ADR-002: a password lives in its
 * `user_credentials` row's `credential_data`, the address in the
 * self-reported `email` attribute).
 *
 * `reset` hashes the new password first, outside the transaction (Argon2id
 * is slow). Then, in one database transaction, it reads the `password`
 * credential whose `external_sub` is the address in the realm and the user
 * behind it, and, only when that credential is the subject's and the user is
 * enabled:
 *
 * - replaces the password's keys of the credential (the new hash, its
 *   normalisation marker, `email_verified: true`) and clears its disabled
 *   mark, through `updatePassword`, which touches no other credential: a
 *   second factor keeps its own;
 * - marks the self-reported `email` attribute verified: the code proved the
 *   mailbox;
 * - removes the `update_password` required action;
 * - revokes every refresh family of the user;
 * - advances the user's session epoch;
 * - records the reset's event.
 *
 * Another user's credential, or none, writes nothing (`subject_mismatch`);
 * so does a disabled user (`account_disabled`). A credential whose data
 * cannot be read throws, so the round is refused and nothing is written.
 * Once the transaction committed, `committed` ends the rest; its failure is
 * never the reset's.
 */
export function createRepositoryAccountResets<Tx>(
  stores: AccountResetRepositories<Tx>,
  transaction: AccountResetTransaction<Tx>,
  policy: AccountResetPolicy<Tx>
): AccountResets {
  const now = () => (policy.now === undefined ? Date.now() : policy.now());
  const resets: AccountResets = {
    allowed: (input) => policy.allowed(input),
    async reset({
      realmId,
      clientId,
      userId,
      identifier,
      password,
      normalization,
    }: AccountReset): Promise<AccountResetOutcome> {
      const passwordHash = await policy.hash(password);
      const outcome = await transaction(
        async (tx): Promise<{ refused: AccountResetOutcome } | { committed: CommittedReset }> => {
          const credential = await stores.userCredentials.findByRealmProviderSub(
            realmId,
            PASSWORD_PROVIDER_TYPE,
            identifier,
            tx
          );
          if (credential === undefined || credential.userId !== userId) {
            return { refused: { kind: 'refused', reason: 'subject_mismatch' } };
          }
          const user = await stores.users.findById(realmId, userId, tx);
          if (user === undefined) {
            return { refused: { kind: 'refused', reason: 'subject_mismatch' } };
          }
          if (!user.enabled) return { refused: { kind: 'refused', reason: 'account_disabled' } };
          if (!passwordCredentialDataSchema.safeParse(credential.credentialData).success) {
            // Never the data itself: it holds the old hash.
            throw new Error('malformed credential_data on the password credential to reset');
          }
          const updated = await stores.userCredentials.updatePassword(
            realmId,
            credential.id,
            { ...buildPasswordCredentialData(passwordHash, true, normalization) },
            tx
          );
          if (updated === undefined) {
            throw new Error('the password credential to reset is gone');
          }
          await stores.userAttributes.setVerified(
            userId,
            SELF_REPORTED_SOURCE,
            EMAIL_ATTR_KEY,
            true,
            tx
          );
          await stores.userRequiredActions.remove(realmId, userId, 'update_password', tx);
          await stores.refreshTokens.revokeAllForUser(userId, RESET_REFRESH_REVOCATION_REASON, tx);
          const { epoch, advancedAt } = await stores.userSessionEpochs.advance(
            { realmId, userId, at: now() },
            tx
          );
          const committed: CommittedReset = Object.freeze({
            realmId,
            clientId,
            userId,
            identifier,
            epoch,
            advancedAt,
          });
          await policy.recorded(committed, tx);
          return { committed };
        }
      );
      if ('refused' in outcome) return outcome.refused;
      await policy.committed(outcome.committed);
      return { kind: 'reset' };
    },
  };
  return Object.freeze(resets);
}
