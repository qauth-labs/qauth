import {
  buildPasswordCredentialData,
  PASSWORD_PROVIDER_TYPE,
  passwordCredentialDataSchema,
} from '@qauth-labs/server-federation';
import type {
  NewPasswordCheck,
  PasswordReplacement,
  PasswordUpdates,
} from '@qauth-labs/server-sign-in-engine';

/**
 * The repositories the password update writes through, by shape, so this
 * library takes the auth server's decorated repositories as they are and
 * depends on no database library. `Tx` is the database transaction they share.
 */
export interface PasswordUpdateRepositories<Tx> {
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
    updateCredentialData(
      id: string,
      credentialData: Record<string, unknown>,
      tx?: Tx
    ): Promise<unknown>;
    clearDisabledAt(
      realmId: string,
      providerType: string,
      externalSub: string,
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
  readonly userRequiredActions: {
    remove(realmId: string, userId: string, action: 'update_password', tx?: Tx): Promise<unknown>;
  };
}

/** One database transaction: `work` commits with it, and a throw rolls it back. */
export type PasswordUpdateTransaction<Tx> = <T>(work: (tx: Tx) => Promise<T>) => Promise<T>;

/** What the update reads of the realm's password policy, and how it hashes. */
export interface PasswordUpdatePolicy {
  /** The realm's `password.minLength`. */
  minLength(realmId: string): Promise<number>;
  /** The realm's password policy for a new password, with the address as a context word. */
  check(input: {
    readonly realmId: string;
    readonly identifier: string;
    readonly password: string;
  }): Promise<NewPasswordCheck>;
  /** The Argon2id hash of a password already in its stored form. */
  hash(password: string): Promise<string>;
}

/**
 * The sign-in engine's forced password update over the auth server's
 * repositories (#635; ADR-002: a password lives in its `user_credentials`
 * row's `credential_data`).
 *
 * `replace` hashes the new password first, outside the transaction (Argon2id
 * is slow), then in one database transaction reads the `password` credential
 * whose `external_sub` is the identifier in the realm and the user behind it,
 * and, only when that credential is the subject's and the user is enabled,
 * writes the new hash and its normalisation marker (keeping the credential's
 * `email_verified`), clears the failure ladder's disabled mark and removes
 * the account's `update_password` required action. Another user's
 * credential, or none, writes nothing (`subject_mismatch`); so does a
 * disabled user (`account_disabled`). A credential whose data cannot be read
 * throws, so the round is refused and nothing is written.
 */
export function createRepositoryPasswordUpdates<Tx>(
  stores: PasswordUpdateRepositories<Tx>,
  transaction: PasswordUpdateTransaction<Tx>,
  policy: PasswordUpdatePolicy
): PasswordUpdates {
  const updates: PasswordUpdates = {
    minLength: (realmId) => policy.minLength(realmId),
    check: (input) => policy.check(input),
    async replace({ realmId, userId, identifier, password, normalization }) {
      const passwordHash = await policy.hash(password);
      return transaction(async (tx): Promise<PasswordReplacement> => {
        const credential = await stores.userCredentials.findByRealmProviderSub(
          realmId,
          PASSWORD_PROVIDER_TYPE,
          identifier,
          tx
        );
        if (credential === undefined || credential.userId !== userId) {
          return { kind: 'refused', reason: 'subject_mismatch' };
        }
        const user = await stores.users.findById(realmId, userId, tx);
        if (user === undefined) return { kind: 'refused', reason: 'subject_mismatch' };
        if (!user.enabled) return { kind: 'refused', reason: 'account_disabled' };
        const data = passwordCredentialDataSchema.safeParse(credential.credentialData);
        if (!data.success) {
          // Never the data itself: it holds the old hash.
          throw new Error('malformed credential_data on the password credential to replace');
        }
        await stores.userCredentials.updateCredentialData(
          credential.id,
          {
            ...credential.credentialData,
            ...buildPasswordCredentialData(passwordHash, data.data.email_verified, normalization),
          },
          tx
        );
        await stores.userCredentials.clearDisabledAt(
          realmId,
          PASSWORD_PROVIDER_TYPE,
          identifier,
          tx
        );
        await stores.userRequiredActions.remove(realmId, userId, 'update_password', tx);
        return { kind: 'replaced' };
      });
    },
  };
  return Object.freeze(updates);
}
