import {
  PASSWORD_PROVIDER_TYPE,
  passwordCredentialDataSchema,
  WEBAUTHN_PROVIDER_TYPE,
} from '@qauth-labs/server-federation';
import type {
  AccountDirectory,
  BoundFactor,
  SignInAccount,
  SignInCandidate,
} from '@qauth-labs/server-sign-in-engine';

/** A `user_credentials` row, as far as the directory reads it. */
interface CredentialRow {
  readonly id: string;
  readonly userId: string;
  readonly realmId: string;
  readonly credentialData: Record<string, unknown>;
  /**
   * The failure ladder's disabled mark (#615): when the hard action disabled
   * the credential, in epoch ms, else `null`. Absent reads as no mark.
   */
  readonly disabledAt?: number | null;
}

/**
 * The repositories the directory reads, by shape, so this library takes the
 * auth server's decorated repositories as they are and depends on no
 * database library.
 */
export interface AccountDirectoryRepositories {
  readonly userCredentials: {
    findByRealmProviderSub(
      realmId: string,
      providerType: string,
      externalSub: string
    ): Promise<CredentialRow | undefined>;
    findAllByUserIdAndType(userId: string, providerType: string): Promise<CredentialRow[]>;
  };
  readonly users: {
    findById(
      realmId: string,
      id: string
    ): Promise<{ readonly id: string; readonly enabled: boolean } | undefined>;
  };
  readonly adminGrants: {
    listLive(realmId: string, userId: string): Promise<readonly unknown[]>;
  };
}

/** Where the directory reports a row it cannot read: data corruption, never a user's doing. */
export interface AccountDirectoryLog {
  error(details: Record<string, unknown>, message: string): void;
}

/** Options of {@link createRepositoryAccountDirectory}. */
export interface AccountDirectoryOptions {
  /**
   * Whether the failure ladder's hard action is armed (#615), asked at run
   * time and only for a credential that carries a disabled mark: while it is,
   * a marked credential is unusable; while it is not, the mark is ignored and
   * reported as such, so a successful sign-in clears it. An error refuses the
   * lookup, so the round fails closed. Absent: never armed.
   */
  readonly hardActionArmed?: (realmId: string) => Promise<boolean>;
}

/**
 * The sign-in engine's account directory over the auth server's repositories
 * (ADR-002: `users` is the identity anchor, credentials live in
 * `user_credentials`).
 *
 * - Before any credential is checked (`findByIdentifier`) it reads only what
 *   the password needs: the `password` credential whose `external_sub` is the
 *   normalised address in the realm, and the users row behind it. No such row,
 *   or no users row, is no account. The account is enabled as
 *   `users.enabled` says and verified as the credential's `email_verified`
 *   says (the proof of a password account's primary identity); its hash is
 *   `null` when the credential's data cannot be read, which the engine
 *   refuses like a wrong password.
 * - Once a factor proved the user (`findByUserId`) it reads the whole
 *   account: every password and passkey (`webauthn`) credential it holds in
 *   the realm, and whether it holds a live admin grant seen from the realm
 *   (#510). An account that exists so costs one read more than none before
 *   the password is checked, not four.
 * - A credential the failure ladder's hard action marked
 *   (`user_credentials.disabled_at`, #615) is disabled only while the hard
 *   action is armed, which is asked only when a mark is there. It still counts
 *   as bound: the account holds it, and only the owner's reset clears it.
 *   While the hard action is unarmed the mark is ignored: the password is
 *   usable and reported with `ignoredMark`, so a successful sign-in clears it.
 */
export function createRepositoryAccountDirectory(
  stores: AccountDirectoryRepositories,
  log: AccountDirectoryLog,
  options: AccountDirectoryOptions = {}
): AccountDirectory {
  const armed = options.hardActionArmed ?? (async () => false);
  /** Whether each row is disabled: its mark, honoured only while the hard action is armed. */
  const disabledOf = async (
    realmId: string,
    rows: readonly CredentialRow[]
  ): Promise<boolean[]> => {
    const marked = rows.map((row) => row.disabledAt !== undefined && row.disabledAt !== null);
    const honoured = marked.some(Boolean) ? await armed(realmId) : false;
    return marked.map((mark) => mark && honoured);
  };
  return Object.freeze({
    async findByIdentifier(realmId: string, identifier: string): Promise<SignInCandidate | null> {
      const credential = await stores.userCredentials.findByRealmProviderSub(
        realmId,
        PASSWORD_PROVIDER_TYPE,
        identifier
      );
      if (credential === undefined) return null;
      const user = await stores.users.findById(realmId, credential.userId);
      if (user === undefined) {
        // The foreign key makes this impossible; answered as no account.
        log.error({ credentialId: credential.id }, 'password credential without a users row');
        return null;
      }
      const data = passwordCredentialDataSchema.safeParse(credential.credentialData);
      if (!data.success) {
        log.error(
          { credentialId: credential.id },
          'malformed credential_data on password credential'
        );
      }
      const marked = credential.disabledAt !== undefined && credential.disabledAt !== null;
      const disabled = (await disabledOf(realmId, [credential]))[0] === true;
      return Object.freeze({
        userId: user.id,
        enabled: user.enabled,
        verified: data.success && data.data.email_verified,
        password: Object.freeze({
          disabled,
          hash: data.success ? data.data.password_hash : null,
          ...(marked && !disabled ? { ignoredMark: true } : {}),
        }),
      });
    },

    async findByUserId(realmId: string, userId: string): Promise<SignInAccount | null> {
      const user = await stores.users.findById(realmId, userId);
      if (user === undefined) return null;
      const ofRealm = (rows: CredentialRow[]) => rows.filter((row) => row.realmId === realmId);
      const passwords = ofRealm(
        await stores.userCredentials.findAllByUserIdAndType(user.id, PASSWORD_PROVIDER_TYPE)
      );
      const passkeys = ofRealm(
        await stores.userCredentials.findAllByUserIdAndType(user.id, WEBAUTHN_PROVIDER_TYPE)
      );
      const grants = await stores.adminGrants.listLive(realmId, user.id);
      const disabled = await disabledOf(realmId, [...passwords, ...passkeys]);
      const factors: BoundFactor[] = [
        ...passwords.map((_, index) => ({
          type: 'password' as const,
          disabled: disabled[index] === true,
        })),
        ...passkeys.map((_, index) => ({
          type: 'passkey' as const,
          disabled: disabled[passwords.length + index] === true,
        })),
      ];
      return Object.freeze({
        userId: user.id,
        enabled: user.enabled,
        admin: grants.length > 0,
        factors: Object.freeze(factors),
      });
    },
  });
}
