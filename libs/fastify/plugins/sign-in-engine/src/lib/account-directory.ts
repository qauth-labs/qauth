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
 * - No factor is disabled yet: `user_credentials.disabled_at` comes with the
 *   ladder's hard action (#615).
 */
export function createRepositoryAccountDirectory(
  stores: AccountDirectoryRepositories,
  log: AccountDirectoryLog
): AccountDirectory {
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
      return Object.freeze({
        userId: user.id,
        enabled: user.enabled,
        verified: data.success && data.data.email_verified,
        password: Object.freeze({
          disabled: false,
          hash: data.success ? data.data.password_hash : null,
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
      const factors: BoundFactor[] = [
        ...passwords.map(() => ({ type: 'password' as const, disabled: false })),
        ...passkeys.map(() => ({ type: 'passkey' as const, disabled: false })),
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
