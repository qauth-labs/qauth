import {
  PASSWORD_PROVIDER_TYPE,
  passwordCredentialDataSchema,
  WEBAUTHN_PROVIDER_TYPE,
} from '@qauth-labs/server-federation';
import type {
  AccountDirectory,
  BoundFactor,
  SignInAccount,
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
 * - An identifier names an account through its password credential: the
 *   `password` row whose `external_sub` is the normalised address, in the
 *   realm. No such row, or no users row behind it, is no account.
 * - The account is enabled as `users.enabled` says, verified as the password
 *   credential's `email_verified` says (the proof of a password account's
 *   primary identity), and an admin when it holds a live admin grant seen
 *   from the realm (#510).
 * - Its factors are its password (its hash, or `null` when the credential's
 *   data cannot be read, which the engine refuses like a wrong password) and
 *   each passkey (`webauthn`) it holds. None is disabled yet:
 *   `user_credentials.disabled_at` comes with the ladder's hard action (#615).
 */
export function createRepositoryAccountDirectory(
  repositories: AccountDirectoryRepositories,
  log: AccountDirectoryLog
): AccountDirectory {
  return Object.freeze({
    async findByIdentifier(realmId: string, identifier: string): Promise<SignInAccount | null> {
      const credential = await repositories.userCredentials.findByRealmProviderSub(
        realmId,
        PASSWORD_PROVIDER_TYPE,
        identifier
      );
      if (credential === undefined) return null;
      const user = await repositories.users.findById(realmId, credential.userId);
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
      const passkeys = (
        await repositories.userCredentials.findAllByUserIdAndType(user.id, WEBAUTHN_PROVIDER_TYPE)
      ).filter((row) => row.realmId === realmId);
      const grants = await repositories.adminGrants.listLive(realmId, user.id);
      const factors: BoundFactor[] = [
        { type: 'password', disabled: false, hash: data.success ? data.data.password_hash : null },
        ...passkeys.map(() => ({ type: 'passkey' as const, disabled: false })),
      ];
      return Object.freeze({
        userId: user.id,
        enabled: user.enabled,
        verified: data.success && data.data.email_verified,
        admin: grants.length > 0,
        factors: Object.freeze(factors),
      });
    },
  });
}
