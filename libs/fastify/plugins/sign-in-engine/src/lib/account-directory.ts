import {
  isUpstreamCredentialData,
  PASSWORD_PROVIDER_TYPE,
  passwordCredentialDataSchema,
  upstreamCredentialDataSchema,
  WEBAUTHN_PROVIDER_TYPE,
} from '@qauth-labs/server-federation';
import {
  type AccountDirectory,
  type BoundFactor,
  REQUIRED_ACTIONS,
  type RequiredAction,
  type SignInAccount,
  type SignInCandidate,
} from '@qauth-labs/server-sign-in-engine';
import { isOperatorVerified } from '@qauth-labs/shared-validation';

import { TOTP_PROVIDER_TYPE } from './totp';

/** A `user_credentials` row, as far as the directory reads it. */
interface CredentialRow {
  readonly id: string;
  readonly userId: string;
  readonly realmId: string;
  readonly providerType: string;
  readonly credentialData: Record<string, unknown>;
  /** The credential's subject: a password credential's identifier, its address. */
  readonly externalSub?: string;
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
    /** Every credential of the user, of every type: one read once a factor proved the user. */
    findAllByUserId(userId: string): Promise<CredentialRow[]>;
  };
  readonly users: {
    findById(
      realmId: string,
      id: string
    ): Promise<
      | {
          readonly id: string;
          readonly enabled: boolean;
          /** When an operator verified the account (#1052); `null` when none did. */
          readonly operatorVerifiedAt?: number | null;
        }
      | undefined
    >;
  };
  readonly adminGrants: {
    listLive(realmId: string, userId: string): Promise<readonly unknown[]>;
  };
  /** The account's pending required actions (#635, `user_required_actions`). */
  readonly userRequiredActions: {
    listForUser(realmId: string, userId: string): Promise<readonly { readonly action: string }[]>;
  };
}

/** Whether `action` is one the engine knows; the table's check allows no other. */
function isRequiredAction(action: string): action is RequiredAction {
  return (REQUIRED_ACTIONS as readonly string[]).includes(action);
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
 *   account: every credential it holds in the realm, in one read, of which
 *   the password, passkey (`webauthn`) and TOTP (`totp`, #653) ones are its
 *   factors, and whether
 *   it holds a live admin grant seen from the realm (#510). An account that
 *   exists so costs one read more than none before the password is checked,
 *   not four. It is verified when every password credential's
 *   `email_verified` says so and every upstream provider's credential its
 *   `verified` (#639: false while a provider whose verified switch is off
 *   created the account and QAuth has not verified its address); with
 *   neither, a passkey or a wallet is its primary identity, with no address
 *   to prove. A credential whose data cannot be read is not verified. It
 *   reads the account's pending required actions too (#635): an
 *   `update_password` among them makes the sign-in ask for a new password
 *   before it completes.
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
      const addressProved = data.success && data.data.email_verified;
      return Object.freeze({
        userId: user.id,
        enabled: user.enabled,
        // Its confirmed address, or an operator's verification (#1052).
        verified: isOperatorVerified(user) || addressProved,
        // The address alone: what a reset reads (#1052).
        addressProved,
        password: Object.freeze({
          disabled,
          hash: data.success ? data.data.password_hash : null,
          ...(data.success && data.data.password_normalization !== undefined
            ? { normalization: data.data.password_normalization }
            : {}),
          ...(marked && !disabled ? { ignoredMark: true } : {}),
        }),
      });
    },

    async findByUserId(realmId: string, userId: string): Promise<SignInAccount | null> {
      const user = await stores.users.findById(realmId, userId);
      if (user === undefined) return null;
      const credentials = (await stores.userCredentials.findAllByUserId(user.id)).filter(
        (row) => row.realmId === realmId
      );
      const passwords = credentials.filter((row) => row.providerType === PASSWORD_PROVIDER_TYPE);
      const passkeys = credentials.filter((row) => row.providerType === WEBAUTHN_PROVIDER_TYPE);
      const totps = credentials.filter((row) => row.providerType === TOTP_PROVIDER_TYPE);
      const upstreams = credentials.filter((row) => isUpstreamCredentialData(row.credentialData));
      const grants = await stores.adminGrants.listLive(realmId, user.id);
      const pending = await stores.userRequiredActions.listForUser(realmId, user.id);
      const requiredActions: RequiredAction[] = [];
      for (const { action } of pending) {
        if (isRequiredAction(action)) {
          if (!requiredActions.includes(action)) requiredActions.push(action);
        } else {
          // The table's check makes this impossible; never a reason to drop the others.
          log.error({ userId: user.id }, 'unknown required action on a user');
        }
      }
      const disabled = await disabledOf(realmId, passwords);
      const address = passwords.length === 1 ? passwords[0]?.externalSub : undefined;
      const factors: BoundFactor[] = [
        ...passwords.map((_, index) => ({
          type: 'password' as const,
          disabled: disabled[index] === true,
        })),
        // A passkey's mark is honoured always (#651): the arming belongs to
        // the password's failure ladder, and the server refuses an assertion
        // of a marked passkey whatever it.
        ...passkeys.map((row) => ({
          type: 'passkey' as const,
          disabled: row.disabledAt !== undefined && row.disabledAt !== null,
        })),
        // A TOTP's mark is honoured always (#653): its hard action sets the
        // mark only while it is armed, so a mark is never one to ignore.
        ...totps.map((row) => ({
          type: 'totp' as const,
          disabled: row.disabledAt !== undefined && row.disabledAt !== null,
        })),
      ];
      const addressProved =
        passwords.every((row) => {
          const data = passwordCredentialDataSchema.safeParse(row.credentialData);
          return data.success && data.data.email_verified;
        }) &&
        upstreams.every((row) => {
          const data = upstreamCredentialDataSchema.safeParse(row.credentialData);
          if (!data.success) {
            log.error({ credentialId: row.id }, 'malformed credential_data on upstream credential');
          }
          return data.success && data.data.verified;
        });
      return Object.freeze({
        userId: user.id,
        enabled: user.enabled,
        admin: grants.length > 0,
        // An operator's verification (#1052) verifies the account whatever its
        // credentials prove, and claims it if it was unclaimed; the address
        // stays unproved until its mailbox proves it.
        verified: isOperatorVerified(user) || addressProved,
        addressProved,
        factors: Object.freeze(factors),
        requiredActions: Object.freeze(requiredActions),
        // The address a sign-in a passkey proved goes on with (#651).
        ...(address === undefined ? {} : { identifier: address }),
      });
    },
  });
}
