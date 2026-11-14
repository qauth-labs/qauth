import {
  isUpstreamCredentialData,
  PASSWORD_PROVIDER_TYPE,
  passwordSetAtOf,
  WALLET_PROVIDER_TYPE,
  WEBAUTHN_PROVIDER_TYPE,
  webauthnCredentialDataSchema,
} from '@qauth-labs/fastify-plugin-federation';
import { TOTP_PROVIDER_TYPE } from '@qauth-labs/fastify-plugin-sign-in-engine';
import type { FastifyInstance } from 'fastify';

import { type AccountFactor, requiredFactorOf } from './account-operation-guard';
import { isNewCredential } from './new-factors';

/**
 * THE ACCOUNT'S SIGN-IN METHODS (#844, #1107; ADR-017 Decision 8, ADR-020 §3):
 * what the hosted account page's overview and the account API's
 * `account.signInMethods.get` read of one account, from one place.
 *
 * The page shows each passkey and the linked accounts' list; the API answers
 * counts. Both read the account's credentials of the realm, its recovery
 * codes' status and the factor a fresh authentication must prove
 * (`requiredFactorOf`) here, so the two never disagree.
 */

/** One credential row of an account, as the repository returns it. */
export type AccountCredentialRow = Awaited<
  ReturnType<FastifyInstance['repositories']['userCredentials']['findAllByUserId']>
>[number];

/** One passkey of the account, as the page shows it. */
export interface AccountPasskey {
  readonly id: string;
  readonly nickname: string | null;
  readonly createdAt: number;
  readonly lastUsedAt: number | null;
  readonly backedUp: boolean;
  /** The failure ladder's mark, or a rebind's: it signs in no more. */
  readonly disabled: boolean;
  /**
   * When it stops being new (#1064), while it is: it was bound after a
   * sign-in that proved only the password, and the password alone may
   * remove it until then.
   */
  readonly newUntil?: number;
}

/** The account's sign-in methods. */
export interface AccountSignInMethods {
  readonly password: {
    readonly set: boolean;
    /** The password's address: where the account's notices go. */
    readonly address?: string;
    /**
     * When the password was last set, in epoch milliseconds (#1107), as its
     * credential records it. A password set before #1107 recorded the time
     * has none: the credential's other times are those of other writes too
     * (an address verification, the failure ladder's mark).
     */
    readonly setAt?: number;
  };
  /** The passkeys, newest first. */
  readonly passkeys: readonly AccountPasskey[];
  readonly totp: { readonly set: boolean; readonly newUntil?: number };
  readonly recoveryCodes: { readonly issued: boolean; readonly unused: number };
  /** How many upstream accounts and wallets are linked to the account. */
  readonly linkedCount: number;
  /** The `amr` value a fresh authentication must hold (ADR-017 Decision 8). */
  readonly requiredFactor: AccountFactor;
}

/** The time a password credential records it was set, when it records one. */
function setAtOf(credentialData: unknown): { readonly setAt?: number } {
  const setAt = passwordSetAtOf(credentialData);
  return setAt === undefined ? {} : { setAt };
}

/** The account's credentials of `realmId`: a row of another realm is none of its methods here (#489). */
export async function accountCredentials(
  fastify: FastifyInstance,
  realmId: string,
  userId: string
): Promise<AccountCredentialRow[]> {
  return (await fastify.repositories.userCredentials.findAllByUserId(userId)).filter(
    (credential) => credential.realmId === realmId
  );
}

/**
 * The sign-in methods of the account `userId` of `realmId`, which holds
 * `credentials` (its rows of that realm, {@link accountCredentials}), at
 * `now`.
 */
export async function signInMethodsOf(
  fastify: FastifyInstance,
  realmId: string,
  userId: string,
  credentials: readonly AccountCredentialRow[],
  now: number
): Promise<AccountSignInMethods> {
  const password = credentials.find((row) => row.providerType === PASSWORD_PROVIDER_TYPE);
  const passkeys = credentials
    .filter((row) => row.providerType === WEBAUTHN_PROVIDER_TYPE)
    .flatMap((row): AccountPasskey[] => {
      const data = webauthnCredentialDataSchema.safeParse(row.credentialData);
      if (!data.success) return [];
      return [
        {
          id: row.id,
          nickname: data.data.nickname,
          createdAt: data.data.created_at,
          lastUsedAt: data.data.last_used_at,
          backedUp: data.data.backed_up,
          disabled: row.disabledAt !== null && row.disabledAt !== undefined,
          ...(isNewCredential(row, now) ? { newUntil: row.newUntil as number } : {}),
        },
      ];
    })
    .sort((a, b) => b.createdAt - a.createdAt);
  const totp = credentials.find((row) => row.providerType === TOTP_PROVIDER_TYPE);
  const recovery = await fastify.repositories.userRecoveryCodes.status(realmId, userId);
  return {
    password:
      password === undefined
        ? { set: false }
        : {
            set: true,
            address: password.externalSub,
            ...setAtOf(password.credentialData),
          },
    passkeys,
    totp: {
      set: totp !== undefined,
      ...(totp !== undefined && isNewCredential(totp, now)
        ? { newUntil: totp.newUntil as number }
        : {}),
    },
    recoveryCodes: { issued: recovery.issued, unused: recovery.unused },
    linkedCount: credentials.filter(
      (row) =>
        row.providerType === WALLET_PROVIDER_TYPE || isUpstreamCredentialData(row.credentialData)
    ).length,
    requiredFactor: requiredFactorOf(credentials, realmId, now),
  };
}

/** The sign-in methods of the account `userId` of `realmId`, read now. */
export async function readSignInMethods(
  fastify: FastifyInstance,
  realmId: string,
  userId: string,
  now: number = Date.now()
): Promise<AccountSignInMethods> {
  const credentials = await accountCredentials(fastify, realmId, userId);
  return signInMethodsOf(fastify, realmId, userId, credentials, now);
}
