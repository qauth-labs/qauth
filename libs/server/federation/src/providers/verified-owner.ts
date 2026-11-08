import { PASSWORD_PROVIDER_TYPE, passwordCredentialDataSchema } from './password.provider';
import { isUpstreamCredentialData, upstreamCredentialDataSchema } from './upstream-credential-data';
import { WALLET_PROVIDER_TYPE, walletCredentialDataSchema } from './wallet.provider';
import { WEBAUTHN_PROVIDER_TYPE } from './webauthn.provider';
import { webauthnCredentialDataSchema } from './webauthn-credential-data';

/**
 * AN AGENT OWNER IS A VERIFIED ACCOUNT (ADR-015 Decision 8 and question 13,
 * amended 2026-11-08; #846).
 *
 * An account is verified when QAuth proved a strong credential it holds,
 * whenever that credential was added. The primary identity (the credential
 * that created the account, `user_credentials.is_primary`, never moved in
 * 1.0) records where the account came from; it does not limit which proof
 * counts. An email address is an attribute: no account needs one, and none
 * counts on its own. A key proves its holder, never an address, so an
 * account verified by a passkey keeps an unverified address unverified.
 *
 * Each type has its own proof, row by row of Decision 8's table:
 *
 * - `password`: the mailbox code for the credential's address was entered,
 *   which the credential records as `email_verified` (only the mailbox-code
 *   paths set it: the verification link, the engine's `email_code`, the
 *   registration after its code and the reset after its recovery code). The
 *   password alone proves nothing;
 * - `webauthn`: the registration ceremony finished, and QAuth checked the
 *   user-verification flag in its authenticator data: `user_verified` is not
 *   `false` (a passkey registered before the flag was stored has none, and
 *   every such registration required the flag);
 * - `wallet`: QAuth's own verifier accepted the presentation, which is the
 *   only way a wallet credential is written;
 * - an upstream identity (`oidc_*`, or an AuthMethod plugin's type): QAuth
 *   checked the sign-in that created or linked it, the only way an upstream
 *   credential is written, and the provider's verified switch (ADR-020 §3,
 *   `marks_verified`) is on now. A provider the realm switched off, or no
 *   longer has, vouches for nothing. What QAuth asked of an account the
 *   switch left unverified (a mailbox code for the provider's address) proves
 *   an attribute, so the credential's own `verified` is not read.
 *
 * Any other type proves nothing. An operator's verification (#1052) is the
 * other way, recorded on the account. The rule never reads
 * `REQUIRE_VERIFIED_ACCOUNT`, and it asks that a credential is proved, not
 * how strongly: assurance (`acr`) is another question.
 */

/** Why an account is not a verified owner. */
export const VERIFIED_OWNER_REFUSAL_REASONS = [
  /** The account holds no credential: every one was removed. */
  'no_credentials',
  /** No credential the account holds is proved. */
  'account_not_verified',
] as const;

export type VerifiedOwnerRefusalReason = (typeof VERIFIED_OWNER_REFUSAL_REASONS)[number];

/** The kind of a credential, as Decision 8's table names it. */
export const CREDENTIAL_KINDS = ['password', 'passkey', 'wallet', 'upstream', 'other'] as const;

export type CredentialKind = (typeof CREDENTIAL_KINDS)[number];

/** One credential of an account, as `user_credentials` stores it. */
export interface AccountCredential {
  readonly providerType: string;
  readonly credentialData: unknown;
  /** Whether this credential created the account (`is_primary`). */
  readonly isPrimary: boolean;
}

/** The realm's upstream provider of a credential's type, while it is on. */
export interface UpstreamProviderSwitch {
  /** ADR-020 §3: whether an identity the provider proved counts as verified. */
  readonly marksVerified: boolean;
}

/**
 * The realm's provider of an upstream `providerType` while it is on, or
 * `undefined` when the realm has none of that type, or it is off.
 */
export type UpstreamProviderLookup = (providerType: string) => UpstreamProviderSwitch | undefined;

/** Whether an account is a verified owner, and if not, why. */
export type VerifiedOwnerDecision =
  | {
      readonly verified: true;
      /** The kind of the credential whose proof counted. */
      readonly proof: CredentialKind;
      /** The kind of the credential that created the account, or `none`. */
      readonly primaryIdentity: CredentialKind | 'none';
    }
  | {
      readonly verified: false;
      readonly reason: VerifiedOwnerRefusalReason;
      readonly primaryIdentity: CredentialKind | 'none';
    };

/** The kind of a credential. An upstream identity is told apart by its data. */
export function credentialKindOf(
  credential: Pick<AccountCredential, 'providerType' | 'credentialData'>
): CredentialKind {
  switch (credential.providerType) {
    case PASSWORD_PROVIDER_TYPE:
      return 'password';
    case WEBAUTHN_PROVIDER_TYPE:
      return 'passkey';
    case WALLET_PROVIDER_TYPE:
      return 'wallet';
    default:
      return isUpstreamCredentialData(credential.credentialData) ? 'upstream' : 'other';
  }
}

/**
 * Whether QAuth proved `credential`, by its row of Decision 8's table.
 * `upstreamProvider` is the realm's provider of its type while it is on,
 * read only for an upstream identity.
 */
export function credentialIsProved(
  credential: Pick<AccountCredential, 'providerType' | 'credentialData'>,
  upstreamProvider?: UpstreamProviderSwitch
): boolean {
  switch (credentialKindOf(credential)) {
    case 'password': {
      const data = passwordCredentialDataSchema.safeParse(credential.credentialData);
      return data.success && data.data.email_verified === true;
    }
    case 'passkey': {
      const data = webauthnCredentialDataSchema.safeParse(credential.credentialData);
      return data.success && data.data.user_verified !== false;
    }
    case 'wallet':
      return walletCredentialDataSchema.safeParse(credential.credentialData).success;
    case 'upstream':
      return (
        upstreamCredentialDataSchema.safeParse(credential.credentialData).success &&
        upstreamProvider?.marksVerified === true
      );
    case 'other':
      return false;
  }
}

/**
 * Decide whether the account that holds `credentials` is a verified owner
 * (ADR-015 Decision 8): one proved credential is enough, the primary one or
 * any added later. The primary one is tried first, so the decision names it
 * when it counts. `upstreamProviderOf` is read only for an upstream identity.
 */
export function decideVerifiedOwner(
  credentials: readonly AccountCredential[],
  upstreamProviderOf: UpstreamProviderLookup = () => undefined
): VerifiedOwnerDecision {
  const primary = credentials.find((credential) => credential.isPrimary);
  const primaryIdentity = primary === undefined ? 'none' : credentialKindOf(primary);
  if (credentials.length === 0) {
    return { verified: false, reason: 'no_credentials', primaryIdentity };
  }
  const ordered = [...credentials].sort((a, b) => Number(b.isPrimary) - Number(a.isPrimary));
  for (const credential of ordered) {
    const kind = credentialKindOf(credential);
    const provider = kind === 'upstream' ? upstreamProviderOf(credential.providerType) : undefined;
    if (credentialIsProved(credential, provider)) {
      return { verified: true, proof: kind, primaryIdentity };
    }
  }
  return { verified: false, reason: 'account_not_verified', primaryIdentity };
}
