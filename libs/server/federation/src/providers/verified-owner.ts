import { PASSWORD_PROVIDER_TYPE, passwordCredentialDataSchema } from './password.provider';
import { isUpstreamCredentialData, upstreamCredentialDataSchema } from './upstream-credential-data';
import { WALLET_PROVIDER_TYPE, walletCredentialDataSchema } from './wallet.provider';
import { WEBAUTHN_PROVIDER_TYPE } from './webauthn.provider';
import { webauthnCredentialDataSchema } from './webauthn-credential-data';

/**
 * AN AGENT OWNER IS A VERIFIED ACCOUNT (ADR-015 Decision 8, #846).
 *
 * An account is verified when its primary identity is proved: the credential
 * that created the account, which `user_credentials.is_primary` marks and
 * which never moves in 1.0 (question 13). Only that credential counts. A
 * password account is found, reset and claimed by its address (ADR-017's
 * unclaimed-account rule), so a later key proves its holder but not the
 * identifier the account answers to: counting it would let someone who
 * registered an address they do not control add a key of their own, pass,
 * and keep the account from the address's owner (pre-hijacking; the rule was
 * weighed again and kept on 2026-11-08). An email address is otherwise an
 * attribute; no account needs one, and an account whose primary identity is
 * a passkey, a wallet or an upstream identity never meets it. An operator's
 * audited verification (#1052) is the other way an account is verified:
 * `users.verify` or the host's `verify-account` command records it on the
 * account, and it counts beside the table below (`operatorVerified`). It
 * attests the account, never an address: `email_verified` stays as it was.
 *
 * Each type has its own proof, row by row of Decision 8's table:
 *
 * - `password`: the mailbox code for the address was entered, so
 *   `email_verified` is `true` on that credential;
 * - `webauthn`: the registration ceremony finished, and QAuth checked the
 *   user-verification flag in its authenticator data: `user_verified` is not
 *   `false` (a passkey registered before the flag was stored has none, and
 *   every such registration required the flag);
 * - `wallet`: QAuth's own verifier accepted the presentation, which is the
 *   only way a wallet credential is written;
 * - an upstream identity (`oidc_*`, or an AuthMethod plugin's type): QAuth
 *   checked the sign-in that created the account, the only way an upstream
 *   account is created, and the provider's verified switch (ADR-020 §3,
 *   `marks_verified`) is on now. A provider the realm switched off, or no
 *   longer has, vouches for nothing. What QAuth asked of an account the
 *   switch left unverified (a mailbox code for the provider's address) proves
 *   an attribute, never the primary identity, so the credential's own
 *   `verified` is not read.
 *
 * Any other type proves nothing. The rule never reads
 * `REQUIRE_VERIFIED_ACCOUNT`, which governs a password account's sign-in, not
 * the ownership of an agent, and it asks that the identity is proved, not how
 * strongly: assurance (`acr`) is another question.
 */

/** Why an account is not a verified owner. */
export const VERIFIED_OWNER_REFUSAL_REASONS = [
  /** The account has no primary credential: it was deleted, or none was ever marked. */
  'no_primary_identity',
  /**
   * Its primary identity is not proved by its kind's rule: a password whose
   * mailbox code was never entered, a passkey registered without user
   * verification, an upstream identity its provider does not vouch for, or a
   * type with no proof. The decision's `identity` says which kind.
   */
  'account_not_verified',
] as const;

export type VerifiedOwnerRefusalReason = (typeof VERIFIED_OWNER_REFUSAL_REASONS)[number];

/** The kind of an account's primary identity, as Decision 8's table names it. */
export const PRIMARY_IDENTITY_KINDS = [
  'password',
  'passkey',
  'wallet',
  'upstream',
  'other',
] as const;

export type PrimaryIdentityKind = (typeof PRIMARY_IDENTITY_KINDS)[number];

/** An account's primary credential, as `user_credentials` stores it. */
export interface PrimaryIdentity {
  readonly providerType: string;
  readonly credentialData: unknown;
}

/** The realm's upstream provider of the identity's type, while it is on. */
export interface UpstreamProviderSwitch {
  /** ADR-020 §3: whether an account the provider created counts as verified. */
  readonly marksVerified: boolean;
}

/** Whether an account is a verified owner, and if not, why. */
export type VerifiedOwnerDecision =
  | {
      readonly verified: true;
      /** `none` only beside `operatorVerified`: the account has no primary identity left. */
      readonly identity: PrimaryIdentityKind | 'none';
      /**
       * `true` when an operator's verification (#1052) decided it: the
       * primary identity is not proved by its kind's rule, or the account has
       * none left. Absent otherwise.
       */
      readonly operatorVerified?: true;
    }
  | {
      readonly verified: false;
      readonly identity: PrimaryIdentityKind | 'none';
      readonly reason: VerifiedOwnerRefusalReason;
    };

/** The kind of a primary credential. An upstream identity is told apart by its data. */
export function primaryIdentityKindOf(primary: PrimaryIdentity): PrimaryIdentityKind {
  switch (primary.providerType) {
    case PASSWORD_PROVIDER_TYPE:
      return 'password';
    case WEBAUTHN_PROVIDER_TYPE:
      return 'passkey';
    case WALLET_PROVIDER_TYPE:
      return 'wallet';
    default:
      return isUpstreamCredentialData(primary.credentialData) ? 'upstream' : 'other';
  }
}

/** What the decision reads of the account itself, beside its primary identity. */
export interface VerifiedOwnerAccount {
  /**
   * Whether an operator verified the account (ADR-015 Decision 8, amended
   * 2026-11-08; #1052): `users.operator_verified_at` is set.
   */
  readonly operatorVerified?: boolean;
}

/**
 * Decide whether the account whose primary identity is `primary` is a
 * verified owner (ADR-015 Decision 8). `upstreamProvider` is the realm's
 * provider of the identity's type while it is on, read only for an upstream
 * identity; `undefined` when the realm has none of that type, or it is off.
 * An operator's verification of the account (`account.operatorVerified`)
 * makes it verified whatever its primary identity's proof says, and with no
 * primary identity left too (one unlinked while another credential still
 * signs in): it attests the account, not a credential, and counts beside
 * the table (Decision 8, amended 2026-11-08).
 */
export function decideVerifiedOwner(
  primary: PrimaryIdentity | undefined,
  upstreamProvider?: UpstreamProviderSwitch,
  account: VerifiedOwnerAccount = {}
): VerifiedOwnerDecision {
  if (primary === undefined) {
    return account.operatorVerified === true
      ? { verified: true, identity: 'none', operatorVerified: true }
      : { verified: false, identity: 'none', reason: 'no_primary_identity' };
  }
  const decision = decideByPrimaryIdentity(primary, upstreamProvider);
  if (decision.verified || account.operatorVerified !== true) return decision;
  return {
    verified: true,
    identity: decision.identity as PrimaryIdentityKind,
    operatorVerified: true,
  };
}

/** Row by row of Decision 8's table: whether `primary` is proved by its kind's rule. */
function decideByPrimaryIdentity(
  primary: PrimaryIdentity,
  upstreamProvider: UpstreamProviderSwitch | undefined
): VerifiedOwnerDecision {
  const identity = primaryIdentityKindOf(primary);
  const refuse = (reason: VerifiedOwnerRefusalReason): VerifiedOwnerDecision => ({
    verified: false,
    identity,
    reason,
  });
  switch (identity) {
    case 'password': {
      const data = passwordCredentialDataSchema.safeParse(primary.credentialData);
      if (!data.success) return refuse('account_not_verified');
      return data.data.email_verified === true
        ? { verified: true, identity }
        : refuse('account_not_verified');
    }
    case 'passkey': {
      const data = webauthnCredentialDataSchema.safeParse(primary.credentialData);
      if (!data.success) return refuse('account_not_verified');
      return data.data.user_verified !== false
        ? { verified: true, identity }
        : refuse('account_not_verified');
    }
    case 'wallet':
      return walletCredentialDataSchema.safeParse(primary.credentialData).success
        ? { verified: true, identity }
        : refuse('account_not_verified');
    case 'upstream':
      if (!upstreamCredentialDataSchema.safeParse(primary.credentialData).success) {
        return refuse('account_not_verified');
      }
      return upstreamProvider?.marksVerified === true
        ? { verified: true, identity }
        : refuse('account_not_verified');
    case 'other':
      return refuse('account_not_verified');
  }
}
