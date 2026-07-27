import { z } from 'zod';

/**
 * The `credential_data` JSONB shape for `provider_type='wallet'` rows
 * (issue #238, ADR-002 / ADR-004 / ADR-009).
 *
 * ## Why the wallet row needs a payload at all
 *
 * `PasswordProvider` stores the secret it will later re-check
 * (`password_hash`). The wallet row stores the analogous thing, and ADR-009 §1
 * says exactly what it is:
 *
 * > The strategy MUST additionally verify that the presented credential matches
 * > the **binding stored for the asserted account**.
 *
 * That stored binding is this shape's `wallet_binding`. Without it a wallet row
 * would record that *some* credential was once linked and prove nothing on the
 * next login — which is ADR-009 §1's total-authentication-bypass failure mode.
 *
 * ## What is deliberately NOT here
 *
 * - **No holder key material.** No `cnf`, no JWK, no thumbprint. OID4VP 1.0
 *   §15.5–§15.6 treat holder key material as a linkability defect wallets rotate
 *   away, and ADR-009 §4 refuses it as an account key. `ValidatedCredential`
 *   carries none, so there is nothing here to copy even by accident.
 * - **No claim values.** The binding is a digest (see `subject-binding.ts`), so
 *   a birth date or a national identification number never lands in this column
 *   in the clear. ADR-009 Finding 2 is what that restraint is for.
 * - **No `external_sub`.** That is a column of its own, and duplicating it here
 *   would create two answers to "which account is this" that can disagree.
 *
 * ## Shape ownership
 *
 * Single owner, exactly as `password.provider.ts` is the single owner of the
 * password shape: snake_case keys, one constructor, one reader. A camelCase
 * drift would satisfy every database constraint and silently strand every
 * linked wallet at the next login.
 */

/**
 * Longest stored binding accepted.
 *
 * A binding is `wb1:` + 64 hex characters today. The cap is generous enough for
 * a future scheme tag and short enough that an oversized `credential_data`
 * cannot turn a login into an unbounded string comparison.
 */
export const MAX_WALLET_BINDING_LENGTH = 256;

/** Longest issuer identifier / `vct` recorded alongside the binding. */
const MAX_CREDENTIAL_DESCRIPTOR_LENGTH = 2048;

/**
 * `credential_data` for `provider_type='wallet'`.
 *
 * Deliberately NOT `.strict()`, for the same reason
 * `passwordCredentialDataSchema` is not: later issues may add sibling keys, and
 * a reader of today's binary must keep parsing rows written by tomorrow's.
 */
export const walletCredentialDataSchema = z.object({
  /**
   * The binding derived when this credential was linked
   * (`deriveWalletBinding`), re-derived and compared on every later
   * presentation. See the module JSDoc.
   */
  wallet_binding: z.string().min(1).max(MAX_WALLET_BINDING_LENGTH),
  /**
   * The **validated** issuer identity the linked credential came from.
   *
   * Recorded for operator visibility — "which issuer does this account's wallet
   * credential come from?" is a question an administrator has to be able to
   * answer without replaying a presentation. It is NOT read back as a trust
   * input: the binding digest already covers the issuer, and re-deriving it is
   * what makes a credential from another issuer fail to match.
   */
  issuer: z.string().min(1).max(MAX_CREDENTIAL_DESCRIPTOR_LENGTH),
  /** The credential type (`vct`) that was linked. Operator visibility only. */
  vct: z.string().min(1).max(MAX_CREDENTIAL_DESCRIPTOR_LENGTH),
});

export type WalletCredentialData = z.infer<typeof walletCredentialDataSchema>;

/**
 * Build the `credential_data` object for a wallet credential row.
 *
 * The only sanctioned constructor of this shape.
 *
 * @param binding - the derived wallet binding (`deriveWalletBinding`).
 * @param issuer - the VALIDATED issuer identifier (`ValidatedIssuer.identifier`).
 * @param vct - the credential type that was presented.
 */
export function buildWalletCredentialData(
  binding: string,
  issuer: string,
  vct: string
): WalletCredentialData {
  return { wallet_binding: binding, issuer, vct };
}

/**
 * Read the stored binding out of an arbitrary `credential_data` value.
 *
 * Returns `null` — never throws, and never a partial value — for every row that
 * does not carry a usable binding: a password row, a wallet row written by a
 * future scheme this binary cannot parse, a hand-edited column. `null` is the
 * documented "this account has no wallet binding" value of
 * `SubjectAccountCandidate.walletBinding`, and ADR-009's second bootstrap case
 * makes it a REFUSAL rather than an invitation to create one, so degrading to
 * `null` is fail-closed rather than lossy.
 *
 * @param credentialData - the raw JSONB value, from the database.
 * @returns the binding, or `null`.
 */
export function readWalletBinding(credentialData: unknown): string | null {
  const parsed = walletCredentialDataSchema.safeParse(credentialData);
  return parsed.success ? parsed.data.wallet_binding : null;
}
