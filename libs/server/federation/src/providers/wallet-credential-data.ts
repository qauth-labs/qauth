import { z } from 'zod';

/**
 * READING the wallet binding back out of a `user_credentials.credential_data`
 * row (issues #235 / #238, ADR-002 / ADR-004 / ADR-009).
 *
 * ## Why the wallet row carries a binding at all
 *
 * `PasswordProvider` stores the secret it will later re-check
 * (`password_hash`). The wallet row stores the analogous thing, and ADR-009 §1
 * says exactly what it is:
 *
 * > The strategy MUST additionally verify that the presented credential matches
 * > the **binding stored for the asserted account**.
 *
 * That stored binding is `wallet_binding`. Without it a wallet row would record
 * that *some* credential was once linked and prove nothing on the next login —
 * which is ADR-009 §1's total-authentication-bypass failure mode.
 *
 * ## Why the READER has its own, narrower schema
 *
 * The WRITE shape is owned by `wallet.provider.ts`
 * (`walletCredentialDataSchema`) and is deliberately rich: format, credential
 * type, issuer, strategy, enrolment instant. This module reads ONE field out of
 * rows that may have been written by an older or newer binary, and asking for
 * the whole write shape would make a row that gained a field — or lost one QAuth
 * has since stopped writing — read as "no binding". That is not fail-closed, it
 * is fail-random: `null` means "this account has no wallet binding", which
 * ADR-009's second bootstrap case turns into a REFUSAL for a legitimate account.
 *
 * So the reader asks for exactly what it consumes, with the same bound the
 * writer applies, and nothing else.
 *
 * ## What is deliberately NOT in the column
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
 */

/**
 * Longest stored binding accepted, by the writer and by the reader alike.
 *
 * A binding is `wb1:` + 64 hex characters today. The cap is generous enough for
 * a future scheme tag and short enough that an oversized `credential_data`
 * cannot turn a login into an unbounded string comparison.
 */
export const MAX_WALLET_BINDING_LENGTH = 256;

/**
 * The one field {@link readWalletBinding} consumes.
 *
 * NOT `.strict()`: every other key in the column is none of this reader's
 * business. Snake_case, matching the write shape exactly — a camelCase drift
 * would satisfy every database constraint and silently strand every enrolled
 * wallet at its next login.
 */
const storedWalletBindingSchema = z.object({
  wallet_binding: z.string().min(1).max(MAX_WALLET_BINDING_LENGTH),
});

/**
 * Read the stored binding out of an arbitrary `credential_data` value.
 *
 * Returns `null` — never throws, and never a partial value — for every row that
 * does not carry a usable binding: a password row, a wallet row whose binding is
 * `null` because the strategy that wrote it stores none, a hand-edited column.
 * `null` is the documented "this account has no wallet binding" value of
 * `SubjectAccountCandidate.walletBinding`, and ADR-009's second bootstrap case
 * makes it a REFUSAL rather than an invitation to create one, so degrading to
 * `null` is fail-closed rather than lossy.
 *
 * @param credentialData - the raw JSONB value, from the database.
 * @returns the binding, or `null`.
 */
export function readWalletBinding(credentialData: unknown): string | null {
  const parsed = storedWalletBindingSchema.safeParse(credentialData);
  return parsed.success ? parsed.data.wallet_binding : null;
}
