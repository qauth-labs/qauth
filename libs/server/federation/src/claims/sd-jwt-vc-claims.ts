import { normalizeEmail } from '@qauth-labs/shared-validation';

import { SD_JWT_VC_FORMAT } from '../oid4vp/credential-format';
import { EMAIL_ATTR_KEY } from '../providers/password.provider';
import { readBindingClaim } from '../subject/subject-binding';
import type {
  CredentialClaimAdapter,
  CredentialClaimSet,
  NormalizedCredentialClaim,
} from './credential-claims.types';

/**
 * The SD-JWT VC (`dc+sd-jwt`) claim adapter — issue #235's first and only
 * shipped format.
 *
 * ## An ALLOWLIST, because an attribute row is future claim surface
 *
 * The mapping is a closed table. A claim not in it produces no row, and that is
 * the security decision this module exists to make: `user_attributes` is read
 * back by `helpers/email-claims.ts` and emitted into ID tokens and `/userinfo`,
 * so "record whatever the credential disclosed" would let any trusted issuer of
 * any credential type define QAuth's downstream claim vocabulary. Issuer trust
 * (#236) bounds WHO may write; this table bounds WHAT they may write.
 *
 * It also bounds HOW MUCH: the table is the row-count bound. Without it a
 * credential disclosing a thousand claims would become a thousand-row upsert on
 * an unauthenticated login path.
 *
 * ## The names are the SD-JWT VC names, and only those
 *
 * ADR-009 Finding 1 records the EUDI PID Rulebook §4.3 worked example — its
 * SD-JWT VC encoding carries `birthdate`, not the mdoc data identifier
 * `birth_date`. Adding the mdoc spellings here as aliases would be the exact
 * confusion `credential-claims.types.ts` explains the format boundary exists to
 * prevent: the SD-JWT path would start accepting a vocabulary no SD-JWT VC
 * issuer emits, and the future `mso_mdoc` adapter would have nothing left to do
 * that this one was not already doing wrongly.
 *
 * ## Values are primitives, and structured claims are refused rather than encoded
 *
 * `user_attributes` stores ONE `text` value per `(user_id, source, attr_key)`.
 * A multi-valued or structured claim has no representation in that column, and
 * inventing one (joining `nationalities` with a comma, JSON-encoding `address`)
 * would be worse than omitting it: `selectTrustedAttribute` hands its winner's
 * `attrValue` straight to a token claim, so `"DE,FR"` would ship as if it were a
 * scalar. See {@link SD_JWT_VC_UNMAPPED_CLAIMS}, which records those claims and
 * the reason each is left out, so a future contributor finds a decision rather
 * than a gap.
 *
 * The value-length bound is not restated here: `readBindingClaim` already
 * applies `MAX_BINDING_CLAIM_VALUE_LENGTH` to the same credential's claims, and
 * two different caps would mean a value could bind an account but not be
 * recorded, or the reverse.
 */

/**
 * SD-JWT VC claim name → `user_attributes.attr_key`.
 *
 * Every key is identical to its claim name today, and that is a property worth
 * stating rather than a reason to drop the indirection: the mapping is what lets
 * a future format adapter map a DIFFERENT name onto the same canonical key (mdoc
 * `birth_date` → `birthdate`), and it is what guarantees a wallet-sourced email
 * lands on `EMAIL_ATTR_KEY` — the key `PasswordProvider` writes and
 * `resolveEmailClaims` reads. If the two ever diverged, #229's trust order would
 * silently stop comparing them and a verified wallet email would never outrank a
 * self-reported one.
 *
 * Sources for the vocabulary:
 *
 * - **OpenID Connect Core 1.0 §5.1** standard claims: `email`, `phone_number`,
 *   `given_name`, `family_name`, `name`, `birthdate`, `locale`.
 * - **EUDI PID Rulebook §4.3** (as recorded in ADR-009 Finding 1) for which of
 *   those an SD-JWT VC PID actually carries.
 * - **Directory vocabulary** for the professional-credential attributes, which
 *   no OIDC or IANA claim registry covers: `title` (RFC 2798 `inetOrgPerson`),
 *   `organization` and `employee_number` (RFC 7643 SCIM Enterprise User
 *   `organization` / `employeeNumber`, in the snake_case form JWT claim names
 *   use). Named here rather than invented per deployment, and extending the
 *   table is a one-line change reviewed like any other.
 */
export const SD_JWT_VC_ATTRIBUTE_CLAIMS: Readonly<Record<string, string>> = Object.freeze({
  // Contact
  email: EMAIL_ATTR_KEY,
  phone_number: 'phone_number',
  // Identity
  given_name: 'given_name',
  family_name: 'family_name',
  name: 'name',
  birthdate: 'birthdate',
  nationality: 'nationality',
  locale: 'locale',
  // Professional attestations (EAA)
  title: 'title',
  organization: 'organization',
  employee_number: 'employee_number',
});

/**
 * Claims an SD-JWT VC credential may carry that are DELIBERATELY not mapped,
 * with the reason each is left out.
 *
 * Data rather than prose so `sd-jwt-vc-claims.test.ts` can assert that none of
 * them ever produces a row: a future contributor adding one to
 * {@link SD_JWT_VC_ATTRIBUTE_CLAIMS} has to delete its entry here, which is a
 * visible act rather than an oversight.
 */
export const SD_JWT_VC_UNMAPPED_CLAIMS: Readonly<Record<string, string>> = Object.freeze({
  nationalities:
    "an ARRAY in the PID Rulebook's SD-JWT VC encoding; `user_attributes` holds one text value per key, and joining members would ship a list where a downstream reader expects a scalar",
  address:
    'a structured claim (OIDC Core §5.1 Address); JSON-encoding it into a text column would make every reader parse a shape nothing declares',
  place_of_birth: 'structured, for the same reason as `address`',
  age_equal_or_over:
    'a nested object of age assertions in the PID Rulebook; each member would need its own key and its own decision about what asserting it downstream means',
  sex: 'ISO/IEC 5218 numeric codes, a different value space from the OIDC `gender` string; mapping one onto the other would silently reinterpret the value',
  portrait:
    'a biometric, and a large binary; recording it as an attribute serves no claim QAuth emits',
  picture: 'as `portrait`',
  email_verified:
    'a verification FLAG, not an attribute. Wallet rows are written `verified=true` because a trusted issuer signed the claim; a credential-supplied flag must never be able to lower that, and cannot be allowed to raise anything either',
  issuing_authority:
    'metadata about the ATTESTATION rather than an assertion about the person; it belongs in `user_credentials.credential_data`, which is where `buildWalletCredentialData` records it',
  issuing_country: 'as `issuing_authority`',
  document_number: 'as `issuing_authority`; ADR-009 Finding 4 also rules it out as an account key',
  expiry_date:
    "the credential's own validity, already carried by `ValidatedCredential.validity` and applied as every row's `expiresAt`",
});

/** Whether a mapped value is usable as `user_attributes.attr_value` (`text NOT NULL`). */
function usableValue(value: string): boolean {
  return value.length > 0 && value.trim().length > 0;
}

/**
 * Reduce one claim to its `attr_value` string.
 *
 * Only `email` is normalized, and it MUST be: `PasswordProvider` writes
 * `normalizeEmail(email)` and #229 ranks the two sources against each other by
 * key, so a wallet row carrying `Alice@Example.COM` next to a self-reported
 * `alice@example.com` would present one address to a downstream app and a
 * different one after the wallet credential expired.
 *
 * Everything else is recorded VERBATIM. Claim values are issuer-signed
 * assertions; case-folding a family name or reformatting a date would replace
 * what the issuer said with QAuth's opinion of it.
 */
function attributeValue(attrKey: string, value: string | number | boolean): string | undefined {
  if (attrKey === EMAIL_ATTR_KEY) {
    if (typeof value !== 'string') return undefined;
    const normalized = normalizeEmail(value);
    return usableValue(normalized) ? normalized : undefined;
  }

  const rendered = typeof value === 'string' ? value : String(value);

  return usableValue(rendered) ? rendered : undefined;
}

/**
 * The SD-JWT VC claim adapter (`dc+sd-jwt`).
 *
 * Iterates the TABLE, not the credential: the number of claims read is fixed by
 * QAuth, so a credential cannot influence how much work normalization does, and
 * the output order is the table's order rather than the holder's disclosure
 * order. A deterministic order matters because `upsertMany` collapses duplicate
 * `(source, attrKey)` pairs last-wins — with a holder-controlled order, which
 * value won would be a holder-controlled outcome.
 */
export const sdJwtVcClaimAdapter: CredentialClaimAdapter = {
  format: SD_JWT_VC_FORMAT,

  normalizeClaims(claimSet: CredentialClaimSet): readonly NormalizedCredentialClaim[] {
    const claims: unknown = claimSet?.claims;
    if (claims === null || typeof claims !== 'object') return [];

    const normalized: NormalizedCredentialClaim[] = [];

    for (const [claimName, attrKey] of Object.entries(SD_JWT_VC_ATTRIBUTE_CLAIMS)) {
      // `readBindingClaim` is reused rather than re-implemented: it already does
      // the `Object.hasOwn` read that keeps a `__proto__` claim name from
      // reaching the prototype (the defence #234's `defineClaim` sets up and a
      // careless consumer undoes), refuses non-finite numbers, and applies the
      // shared value-length bound.
      const value = readBindingClaim(claims as Readonly<Record<string, unknown>>, claimName);
      if (value === undefined) continue;

      const attrValue = attributeValue(attrKey, value);
      if (attrValue === undefined) continue;

      normalized.push(Object.freeze({ attrKey, attrValue }));
    }

    return Object.freeze(normalized);
  },
};
