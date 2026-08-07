import { InvalidConfigurationError } from '@qauth-labs/shared-errors';

import { summarizeConfiguredValue } from '../trust/configured-value';
import { canonicalizeIssuerIdentifier } from '../trust/issuer-identity';
import { FORBIDDEN_BINDING_CLAIMS, MAX_BINDING_CLAIMS } from './subject-binding';

/**
 * Operator configuration for the subject-resolution strategies (issue #300).
 *
 * Validated ONCE, loudly, at the point a strategy is constructed — never
 * per-request. A malformed strategy configuration is an operator error and the
 * deployment must not start with it, for the same reason
 * `createStaticIssuerAllowlist` refuses a malformed allowlist entry: silently
 * dropping a binding claim would leave the operator believing entitlement is
 * checked when it is not, and that is ADR-009 §1's total-authentication-bypass
 * failure mode arrived at through configuration instead of code.
 *
 * Every refusal is an {@link InvalidConfigurationError} carrying the offending
 * value on `details`, never in the message — these functions are on the
 * package's public surface, so a future caller could reach one from a request
 * path where a message lands in a 500 body and in every log line.
 */

/**
 * The `asserted-lookup` configuration (ADR-009 §1).
 *
 * One field, and it is REQUIRED. There is no "check the binding if one is
 * configured" mode: a deployment with no binding claims cannot verify
 * entitlement, and `asserted-lookup` without the entitlement check is the
 * bypass, not a degraded version of the strategy.
 */
export interface AssertedLookupConfig {
  /**
   * The credential claims a wallet binding is derived from.
   *
   * Ecosystem-specific and therefore operator-supplied: an EUDI PID deployment
   * binds on the mandatory attribute set (`family_name`, `given_name`,
   * `birth_date`), a workforce deployment on an employee number. No default is
   * offered, because a wrong default here is a weak binding nobody notices.
   */
  readonly bindingClaims: readonly string[];
}

/**
 * The `issuer-scoped-claim` configuration (ADR-009 §2).
 *
 * Opt-in per NAMED issuer, and the fallback is structural rather than optional:
 * ADR-009 §2 requires *"always with fallback to `asserted-lookup` when the claim
 * is withheld, since the holder may refuse it"*, so the fallback is a required
 * field and a deployment cannot express "issuer-scoped-claim, no fallback".
 */
export interface IssuerScopedClaimConfig {
  /**
   * The claim carrying the issuer's stable subject identifier — an employee
   * number, or a national scheme's `personal_administrative_number` where its
   * value policy has been published.
   */
  readonly subjectClaim: string;
  /**
   * Issuer identifiers this strategy is opted into, canonicalized.
   *
   * Non-empty. ADR-009 §2 permits the strategy only *"where a specific, named
   * issuer contractually guarantees a stable, disclosed claim"* — a guarantee
   * QAuth cannot verify in code, so the operator names the issuers it holds that
   * guarantee from, and every other trusted issuer takes the fallback path.
   */
  readonly issuers: readonly string[];
  /** Where a presentation goes when the claim or the issuer does not qualify. */
  readonly fallback: AssertedLookupConfig;
}

/** Longest issuer-scoped subject claim NAME accepted. */
const MAX_CLAIM_NAME_LENGTH = 256;

/** Most named issuers `issuer-scoped-claim` may be opted into. */
const MAX_ISSUER_SCOPED_ISSUERS = 64;

/**
 * Validate and canonicalize a configured claim name.
 *
 * @param name - the operator-supplied claim name.
 * @param field - the configuration field, for the error's `details`.
 * @returns the claim name, unchanged — claim names are case-sensitive and are
 * NOT normalized, because `given_name` and `Given_Name` are different claims.
 * @throws InvalidConfigurationError when it is empty, over-long, carries
 * whitespace, or is one of {@link FORBIDDEN_BINDING_CLAIMS}.
 */
export function normalizeClaimName(name: unknown, field: string): string {
  if (typeof name !== 'string' || name.length === 0 || name.length > MAX_CLAIM_NAME_LENGTH) {
    throw new InvalidConfigurationError(
      `${field} must be a non-empty claim name (#300). See this error's "details" for the value.`,
      { field, value: summarizeConfiguredValue(name) }
    );
  }

  if (/\s/.test(name)) {
    throw new InvalidConfigurationError(
      `${field} must not contain whitespace (#300). See this error's "details" for the value.`,
      { field, value: summarizeConfiguredValue(name) }
    );
  }

  if (FORBIDDEN_BINDING_CLAIMS.includes(name)) {
    throw new InvalidConfigurationError(
      `${field} may not be '${name}'. ADR-009 §2 forbids keying an account on a self-asserted issuer, and OID4VP 1.0 §15.5–§15.6 forbid keying it on holder key material; presentation validation strips all of ${FORBIDDEN_BINDING_CLAIMS.join(', ')} from the claim set, so configuring one would silently never match (#300).`,
      { field, value: name }
    );
  }

  return name;
}

/**
 * Validate the binding claim list and reduce it to its canonical form.
 *
 * De-duplicated and SORTED, so the derived binding does not depend on the order
 * the operator happened to write the list in. Without that, reordering
 * `OID4VP_SUBJECT_BINDING_CLAIMS` would invalidate every stored binding in the
 * deployment and lock every wallet user out — a config edit with no visible
 * relationship to its effect.
 *
 * @param claims - the operator-supplied claim names.
 * @param field - the configuration field, for error `details`.
 * @returns a frozen, sorted, de-duplicated list.
 * @throws InvalidConfigurationError when the list is not an array, is empty, is
 * longer than {@link MAX_BINDING_CLAIMS}, or contains an unusable name.
 */
export function normalizeBindingClaims(
  claims: unknown,
  field = 'bindingClaims'
): readonly string[] {
  if (!Array.isArray(claims) || claims.length === 0) {
    throw new InvalidConfigurationError(
      `${field} must list at least one credential claim. 'asserted-lookup' verifies that the presented credential matches the binding stored for the asserted account (ADR-009 §1); with no binding claims there is nothing to match, and any valid credential would authenticate any account (#300).`,
      { field }
    );
  }

  if (claims.length > MAX_BINDING_CLAIMS) {
    throw new InvalidConfigurationError(
      `${field} may name at most ${MAX_BINDING_CLAIMS} claims (#300).`,
      { field, count: claims.length }
    );
  }

  const normalized = new Set<string>();
  for (const claim of claims) normalized.add(normalizeClaimName(claim, field));

  return Object.freeze([...normalized].sort());
}

/**
 * Validate the `issuer-scoped-claim` issuer opt-in list.
 *
 * Canonicalized with {@link canonicalizeIssuerIdentifier} — the same reduction
 * `ValidatedIssuer` applies to the identity being matched, so both sides of
 * every membership test have been through it. An entry that does not
 * canonicalize is an operator error and throws, exactly as a malformed
 * trusted-issuer allowlist entry does: silently dropping it would leave the
 * operator believing an issuer is opted in when every one of its presentations
 * quietly takes the fallback path instead.
 *
 * @param issuers - operator-supplied issuer identifiers.
 * @param field - the configuration field, for error `details`.
 * @returns a frozen, de-duplicated, canonicalized list.
 * @throws InvalidConfigurationError when the list is not a non-empty array of
 * canonicalizable HTTPS issuer identifiers.
 */
export function normalizeIssuerScopedIssuers(
  issuers: unknown,
  field = 'issuers'
): readonly string[] {
  if (!Array.isArray(issuers) || issuers.length === 0) {
    throw new InvalidConfigurationError(
      `${field} must name at least one issuer. ADR-009 §2 permits 'issuer-scoped-claim' only for a specific, named issuer that contractually guarantees a stable, disclosed claim — a guarantee QAuth cannot verify in code (#300).`,
      { field }
    );
  }

  if (issuers.length > MAX_ISSUER_SCOPED_ISSUERS) {
    throw new InvalidConfigurationError(
      `${field} may name at most ${MAX_ISSUER_SCOPED_ISSUERS} issuers (#300).`,
      { field, count: issuers.length }
    );
  }

  const canonical = new Set<string>();
  for (const [index, entry] of issuers.entries()) {
    const identifier = canonicalizeIssuerIdentifier(entry);
    if (identifier === undefined) {
      throw new InvalidConfigurationError(
        `An ${field} entry is not a usable issuer identity (#300). Entries must be absolute https:// URLs with no userinfo, query string or fragment. See this error's "details" for the position and the value.`,
        { field, index, entry: summarizeConfiguredValue(entry) }
      );
    }
    canonical.add(identifier);
  }

  return Object.freeze([...canonical]);
}
