import { createHash, timingSafeEqual } from 'node:crypto';

import { normalizeEmail } from '@qauth-labs/shared-validation';

import type { ValidatedCredential } from '../oid4vp/validated-credential';
import { canonicalizeIssuerIdentifier, ValidatedIssuer } from '../trust/issuer-identity';

/**
 * Deriving the values subject resolution compares (issue #300, ADR-009).
 *
 * ## Two derived values, two jobs
 *
 * - A **wallet binding** ({@link deriveWalletBinding}) is the proof half of
 *   `asserted-lookup`: recorded when a wallet credential is enrolled against an
 *   account, re-derived on every later presentation, and compared. ADR-009 §1
 *   states the constraint it exists to satisfy, and states it as the likeliest
 *   way the feature gets built wrong:
 *
 *   > Validity is necessary but not sufficient. Verifying that a presentation is
 *   > well-formed and issuer-trusted proves only that the holder has *a* valid
 *   > credential. The strategy MUST additionally verify that the presented
 *   > credential matches the binding stored for the asserted account.
 *
 * - An **issuer-scoped subject** ({@link deriveIssuerScopedSubject}) is both
 *   halves at once for `issuer-scoped-claim`: the lookup key IS the proof,
 *   because it is derived from a claim a validated issuer signed.
 *
 * ## Why both are digests, and what a digest is not
 *
 * Both reduce to `sha256` over a canonical, self-describing encoding:
 *
 * - **Fixed length.** Every comparison is between two 64-hex-character strings,
 *   so {@link constantTimeEquals} never falls out early on a length mismatch
 *   and the stored value's length says nothing about the claims behind it.
 * - **No plaintext identity at rest.** The binding lands in
 *   `user_credentials.credential_data` and the issuer-scoped subject in
 *   `external_sub`. A national identification number or a birth date sitting in
 *   those columns in the clear is precisely what ADR-009 Finding 2 spends its
 *   length on; a digest keeps the matching property without keeping the value.
 * - **Unambiguous.** The encoding is JSON over an array with a version tag, so
 *   `['a','bc']` and `['ab','c']` cannot collide, and a future change of scheme
 *   is a new tag rather than a silent re-interpretation of stored values.
 *
 * A digest is NOT a secret and NOT a proof of possession. Its strength is
 * exactly the strength of the claim set behind it: an operator who binds on
 * `family_name` alone gets a binding that any credential asserting that surname
 * satisfies. What makes the scheme sound is the ISSUER — an attacker cannot mint
 * a credential asserting the victim's attributes without a trusted issuer having
 * issued it — which is why issuer trust (#236) is a precondition of resolution
 * rather than a parallel concern.
 *
 * ## Never key on a self-asserted issuer
 *
 * Both derivations re-check `ValidatedIssuer.isValidated` at run time even
 * though the type already says so. `ValidatedCredential.issuer` is nominally
 * typed, but `as unknown as ValidatedIssuer` exists and JSON round-trips
 * happen; ADR-009 §2 makes the rule absolute — *"the issuer component MUST come
 * from the validated issuer certificate chain … never from an unverified `iss`
 * value"* — so it is enforced where the composite key is built, not only where
 * the credential was made.
 *
 * @see docs/adr/009-wallet-account-resolution.md
 */

/**
 * Version tag prefixing every wallet binding.
 *
 * Present in the stored value so an operator reading `credential_data` can tell
 * what produced it, and so a future scheme is additive: a `wb2:` value never
 * compares equal to a `wb1:` one, which fails closed rather than silently
 * matching across schemes.
 */
export const WALLET_BINDING_PREFIX = 'wb1:';

/**
 * Version tag prefixing every issuer-scoped subject.
 *
 * Distinct from {@link WALLET_BINDING_PREFIX} on purpose: the two values are
 * derived from different inputs for different jobs, and a value that leaked from
 * one column into the other must not be usable in the other's comparison.
 */
export const ISSUER_SCOPED_SUBJECT_PREFIX = 'isc1:';

/**
 * Longest asserted identifier accepted.
 *
 * 320 = the RFC 5321 maximum email address length, and the same cap
 * `apps/auth-server`'s `ASSERTED_IDENTIFIER_MAX_LENGTH` applies to the
 * wallet-login form field (#239). Duplicated rather than shared because
 * `scope:app` may not export to `scope:server`; the direction that matters is
 * that nothing longer than the form accepts can be constructed here.
 */
export const MAX_ASSERTED_IDENTIFIER_LENGTH = 320;

/**
 * Most claims a wallet binding may be derived from.
 *
 * A bound rather than a policy: the claim list is operator configuration, and an
 * unbounded one turns every login into an unbounded number of claim reads. No
 * ecosystem needs sixteen attributes to identify a person.
 */
export const MAX_BINDING_CLAIMS = 16;

/**
 * Longest claim VALUE that may take part in a derivation.
 *
 * Claim values are issuer-signed but still arbitrary strings. The cap keeps a
 * pathological credential from turning binding derivation into the expensive
 * part of a login.
 */
export const MAX_BINDING_CLAIM_VALUE_LENGTH = 512;

/**
 * Claim names that may never be configured as binding or subject claims.
 *
 * `iss` and `cnf` are the two the whole design is built to keep out of an
 * account key: `iss` is the self-asserted issuer ADR-009 §2 forbids keying on,
 * and `cnf` is the holder key OID4VP 1.0 §15.5–§15.6 treat as a linkability
 * defect and ADR-009 §4 refuses as a subject. `_sd` and `_sd_alg` are
 * selective-disclosure control members, not assertions about the subject.
 *
 * Neither can actually reach {@link ValidatedCredential.claims} — #234 strips
 * all four — so this list is a CONFIGURATION guard, refusing the intent at boot
 * rather than letting it fail silently at run time as a claim that is never
 * present.
 */
export const FORBIDDEN_BINDING_CLAIMS: readonly string[] = Object.freeze([
  '_sd',
  '_sd_alg',
  'cnf',
  'iss',
]);

/**
 * A claim value that may take part in a derivation.
 *
 * Primitives only. A structured claim has no canonical string form this module
 * can commit to — `JSON.stringify` of an object is key-order dependent, so two
 * semantically identical credentials could derive two different bindings and a
 * returning user would be refused. Refusing is the honest answer; silently
 * picking an ordering is not.
 */
export type BindingClaimValue = string | number | boolean;

/**
 * Compare two strings without an early-exit branch on content.
 *
 * The same helper `sd-jwt-vc.ts` keeps private for `nonce`/`aud`, deliberately
 * re-stated here rather than exported from there: widening that module's surface
 * to share five lines would make a validator's internals part of the package
 * API. A stored binding is not a high-value secret, but it is the value an
 * attacker probes when trying to find a credential that matches an account —
 * and a codebase that compares one authentication input in constant time and the
 * next with `===` teaches the wrong habit at exactly the wrong boundary.
 *
 * Length is compared first because `timingSafeEqual` throws on a length
 * mismatch; both operands are fixed-length digests, so length is never the
 * secret.
 *
 * @param left - one value.
 * @param right - the other.
 * @returns whether the two are byte-identical.
 */
export function constantTimeEquals(left: string, right: string): boolean {
  const a = Buffer.from(left, 'utf8');
  const b = Buffer.from(right, 'utf8');
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/**
 * Normalize an asserted identifier to the single form account lookups use.
 *
 * ADR-009 §1 puts the asserted identifier in `user_credentials.external_sub` —
 * *"the same column `PasswordProvider` fills"* — so it MUST be normalized the
 * same way, or the two providers disagree about what "the same account" means
 * and a wallet login silently enrols a duplicate. Hence `normalizeEmail`,
 * exactly as `password.provider.ts` and the #239 login form use it.
 *
 * @param raw - the identifier as typed; `unknown` because it arrives as form
 * input and, later, from a session store.
 * @returns the normalized identifier, or `undefined` when it is not usable at
 * all. Never throws — callers decide what a rejection means.
 */
export function normalizeAssertedIdentifier(raw: unknown): string | undefined {
  if (typeof raw !== 'string') return undefined;
  if (raw.length > MAX_ASSERTED_IDENTIFIER_LENGTH) return undefined;

  const normalized = normalizeEmail(raw);

  return normalized.length === 0 ? undefined : normalized;
}

/**
 * Read one claim, refusing anything that cannot take part in a derivation.
 *
 * `Object.hasOwn` rather than `name in claims` or a bare property read: the
 * claims object is built with `Object.defineProperty` by #234 precisely so a
 * `__proto__` claim name cannot reach the prototype, and reading it back has to
 * be equally careful or the defence is undone at the consumer.
 *
 * @param claims - {@link ValidatedCredential.claims}.
 * @param name - the configured claim name.
 * @returns the primitive value, or `undefined` when the claim is absent, is not
 * a primitive, is an empty string, or is over
 * {@link MAX_BINDING_CLAIM_VALUE_LENGTH}.
 */
export function readBindingClaim(
  claims: Readonly<Record<string, unknown>>,
  name: string
): BindingClaimValue | undefined {
  if (claims === null || typeof claims !== 'object') return undefined;
  if (!Object.hasOwn(claims, name)) return undefined;

  const value = claims[name];

  if (typeof value === 'string') {
    if (value.length === 0 || value.length > MAX_BINDING_CLAIM_VALUE_LENGTH) return undefined;
    return value;
  }

  // `Number.isFinite` excludes NaN and both infinities: neither round-trips
  // through JSON as itself (`JSON.stringify(NaN)` is `null`), so a binding
  // derived from one would collide with a binding derived from a null claim.
  if (typeof value === 'number') return Number.isFinite(value) ? value : undefined;
  if (typeof value === 'boolean') return value;

  return undefined;
}

/** `sha256` over a canonical encoding, hex. */
function digest(parts: readonly unknown[]): string {
  return createHash('sha256').update(JSON.stringify(parts), 'utf8').digest('hex');
}

/**
 * The validated issuer identifier, or `undefined` if the credential does not
 * actually carry one.
 *
 * The run-time half of ADR-009 §2's rule. See the module JSDoc.
 */
function validatedIssuerIdentifier(credential: ValidatedCredential): string | undefined {
  const issuer: unknown = credential?.issuer;
  if (!ValidatedIssuer.isValidated(issuer)) return undefined;

  // Canonicalized a second time. `ValidatedIssuer` already canonicalizes at
  // construction, so this is belt-and-braces against a hand-built instance in a
  // future test double — and it costs one URL parse per login.
  return canonicalizeIssuerIdentifier(issuer.identifier);
}

/**
 * Derive the wallet binding for a presentation (ADR-009 §1's proof half).
 *
 * Composite: the **validated** issuer identity, the credential type, and the
 * configured claims with their values. All three matter —
 *
 * - dropping the issuer would let a credential from any other trusted issuer
 *   satisfy a binding established by one of them;
 * - dropping the `vct` would let a different credential type from the same
 *   issuer satisfy it;
 * - the claims are what make it about a PERSON rather than about a credential
 *   type.
 *
 * Claim names are sorted and de-duplicated by the caller
 * (`normalizeBindingClaims`), so reordering the operator's configuration does
 * not invalidate every stored binding in the deployment.
 *
 * Fails closed on any missing or unusable claim: a holder who withholds a
 * binding claim has not proven entitlement to anything, and deriving a binding
 * from the subset they did disclose would let selective disclosure WEAKEN the
 * check the more it is exercised.
 *
 * @param credential - the validated presentation.
 * @param claimNames - normalized configured claim names, non-empty.
 * @returns the binding, or `undefined` when it cannot be derived.
 */
export function deriveWalletBinding(
  credential: ValidatedCredential,
  claimNames: readonly string[]
): string | undefined {
  if (claimNames.length === 0) return undefined;

  const issuer = validatedIssuerIdentifier(credential);
  if (issuer === undefined) return undefined;

  const credentialType = credential.credentialType;
  if (typeof credentialType !== 'string' || credentialType.length === 0) return undefined;

  const claims: (readonly [string, BindingClaimValue])[] = [];
  for (const name of claimNames) {
    const value = readBindingClaim(credential.claims, name);
    if (value === undefined) return undefined;
    claims.push([name, value]);
  }

  return `${WALLET_BINDING_PREFIX}${digest(['qauth.wallet-binding.v1', issuer, credentialType, claims])}`;
}

/**
 * Derive the issuer-scoped subject for a presentation (ADR-009 §2).
 *
 * Keyed on `(validated issuer, claim name, claim value)` — **never the claim
 * value alone**. Two Member States issuing the same
 * `personal_administrative_number` to two different people is not hypothetical:
 * CIR (EU) 2024/2977 scopes that attribute's uniqueness to *"the provider of
 * person identification data"*, so the issuer is part of the identifier rather
 * than context around it.
 *
 * @param credential - the validated presentation.
 * @param claimName - the configured issuer-scoped claim.
 * @returns the subject value for `user_credentials.external_sub`, or
 * `undefined` when the issuer is not validated or the claim was withheld — in
 * which case ADR-009 §2 requires falling back to `asserted-lookup`, never
 * failing the login outright.
 */
export function deriveIssuerScopedSubject(
  credential: ValidatedCredential,
  claimName: string
): string | undefined {
  const issuer = validatedIssuerIdentifier(credential);
  if (issuer === undefined) return undefined;

  const value = readBindingClaim(credential.claims, claimName);
  if (value === undefined) return undefined;

  return `${ISSUER_SCOPED_SUBJECT_PREFIX}${digest(['qauth.issuer-scoped-subject.v1', issuer, claimName, value])}`;
}
