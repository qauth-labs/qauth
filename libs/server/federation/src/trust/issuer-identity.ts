import { issuerTrustRejection } from './issuer-trust-rejection';

/**
 * The VALIDATED issuer identity the trust registry consumes (ADR-004/ADR-009,
 * issue #236).
 *
 * ## The thing this module exists to prevent
 *
 * A Verifiable Presentation carries an `iss` value that is, until proven
 * otherwise, attacker-controlled text. Trusting it is a complete authentication
 * bypass: anyone can mint a credential claiming `iss: "https://gov.example"`.
 * #236 therefore specifies that `isTrusted` consumes *"the **validated** issuer
 * identity produced by #234's presentation validation — never an unverified
 * `iss` string"*, and ADR-009 repeats the rule for account keying: the issuer
 * component of an issuer-scoped account key MUST come from the validated key
 * resolution, never from an unverified `iss`.
 *
 * A convention cannot enforce that. {@link ValidatedIssuer} does, twice over:
 *
 *  - **At compile time** — it is a `class` with a private constructor and a
 *    private brand field, so TypeScript treats it NOMINALLY. `isTrusted(iss)`
 *    where `iss` is a `string`, or an object literal with the right fields,
 *    does not compile. An `interface` would have been structurally satisfiable
 *    and would have bought nothing.
 *  - **At run time** — {@link ValidatedIssuer.isValidated} tests for the
 *    private field with `#brand in value`, which only the constructor can have
 *    set. That survives `as unknown as ValidatedIssuer`, a JSON round-trip, and
 *    `Object.create(ValidatedIssuer.prototype)` — none of which `instanceof`
 *    survives.
 *
 * ## Canonicalization lives here, and is applied to BOTH sides
 *
 * Membership in an allowlist is a string comparison, so the allowlist entry and
 * the validated identity must be reduced to the same form or trust silently
 * fails (or, worse, silently succeeds on a near-match). Both sides go through
 * {@link canonicalizeIssuerIdentifier}: config validates shape,
 * `server-federation` decides equality. `server-config` cannot import this — it
 * is the lowest layer and carries no dependency on `server-federation` — which
 * is exactly why the canonicalizer must not be duplicated over there.
 *
 * ## Scope: base profile, HTTPS issuer identities
 *
 * `oid4vp-1.0-base` with SD-JWT VC (`dc+sd-jwt`) identifies an issuer by HTTPS
 * URI. The HAIP path (#298-gated) resolves the issuer key from an `x5c` chain
 * instead; {@link IssuerKeyResolutionMethod} records WHICH resolution produced
 * this identity so a chain-validating backend can later demand `x5c` without
 * any change to callers. The static allowlist does not branch on it — base
 * OID4VP 1.0 does not mandate X.509 issuer key resolution.
 */

/**
 * How #234 resolved the issuer's signing key before asserting this identity.
 *
 * - `issuer-metadata` — key fetched from the issuer's published metadata at the
 *   HTTPS issuer identifier. The base-profile path.
 * - `x5c` — key taken from the certificate chain in the credential's `x5c` JOSE
 *   header, validated to a trust anchor (HAIP §6.1.1). Ships with the HAIP
 *   profile, after #298.
 *
 * Deliberately NOT imported from `profiles/verifier-profile.types.ts`. That
 * module describes the VERIFIER trust direction (how QAuth proves who it is);
 * sharing a type across the two directions is the first step toward sharing a
 * code path, which #236 and #299 both forbid.
 */
export type IssuerKeyResolutionMethod = 'x5c' | 'issuer-metadata';

/**
 * Longest issuer identifier accepted, in characters.
 *
 * Mirrors the cap `server-config`'s `trust-registry.ts` applies to allowlist
 * entries. The two are duplicated because config may not import this lib; they
 * must stay equal, and the direction that matters is that no identity longer
 * than a configurable entry can be constructed here.
 */
const MAX_ISSUER_IDENTIFIER_LENGTH = 2048;

/**
 * Reduce an issuer identifier to the single form trust comparisons are made in.
 *
 * Applied to allowlist entries at registry construction AND to the validated
 * identity at {@link ValidatedIssuer} construction, so both sides of every
 * membership test have been through the same reduction.
 *
 * Accepted: an absolute `https:` URL. The canonical form is
 * `https://host[:port]/path` with:
 *
 *  - the host lowercased and IDN-encoded to punycode (both by `URL`);
 *  - a default `:443` port removed (by `URL`);
 *  - trailing slashes stripped, so `https://a.example/` and `https://a.example`
 *    are the same issuer, and `https://a.example/t/` matches `https://a.example/t`.
 *
 * Rejected, each as a deliberate refusal rather than something to normalise
 * away:
 *
 *  - **non-HTTPS** — an issuer identity resolvable in the clear is not worth
 *    pinning trust to, and SD-JWT VC issuer identifiers are HTTPS URIs;
 *  - **userinfo** (`https://user:pw@host`) — credentials in an identifier are
 *    never meaningful and are a classic way to make two identifiers look alike;
 *  - **query and fragment** — not part of an issuer's identity; allowing them
 *    would let `https://a.example?x=1` and `https://a.example` be different
 *    entries for the same issuer, and would let an attacker vary an identifier
 *    that a naive comparison treats as distinct;
 *  - **anything with no host**, and anything over
 *    {@link MAX_ISSUER_IDENTIFIER_LENGTH}.
 *
 * Path case is preserved: HTTPS hosts are case-insensitive, paths are not.
 *
 * @param raw - candidate identifier; `unknown` because untrusted JSON and DB
 * columns both reach this function.
 * @returns the canonical identifier, or `undefined` when the input is not a
 * usable issuer identity. Never throws — callers decide what a rejection means.
 */
export function canonicalizeIssuerIdentifier(raw: unknown): string | undefined {
  if (typeof raw !== 'string') return undefined;

  const trimmed = raw.trim();
  if (trimmed.length === 0 || trimmed.length > MAX_ISSUER_IDENTIFIER_LENGTH) return undefined;

  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    return undefined;
  }

  if (url.protocol !== 'https:') return undefined;
  if (url.username !== '' || url.password !== '') return undefined;
  if (url.search !== '' || url.hash !== '') return undefined;
  if (url.hostname === '') return undefined;

  const path = url.pathname.replace(/\/+$/, '');

  return `https://${url.host}${path}`;
}

/**
 * What #234 must hand over to assert that it validated an issuer.
 *
 * A named input type rather than positional arguments so the call site reads as
 * a claim about what was verified, not as two strings in an order that could be
 * swapped.
 */
export interface IssuerValidationEvidence {
  /**
   * The issuer identifier that key resolution CONFIRMED — the `iss` whose
   * signature verified against the resolved key, or the identity carried by the
   * validated certificate chain. Never a raw `iss` read off an unverified
   * credential.
   */
  readonly identifier: string;
  /** Which resolution established the identifier above. */
  readonly keyResolution: IssuerKeyResolutionMethod;
}

/**
 * An issuer identity that presentation validation has actually established.
 *
 * Constructible only through {@link ValidatedIssuer.fromValidatedPresentation}
 * — see the module JSDoc for why the nominal typing is the point.
 */
export class ValidatedIssuer {
  /**
   * Private brand. Its VALUE is irrelevant; its presence is the proof, because
   * a private field can only be installed by this class's constructor. Read
   * only by {@link ValidatedIssuer.isValidated}.
   */
  readonly #validated = true;

  /** Canonical issuer identifier — see {@link canonicalizeIssuerIdentifier}. */
  readonly identifier: string;

  /** How the identity above was established. */
  readonly keyResolution: IssuerKeyResolutionMethod;

  private constructor(identifier: string, keyResolution: IssuerKeyResolutionMethod) {
    this.identifier = identifier;
    this.keyResolution = keyResolution;
    Object.freeze(this);
  }

  /**
   * Assert a validated issuer identity (#236).
   *
   * **Only presentation validation (#234) may call this**, and only AFTER it
   * has verified the credential signature against a resolved issuer key. There
   * is no way for this function to check that for itself — it is the seam where
   * the cryptographic guarantee is converted into a type — so calling it with
   * an unverified `iss` re-opens the exact bypass the type exists to close.
   *
   * Throws the shared non-enumerating rejection rather than a plain `Error`:
   * the identifier reaching here came off the wire, so a malformed one is a
   * rejected credential (401), not a server fault (500). Using the SAME error
   * as an untrusted-issuer refusal is required, not incidental — a distinct
   * "malformed identifier" error would let a caller tell a malformed credential
   * apart from a well-formed one whose issuer is not trusted.
   *
   * @param evidence - the confirmed identifier and how it was confirmed.
   * @returns the branded identity the trust registry accepts.
   * @throws InvalidCredentialsError when the identifier does not canonicalize,
   * or the key-resolution method is not one this lib knows.
   */
  static fromValidatedPresentation(evidence: IssuerValidationEvidence): ValidatedIssuer {
    const identifier = canonicalizeIssuerIdentifier(evidence?.identifier);
    if (identifier === undefined) throw issuerTrustRejection();

    // Re-checked at run time even though the type says it cannot happen:
    // #234 will build this from parsed JOSE headers, where `as` casts are
    // routine and the compiler's guarantee does not reach.
    const { keyResolution } = evidence;
    if (keyResolution !== 'x5c' && keyResolution !== 'issuer-metadata') {
      throw issuerTrustRejection();
    }

    return new ValidatedIssuer(identifier, keyResolution);
  }

  /**
   * Run-time proof that `value` came out of
   * {@link ValidatedIssuer.fromValidatedPresentation}.
   *
   * Uses the `#field in obj` brand check rather than `instanceof`: `instanceof`
   * only inspects the prototype chain, so `Object.create(ValidatedIssuer.prototype)`
   * — or any object a `JSON.parse` + cast produced — would pass it. A private
   * field cannot be forged from outside the class body.
   *
   * The trust registry and {@link import('./trust-registry').assertIssuerTrusted}
   * both call this, so a `as unknown as ValidatedIssuer` cast anywhere in the
   * codebase still fails closed at the trust boundary.
   *
   * @param value - anything.
   * @returns whether `value` is a genuine {@link ValidatedIssuer}.
   */
  static isValidated(value: unknown): value is ValidatedIssuer {
    return typeof value === 'object' && value !== null && #validated in value;
  }
}
