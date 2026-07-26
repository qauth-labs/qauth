import { InvalidConfigurationError } from '@qauth-labs/shared-errors';

import { summarizeConfiguredValue } from './configured-value';
import { canonicalizeIssuerIdentifier, ValidatedIssuer } from './issuer-identity';
import { issuerTrustRejection } from './issuer-trust-rejection';

/**
 * The issuer trust seam and its first backend (ADR-004, issue #236).
 *
 * ## What this decides
 *
 * Given an issuer identity #234 has already validated cryptographically, is
 * that issuer trusted by this realm? A validly-signed credential from an
 * UNTRUSTED issuer is not an authenticated user, so this is the gate #234 must
 * pass before it may emit a `VerifiedIdentity`.
 *
 * It is emphatically NOT the verifier direction. `profiles/verifier-identity.ts`
 * (#299) decides how QAuth proves that it is the Verifier. The two share no
 * configuration and no code path.
 *
 * ## Why a seam, with a static allowlist behind it
 *
 * ADR-004's 2026-07-20 refresh flags OpenID Federation 1.0/1.1 as the
 * standardised, registry-free answer to wallet–issuer trust, and an EUDI
 * list-of-trusted-lists as another candidate — both deserving their own ADR
 * rather than being folded in here. HAIP §6.1.1 specifies a third: X.509 `x5c`
 * chain validation to an operator-supplied trust anchor, which ships after
 * #298. {@link TrustRegistry} is the one call site all of them replace, so
 * swapping a backend never touches `WalletProvider` or the OID4VP endpoint.
 *
 * The static per-realm allowlist is the first backend precisely because base
 * OID4VP 1.0 does not mandate X.509 issuer key resolution: it is a membership
 * check over a validated identity, and it runs on today's crypto.
 *
 * ## Fail-closed, everywhere
 *
 * There is no permissive default anywhere in this module. No allowlist means an
 * empty allowlist, an empty allowlist trusts nobody, and an unvalidated issuer
 * is refused even if its identifier happens to appear in the list. HAIP §3.4
 * puts the establishment of trust anchors out of scope — the operator supplies
 * them — so "nothing configured" can only mean "trust nothing".
 */

/**
 * The single issuer-trust decision point (#236).
 *
 * A registry is **realm-scoped**: it is obtained for one realm (see
 * `resolveTrustRegistry`) and then asked only about issuers. That is why
 * `isTrusted` takes no realm — a realm argument would make it possible to hold
 * one realm's registry and ask it about another realm's trust, which is exactly
 * the cross-tenant leak a per-realm allowlist exists to prevent.
 *
 * ## Contract for backends
 *
 * - **Pure membership, no side effects.** Called on the request path.
 * - **Must return `false`, never throw,** for an issuer it does not trust.
 *   Distinguishing rejection reasons is the caller's business, and per #236
 *   there is only one reason on the wire anyway
 *   (`issuer-trust-rejection.ts`). A backend that breaks this rule is
 *   CONTAINED by {@link assertIssuerTrusted} rather than trusted to keep it —
 *   a thrown exception becomes the same refusal, reported server-side — but
 *   containment is a backstop, not a licence to signal by throwing.
 * - **Must re-check {@link ValidatedIssuer.isValidated}.** A backend is a trust
 *   boundary in its own right and cannot assume the compiler's nominal typing
 *   survived every cast on the way in.
 *
 * ## Why synchronous
 *
 * `isTrusted(issuer): boolean` is the shape #236 specifies, and it fits every
 * backend on the near roadmap: an allowlist is a set lookup and HAIP §6.1.1
 * chain validation is local certificate arithmetic against operator-supplied
 * anchors. A network-backed backend (OpenID Federation) needs either a
 * cache-warmed synchronous view or a revision of this signature — a decision
 * that belongs to that backend's own ADR, not to a speculative `Promise` every
 * caller would have to await today.
 */
export interface TrustRegistry {
  /**
   * @param issuer - the identity produced by #234's presentation validation.
   * @returns `true` only if this realm trusts that issuer.
   */
  isTrusted(issuer: ValidatedIssuer): boolean;
}

/**
 * A registry that trusts nobody.
 *
 * The value every unconfigured or unparseable path resolves to, so "we could
 * not work out what this realm trusts" and "this realm trusts nothing" are the
 * same object rather than two branches one of which might be forgotten.
 */
export const DENY_ALL_TRUST_REGISTRY: TrustRegistry = Object.freeze({
  isTrusted: (): boolean => false,
});

/**
 * Build the static per-realm issuer allowlist backend (#236).
 *
 * ## Matching
 *
 * Entries are canonicalized with {@link canonicalizeIssuerIdentifier} — the
 * same reduction {@link ValidatedIssuer} applies to the identity being tested —
 * and stored in a `Set`. A `Set` rather than an array scan: lookup cost does
 * not depend on an issuer's POSITION in the list, so the check cannot be turned
 * into a "how far down the list is this issuer" oracle. Issuer identifiers are
 * public values, not secrets, so a constant-time comparison is not required
 * here the way it is for tokens and password hashes; not leaking list ORDER is.
 *
 * ## Throwing on a bad entry
 *
 * A malformed entry is an OPERATOR error and this throws loudly. Silently
 * dropping it would leave the operator believing an issuer is trusted when it
 * is not, and silently returning a deny-all registry would be indistinguishable
 * from a correctly-empty configuration.
 *
 * It throws {@link InvalidConfigurationError} — a domain error — rather than a
 * plain `Error`, and the offending entry goes on that error's `details`, never
 * into its message. This function is part of the package's public surface, so
 * it can be reached from a request path by a future caller; a plain `Error`
 * there escapes as a non-domain fault and its message — which used to quote the
 * entry — lands in a 500 body in development and in every log line regardless.
 * Structured details keep the value where an operator can read it and a client
 * cannot.
 *
 * That still makes this function unsafe to call with untrusted input, which is
 * deliberate: `resolveTrustRegistry` validates DB-sourced lists before calling
 * it, so a corrupt row fails closed instead of turning a request into a 500,
 * and `assertTrustedIssuersUsable` runs the same reduction over
 * `OID4VP_TRUSTED_ISSUERS` at boot so config-sourced lists cannot reach here
 * malformed either.
 *
 * @param entries - issuer identifiers this realm trusts; may be empty, which
 * yields a registry that trusts nobody.
 * @returns a frozen realm-scoped registry.
 * @throws InvalidConfigurationError when an entry is not a canonicalizable
 * HTTPS issuer identifier. The entry is on `details`, not in the message.
 */
export function createStaticIssuerAllowlist(entries: readonly string[]): TrustRegistry {
  if (!Array.isArray(entries)) {
    throw new InvalidConfigurationError(
      'Trusted-issuer allowlist must be an array of https:// issuer identifiers (#236).'
    );
  }

  const allowed = new Set<string>();
  for (const [index, entry] of entries.entries()) {
    const canonical = canonicalizeIssuerIdentifier(entry);
    if (canonical === undefined) {
      throw new InvalidConfigurationError(
        'A trusted-issuer allowlist entry is not a usable issuer identity (#236). Entries must be absolute https:// URLs with no userinfo, query string or fragment. See this error\'s "details" for the position and the value.',
        { index, entry: summarizeConfiguredValue(entry) }
      );
    }
    allowed.add(canonical);
  }

  return Object.freeze({
    isTrusted(issuer: ValidatedIssuer): boolean {
      // Re-checked here, not only in `assertIssuerTrusted`: a backend is a
      // trust boundary and must not inherit the caller's assumptions.
      if (!ValidatedIssuer.isValidated(issuer)) return false;
      return allowed.has(issuer.identifier);
    },
  });
}

/**
 * Optional wiring for {@link assertIssuerTrusted}.
 */
export interface IssuerTrustGateOptions {
  /**
   * Called when the {@link TrustRegistry} backend THREW instead of answering.
   *
   * Wire it to the request logger (`request.log.error`). The gate's refusal is
   * deliberately silent on the wire — every rejection looks identical, which is
   * the non-enumeration property — so a backend that is broken rather than
   * merely unconvinced would otherwise be invisible: the deployment would
   * refuse every presentation and log nothing about why.
   *
   * Defaults to `console.error`, so a caller that forgets to pass one still
   * gets a loud signal. Fail LOUD is the counterpart of fail closed here; a
   * silent default would make the omission cost-free.
   */
  readonly onBackendError?: (error: unknown) => void;
}

/**
 * Where a backend failure goes when the caller wired no reporter.
 *
 * `console.error` rather than nothing: this lib has no logger dependency (it is
 * a pure `scope:server` library and must stay bootable without Fastify), and a
 * no-op default would let the one failure mode that is invisible on the wire be
 * invisible server-side too.
 */
const DEFAULT_BACKEND_ERROR_REPORTER = (error: unknown): void => {
  console.error('[issuer-trust] TrustRegistry backend threw; refusing the presentation', error);
};

/** Report a backend failure without ever letting the reporter become the fault. */
function reportBackendError(error: unknown, report: (error: unknown) => void): void {
  try {
    report(error);
  } catch {
    // A logger that throws must not convert a contained 401 into an
    // uncontained 500 — the thing that reports a failure may not become one.
  }
}

/**
 * The mandatory issuer trust gate (#236).
 *
 * The function #234 calls once per presentation, after validating it and before
 * building a `VerifiedIdentity`. It throws rather than returning a boolean so a
 * caller cannot proceed by ignoring the result — an untrusted issuer must make
 * the flow unreachable, not merely unrecommended.
 *
 * Every refusal is the SAME error (`issuer-trust-rejection.ts`): missing
 * registry, untrusted issuer, forged identity, and a backend that THREW are
 * indistinguishable to the caller, which is what makes the rejection
 * non-enumerating.
 *
 * ## A backend that throws is contained, not propagated
 *
 * {@link TrustRegistry} backends are pluggable and the contract says they must
 * not throw, but a contract is not an enforcement: the HAIP §6.1.1 chain
 * validator parses certificates, and a future federation backend does I/O. If
 * such a backend threw, the exception escaped this gate as a non-domain error —
 * which breaks the single-refusal-shape guarantee twice over. On a route it
 * becomes a 500 instead of a 401, so an attacker can tell "backend blew up on
 * this credential" from "issuer not trusted"; and it is not an
 * `InvalidCredentialsError`, so a caller branching on the domain error would
 * treat a refusal as an infrastructure fault and might retry past it.
 *
 * Containing it is fail-closed: a backend that cannot answer has not
 * established trust, so the answer is the same refusal as "no". The failure is
 * reported through {@link IssuerTrustGateOptions.onBackendError} so it is loud
 * server-side while staying silent on the wire.
 *
 * `registry` accepts `null`/`undefined` on purpose. A caller that could not
 * resolve a registry — no realm, no profile selected, a lookup that failed —
 * must land on a refusal, not on a `TypeError` it might catch and treat as
 * something else.
 *
 * @param registry - the realm's registry, or nothing at all.
 * @param issuer - the validated issuer identity.
 * @param options - optional backend-failure reporting; see
 * {@link IssuerTrustGateOptions}.
 * @throws InvalidCredentialsError whenever trust is not positively established.
 */
export function assertIssuerTrusted(
  registry: TrustRegistry | null | undefined,
  issuer: ValidatedIssuer,
  options?: IssuerTrustGateOptions
): void {
  if (!ValidatedIssuer.isValidated(issuer)) throw issuerTrustRejection();
  if (registry === null || registry === undefined) throw issuerTrustRejection();

  let trusted: unknown;
  try {
    trusted = registry.isTrusted(issuer);
  } catch (error) {
    reportBackendError(error, options?.onBackendError ?? DEFAULT_BACKEND_ERROR_REPORTER);
    throw issuerTrustRejection();
  }

  // `!== true` rather than `!`: a third-party backend returning a truthy
  // non-boolean must not be read as a grant.
  if (trusted !== true) throw issuerTrustRejection();
}
