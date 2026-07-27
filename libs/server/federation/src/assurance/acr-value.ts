import type { AssuranceLevel } from '../providers/credential-provider.interface';

/**
 * The eIDAS LoA → OIDC `acr` VALUE mapping (ADR-004, ADR-010, issue #237).
 *
 * ## What the research settled, and what it did not
 *
 * #237 required the mapping to be researched rather than named. The finding
 * (recorded in full in [ADR-010](../../../../../docs/adr/010-acr-assurance-mapping.md)):
 * **there is no registered `acr` value for an eIDAS Level of Assurance.** No
 * IANA registry entry and no OIDF-registered URI could be confirmed; RFC 6711 —
 * the "OpenID Connect Authentication Context Class Reference" registry — carries
 * no eIDAS entry. Two conventions exist in the wild and neither is normative:
 *
 *  - the eIDAS SAML-era URIs `http://eidas.europa.eu/LoA/{substantial,high}`,
 *    which national eID nodes have used since the eIDAS SAML attribute profile;
 *  - the bare strings `substantial` / `high`, common in national eID→OIDC
 *    bridges.
 *
 * So the emitted value is a DEPLOYMENT choice, expressed by
 * {@link AcrValueStyle}, and QAuth ships the URI form as the default because
 * OIDC Core §2 says an `acr` value "SHOULD" be an absolute URI or an RFC 6711
 * registered name — a bare `high` is neither.
 *
 * ## Why the eIDAS URIs are `http:` and that is not a mistake
 *
 * `http://eidas.europa.eu/LoA/high` is an IDENTIFIER, not a location: nothing
 * dereferences it, and rewriting it to `https:` would produce a different string
 * that no eIDAS-aware Relying Party recognises. It is quoted verbatim, exactly
 * as the eIDAS SAML profile defines it. (Contrast `canonicalizeIssuerIdentifier`,
 * which refuses `http:` — an issuer identity IS resolved, so the scheme is
 * load-bearing there and inert here.)
 *
 * ## `low` has no `acr` value, and that is the invariant
 *
 * {@link resolveAcrValue} returns `undefined` for `'low'`, so a password login
 * emits NO `acr` claim (ADR-003, ADR-004, #240). OIDC Core treats `acr` as an
 * optional higher-assurance indicator: emitting `.../LoA/low` for every password
 * login would assert an eIDAS level QAuth never established, and a Relying Party
 * gating on "is `acr` present" would then see every session as assured.
 *
 * ## Not `verified_claims`
 *
 * Claim PROVENANCE (which trust framework vouched for which attribute) belongs
 * in OIDC Identity Assurance `verified_claims`, not in `acr`. `acr` describes the
 * authentication EVENT. This module maps only the event's assurance level; it
 * deliberately says nothing about individual claims.
 */

/**
 * Which vocabulary a deployment emits its `acr` values in.
 *
 * - `eidas-uri` — `http://eidas.europa.eu/LoA/substantial` / `.../high`. The
 *   default: an absolute URI, as OIDC Core §2 asks for, and the form eIDAS
 *   ecosystems already read.
 * - `loa-name` — bare `substantial` / `high`. For deployments whose Relying
 *   Parties already consume the short names used by national eID→OIDC bridges.
 *
 * There is no `custom` member. An arbitrary operator-supplied string would let a
 * deployment emit a value that COLLIDES with a registered `acr` name while
 * meaning something else, which OIDC Core §2 forbids ("registered names MUST NOT
 * be used with a different meaning than that which is registered"). A closed set
 * of two documented vocabularies keeps the emitted value reviewable.
 */
export type AcrValueStyle = 'eidas-uri' | 'loa-name';

/**
 * Every vocabulary a deployment may select.
 *
 * Exported so `apps/auth-server` can pin `ACR_VALUE_STYLE`'s duplicated enum
 * against this list — `server-config` may not import this lib, and a duplicated
 * list drifts. Mirrors `VERIFIER_PROFILE_IDS` and the pin #299 established.
 */
export const ACR_VALUE_STYLES: readonly AcrValueStyle[] = Object.freeze(['eidas-uri', 'loa-name']);

/**
 * Assurance levels that HAVE an `acr` value. `'low'` is excluded by
 * construction, not by a runtime branch someone can forget.
 */
export type AcrBearingAssuranceLevel = Exclude<AssuranceLevel, 'low'>;

/**
 * eIDAS SAML-era LoA URIs, verbatim. See the module JSDoc for why `http:`.
 */
export const EIDAS_LOA_ACR_VALUES: Readonly<Record<AcrBearingAssuranceLevel, string>> =
  Object.freeze({
    substantial: 'http://eidas.europa.eu/LoA/substantial',
    high: 'http://eidas.europa.eu/LoA/high',
  });

/** Bare eIDAS LoA names, as used by several national eID→OIDC bridges. */
export const LOA_NAME_ACR_VALUES: Readonly<Record<AcrBearingAssuranceLevel, string>> =
  Object.freeze({
    substantial: 'substantial',
    high: 'high',
  });

/**
 * The style a deployment gets when it expresses no preference.
 *
 * `eidas-uri`, because OIDC Core §2 asks for an absolute URI and because a URI
 * cannot be mistaken for an RFC 6711 registered name that means something else.
 */
export const DEFAULT_ACR_VALUE_STYLE: AcrValueStyle = 'eidas-uri';

/** All value tables, keyed by style, so a new style cannot be half-added. */
const ACR_VALUE_TABLES: Readonly<
  Record<AcrValueStyle, Readonly<Record<AcrBearingAssuranceLevel, string>>>
> = Object.freeze({
  'eidas-uri': EIDAS_LOA_ACR_VALUES,
  'loa-name': LOA_NAME_ACR_VALUES,
});

/**
 * Parse an operator-supplied style, fail-closed.
 *
 * Returns `undefined` for anything unrecognised rather than falling back to the
 * default: a caller that wants the default asks for it explicitly, so a typo in
 * configuration surfaces as "not configured" at the boundary that validates
 * configuration, instead of silently selecting a vocabulary nobody chose.
 *
 * @param value - candidate style; `unknown` because env and DB both reach here.
 * @returns the style, or `undefined` when the value is not one QAuth emits.
 */
export function parseAcrValueStyle(value: unknown): AcrValueStyle | undefined {
  if (value !== 'eidas-uri' && value !== 'loa-name') return undefined;
  return value;
}

/**
 * Map an assurance level to the `acr` claim value to emit, if any.
 *
 * The ONE function that decides whether an ID token carries `acr`. Every caller
 * omits the claim entirely when this returns `undefined` — there is no "empty
 * `acr`" and no placeholder.
 *
 * @param level - the assurance level established for the authentication event;
 * `null`/`undefined` mean none was established.
 * @param style - the deployment's vocabulary; defaults to
 * {@link DEFAULT_ACR_VALUE_STYLE}. An unrecognised value falls back to the
 * default rather than throwing — this runs on the token path, and a bad style
 * must not turn an otherwise valid issuance into a 500.
 * @returns the `acr` value, or `undefined` when no `acr` claim may be emitted.
 */
export function resolveAcrValue(
  level: AssuranceLevel | null | undefined,
  style?: AcrValueStyle
): string | undefined {
  // `'low'`, `null`, `undefined` and anything a cast smuggled in all land here.
  // Written as an ALLOWLIST of the two levels that bear a value, so a widened
  // `AssuranceLevel` union cannot start emitting a claim by default.
  if (level !== 'substantial' && level !== 'high') return undefined;
  const table = ACR_VALUE_TABLES[parseAcrValueStyle(style) ?? DEFAULT_ACR_VALUE_STYLE];
  return table[level];
}

/**
 * Every `acr` value this deployment can emit, in ascending assurance order.
 *
 * For OIDC discovery (`acr_values_supported`) and for operator documentation.
 * Note it lists what QAuth CAN emit under the given style, not what any
 * particular realm is configured to reach — the latter depends on the issuer
 * assurance policy and is deliberately not advertised.
 *
 * @param style - the deployment's vocabulary; defaults to
 * {@link DEFAULT_ACR_VALUE_STYLE}.
 */
export function supportedAcrValues(style?: AcrValueStyle): readonly string[] {
  const table = ACR_VALUE_TABLES[parseAcrValueStyle(style) ?? DEFAULT_ACR_VALUE_STYLE];
  return Object.freeze([table.substantial, table.high]);
}
