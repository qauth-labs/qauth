import type { UserAttribute, VerifiedIdentity } from '@qauth-labs/server-federation';

/**
 * The attributes the client takes from a provider's claims: by default the
 * standard profile claims of OpenID Connect Core 1.0 §5.1 that are plain
 * text, and a preset plugin's own rules in their place (#671). Mapping other
 * claims is the IdP mappers' work (#713); the account decisions (a new
 * account, a match) are the sign-in flow's (#639). Nothing here matches or
 * merges an account by an attribute.
 *
 * By default `email` and `phone_number` are `verified` only when the
 * provider's own `email_verified` / `phone_number_verified` claim is the
 * boolean `true`. Every other attribute is `verified: false`: the provider
 * asserts it, it does not verify it. A claim that is not a string, or that
 * the engine's attribute rules would refuse, is left out.
 */

/**
 * One attribute a provider's claims map to.
 *
 * @experimental
 */
export interface UpstreamClaimAttribute {
  /** The claim the value is read from: a string claim, or the attribute is left out. */
  readonly claim: string;
  /** The attribute's key: the claim's name unless set. */
  readonly attribute?: string;
  /**
   * Whether the provider vouches for the value, read from the identity's
   * claims: `verified` only when this returns the boolean `true`. Without
   * it the attribute is never verified.
   */
  readonly verified?: (claims: Readonly<Record<string, unknown>>) => boolean;
}

/** Whether `claims[name]` is the boolean `true`. */
export function upstreamClaimIsTrue(
  claims: Readonly<Record<string, unknown>>,
  name: string
): boolean {
  return Object.hasOwn(claims, name) && claims[name] === true;
}

/**
 * The generic client's attributes: the standard profile claims that are
 * plain text, `email` and `phone_number` verified by their `*_verified`
 * claim.
 *
 * @experimental
 */
export const UPSTREAM_STANDARD_ATTRIBUTES: readonly UpstreamClaimAttribute[] = Object.freeze([
  { claim: 'email', verified: (claims) => upstreamClaimIsTrue(claims, 'email_verified') },
  {
    claim: 'phone_number',
    verified: (claims) => upstreamClaimIsTrue(claims, 'phone_number_verified'),
  },
  { claim: 'name' },
  { claim: 'given_name' },
  { claim: 'family_name' },
  { claim: 'middle_name' },
  { claim: 'nickname' },
  { claim: 'preferred_username' },
  { claim: 'locale' },
  { claim: 'zoneinfo' },
]);

/** The longest attribute value, as the AuthMethod contract caps it. */
const MAX_VALUE_LENGTH = 8192;

/** A control character an attribute value may not hold: C0 but tab and line breaks, and DEL. */
// eslint-disable-next-line no-control-regex -- matching control characters is the point
const VALUE_CONTROL_CHARACTER = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;

/** The attributes of a verified identity, each under `source`, by the standard rules. */
export function claimAttributes(source: string, identity: VerifiedIdentity): UserAttribute[] {
  return upstreamClaimAttributes(source, identity.rawClaims, UPSTREAM_STANDARD_ATTRIBUTES);
}

/**
 * The attributes `rules` map `claims` to, each under `source`. A rule whose
 * claim is not a plain-text string is left out; a key two rules map to is
 * taken from the first that has a value.
 *
 * @experimental
 */
export function upstreamClaimAttributes(
  source: string,
  claims: Readonly<Record<string, unknown>>,
  rules: readonly UpstreamClaimAttribute[]
): UserAttribute[] {
  const attributes: UserAttribute[] = [];
  const taken = new Set<string>();
  for (const rule of rules) {
    const key = rule.attribute ?? rule.claim;
    if (taken.has(key)) continue;
    const value = Object.hasOwn(claims, rule.claim) ? claims[rule.claim] : undefined;
    if (!isAttributeValue(value)) continue;
    taken.add(key);
    attributes.push({ source, attrKey: key, attrValue: value, verified: vouched(rule, claims) });
  }
  return attributes;
}

/** Whether the rule says the provider vouches for the value; a rule that throws does not. */
function vouched(rule: UpstreamClaimAttribute, claims: Readonly<Record<string, unknown>>): boolean {
  try {
    return rule.verified?.(claims) === true;
  } catch {
    return false;
  }
}

/** Whether `value` is plain text an attribute may hold. */
export function isAttributeValue(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= MAX_VALUE_LENGTH &&
    !VALUE_CONTROL_CHARACTER.test(value) &&
    (String.prototype as unknown as { isWellFormed(this: string): boolean }).isWellFormed.call(
      value
    )
  );
}
