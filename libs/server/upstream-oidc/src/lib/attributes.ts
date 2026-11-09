import {
  UPSTREAM_STANDARD_ATTRIBUTES,
  type UpstreamClaimAttribute,
  upstreamClaimIsTrue,
  type UserAttribute,
  type VerifiedIdentity,
} from '@qauth-labs/server-federation';

// A preset's attribute rules are the plugin SDK's shape (#671): the rule, its
// test of a `*_verified` flag and the standard rules are declared there.
export { UPSTREAM_STANDARD_ATTRIBUTES, type UpstreamClaimAttribute, upstreamClaimIsTrue };

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
