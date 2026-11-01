import type { UserAttribute, VerifiedIdentity } from '@qauth-labs/server-federation';

/**
 * The attributes the generic client takes from a provider's claims: the
 * standard profile claims of OpenID Connect Core 1.0 §5.1 that are plain
 * text. Mapping other claims is the IdP mappers' work (#713); the account
 * decisions (a new account, a match) are the sign-in flow's (#639). Nothing
 * here matches or merges an account by an attribute.
 *
 * `email` and `phone_number` are `verified` only when the provider's own
 * `email_verified` / `phone_number_verified` claim is the boolean `true`.
 * Every other attribute is `verified: false`: the provider asserts it, it
 * does not verify it. A claim that is not a string, or that the engine's
 * attribute rules would refuse, is left out.
 */

/** The claims taken as attributes, and the claim that marks each verified. */
const ATTRIBUTE_CLAIMS: readonly (readonly [claim: string, verifiedBy?: string])[] = [
  ['email', 'email_verified'],
  ['phone_number', 'phone_number_verified'],
  ['name'],
  ['given_name'],
  ['family_name'],
  ['middle_name'],
  ['nickname'],
  ['preferred_username'],
  ['locale'],
  ['zoneinfo'],
];

/** The longest attribute value, as the AuthMethod contract caps it. */
const MAX_VALUE_LENGTH = 8192;

/** A control character an attribute value may not hold: C0 but tab and line breaks, and DEL. */
// eslint-disable-next-line no-control-regex -- matching control characters is the point
const VALUE_CONTROL_CHARACTER = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;

/** The attributes of a verified identity, each under `source`. */
export function claimAttributes(source: string, identity: VerifiedIdentity): UserAttribute[] {
  const claims = identity.rawClaims;
  const claim = (name: string): unknown => (Object.hasOwn(claims, name) ? claims[name] : undefined);
  const attributes: UserAttribute[] = [];
  for (const [name, verifiedBy] of ATTRIBUTE_CLAIMS) {
    const value = claim(name);
    if (!isAttributeValue(value)) continue;
    attributes.push({
      source,
      attrKey: name,
      attrValue: value,
      verified: verifiedBy !== undefined && claim(verifiedBy) === true,
    });
  }
  return attributes;
}

function isAttributeValue(value: unknown): value is string {
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
