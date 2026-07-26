/**
 * Client Identifier Prefixes (OID4VP 1.0 §5.9), issue #233.
 *
 * A Verifier identifies itself to a wallet through a PREFIX carried inside
 * `client_id`, in the form `<prefix>:<value>`. The prefix tells the wallet HOW
 * to establish who the Verifier is; the value is the identifier itself.
 *
 * Which prefixes a deployment may present — and what X.509 material each one
 * needs — is owned by the `VerifierProfile` (#299), never decided here. This
 * module only renders the string.
 *
 * QAuth implements ONE prefix today:
 *
 * - **`redirect_uri`** (§5.9.3) — unsigned and self-contained. The wallet
 *   authenticates the Verifier by the fact that the response goes to a URI the
 *   Verifier itself named, which is why §5.9.3 states such a request cannot be
 *   signed: a signature over it would be unverifiable, so it asserts nothing.
 *   Needs no certificate and therefore runs on today's EdDSA-only crypto.
 *
 * `x509_san_dns` and `x509_hash` both require a SIGNED request object, which
 * needs ES256 from #298. See {@link UNSIGNED_CLIENT_ID_PREFIX}.
 */

import type { ClientIdPrefix } from '../profiles/verifier-profile.types';

/** Separator between the prefix and its value in `client_id` (§5.9). */
export const CLIENT_ID_PREFIX_SEPARATOR = ':';

/**
 * The only prefix QAuth can present today.
 *
 * Named as a constant rather than written inline so the one place that decides
 * "unsigned is all we can do" is greppable, and so #298 has a single site to
 * revisit when signed prefixes become possible.
 */
export const UNSIGNED_CLIENT_ID_PREFIX = 'redirect_uri' satisfies ClientIdPrefix;

/**
 * Render a `client_id` from a prefix and its value (§5.9).
 *
 * @param prefix - the Client Identifier Prefix.
 * @param value - the prefix-specific identifier.
 */
export function buildClientId(prefix: ClientIdPrefix, value: string): string {
  return `${prefix}${CLIENT_ID_PREFIX_SEPARATOR}${value}`;
}

/**
 * Render the `redirect_uri`-prefixed `client_id` for a `direct_post` request
 * (OID4VP 1.0 §5.9.3).
 *
 * The subtlety worth writing down: with `response_mode=direct_post` the
 * identifier is the **Response URI**, not a redirect URI — §5.9.3 says the value
 * "MUST be equal to the `response_uri` value" in that mode. Since §8.2 also
 * forbids `redirect_uri` from appearing as a request parameter at all under
 * `direct_post`, the string `redirect_uri` survives ONLY as this prefix. A
 * reader who conflates the two would either emit a forbidden parameter or build
 * a `client_id` the wallet rejects for mismatching the response endpoint.
 *
 * @param responseUri - the absolute `response_uri` this request will carry.
 */
export function buildRedirectUriClientId(responseUri: string): string {
  return buildClientId(UNSIGNED_CLIENT_ID_PREFIX, responseUri);
}
