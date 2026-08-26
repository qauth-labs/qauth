/**
 * Client Identifier Prefixes (OID4VP 1.0 §5.9), issues #233 and #377.
 *
 * A Verifier identifies itself to a wallet through a PREFIX carried inside
 * `client_id`, in the form `<prefix>:<value>`. The prefix tells the wallet HOW
 * to establish who the Verifier is; the value is the identifier itself.
 *
 * Which prefixes a deployment may present — and what X.509 material each one
 * needs — is owned by the `VerifierProfile` (#299), never decided here. This
 * module only renders the string.
 *
 * QAuth implements TWO prefixes:
 *
 * - **`redirect_uri`** (§5.9.3) — unsigned and self-contained. The wallet
 *   authenticates the Verifier by the fact that the response goes to a URI the
 *   Verifier itself named, which is why §5.9.3 states such a request cannot be
 *   signed: a signature over it would be unverifiable, so it asserts nothing.
 *   Needs no certificate and therefore runs on today's EdDSA-only crypto.
 * - **`x509_hash`** (§5.9.3, #377) — the prefix HAIP 1.0 §5 MANDATES for signed
 *   requests: *"the Verifier MUST use, and the Wallet MUST accept the Client
 *   Identifier Prefix `x509_hash`"*. The value is a digest of the Verifier's
 *   leaf certificate, so the wallet learns the identity from the `x5c` header of
 *   the SIGNED request object and checks it against this value. Needs a
 *   non-self-signed chain (in the EU a QTSP-issued WRPAC) and ES256.
 *
 * `x509_san_dns` remains unimplemented. It is the OTHER signed prefix base
 * OID4VP permits, and #377 deliberately does not build it: HAIP mandates
 * `x509_hash` and nothing else, so shipping a second signed identity would add a
 * code path with no profile asking for it and no test ecosystem to prove it
 * against. See {@link UNSIGNED_CLIENT_ID_PREFIX}.
 */

import { createHash } from 'node:crypto';

import type { ClientIdPrefix } from '../profiles/verifier-profile.types';

/** Separator between the prefix and its value in `client_id` (§5.9). */
export const CLIENT_ID_PREFIX_SEPARATOR = ':';

/**
 * The prefix a deployment presents when it cannot — or must not — sign.
 *
 * Named as a constant rather than written inline so the one place that decides
 * "unsigned is all we can do" is greppable. It is also the value
 * `assertRequestSigningAllowed` refuses outright: OID4VP 1.0 §5.9.3 makes a
 * request under this prefix unverifiable, so signing it asserts nothing.
 */
export const UNSIGNED_CLIENT_ID_PREFIX = 'redirect_uri' satisfies ClientIdPrefix;

/**
 * The only prefix HAIP 1.0 mandates, and the only SIGNED prefix QAuth renders.
 *
 * Named here rather than written inline for the same reason as the constant
 * above — and because #299's acceptance criterion is that no HAIP-specific
 * constant appears in protocol code outside the profile table. This module is
 * the rendering layer for a prefix the TABLE selected; it never decides that
 * `haip-1.0` is in force.
 */
export const X509_HASH_CLIENT_ID_PREFIX = 'x509_hash' satisfies ClientIdPrefix;

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

/**
 * Render the `x509_hash`-prefixed `client_id` from the Verifier's LEAF
 * certificate (OID4VP 1.0 §5.9.3, #377).
 *
 * §5.9.3 defines the value as *"the base64url-encoded value of the SHA-256 hash
 * of the DER-encoded X.509 certificate"* — so three things are load-bearing and
 * each is a way to get a `client_id` every wallet rejects:
 *
 *  - **The LEAF, and only the leaf.** Not the chain, not the anchor. The wallet
 *    recomputes this digest over `x5c[0]` of the signed request object; a digest
 *    over anything else can never match.
 *  - **DER, not PEM.** `X509Certificate.raw` is the DER; `toString()` is the
 *    base64-wrapped PEM. Hashing the PEM would hash a text encoding of the
 *    certificate rather than the certificate.
 *  - **base64url, unpadded.** Node's `digest('base64url')` emits exactly that.
 *    Standard base64 would carry `+`, `/` and `=`, none of which survive a URL
 *    intact — and `client_id` travels as a query parameter.
 *
 * @param leafCertificateDer - DER bytes of the leaf certificate, i.e.
 * `X509Certificate.raw` for the certificate whose key signs the request object.
 * @returns the prefixed `client_id`, ready to go on the wire.
 */
export function buildX509HashClientId(leafCertificateDer: Uint8Array): string {
  return buildClientId(
    X509_HASH_CLIENT_ID_PREFIX,
    createHash('sha256').update(leafCertificateDer).digest('base64url')
  );
}
