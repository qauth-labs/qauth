import type { X509Certificate } from 'node:crypto';

import type { ChainResolution, X509TrustAnchors } from '../x509/anchored-chain';
import {
  createX509TrustAnchors,
  NO_X509_TRUST_ANCHORS,
  resolveAnchoredSigningCertificate,
} from '../x509/anchored-chain';

/**
 * `x5c` chain validation for the Status List Token (HAIP §6.1.1, issue #297).
 *
 * ## Why the status path needs its own key resolution
 *
 * The Status List Token is signed by the STATUS issuer, which need not be the
 * credential issuer and is reached over a URI the credential itself supplied.
 * Nothing about the presentation authenticates it. #297 specifies the same
 * resolution HAIP gives issuer keys — *"via the `x5c` JOSE header, trust anchor
 * excluded, signing certificate not self-signed"* — and that is what this
 * module applies, against anchors the OPERATOR configured out of band.
 *
 * Without it the whole feature inverts into a vulnerability: a verifier that
 * fetches a document from an attacker-named URI and believes whatever it says
 * has not added revocation checking, it has added a way for an attacker to
 * assert that a revoked credential is valid.
 *
 * ## The chain arithmetic itself lives in `x509/anchored-chain.ts`
 *
 * HAIP states the same three `x5c` rules twice — §6.1.1 for the Status List
 * Token here, §4.5.1 for the key attestation #308 validates — so the DER walk,
 * the path building and the leaf checks are ONE implementation shared by both
 * (see that module's JSDoc for what is and is not checked, and for why
 * `keyUsage` is enforced on the leaf while `cA` deliberately is not). What stays
 * here is everything status-specific: the anchor set is a DIFFERENT set of
 * anchors from the wallet-provider anchors #308 uses, and
 * {@link certificateBindsIssuer} is a binding only the status path needs.
 *
 * Two things the shared module's "NOT checked" list means HERE. Certificate
 * revocation of the chain itself (CRL/OCSP), name constraints and policy OIDs
 * are unchecked, and the outer defence that makes that acceptable on this path
 * is that a status list URI must already be on the operator's allowlist before
 * any of this runs. And the leaf's Extended Key Usage is not required: draft-14
 * §10 models the Status List Token signer as an END ENTITY and §11.3 recommends
 * the Status Issuer's certificate carry a status-signing `KeyPurposeId`, but
 * that EKU's OID is still `TBD` in draft-14, so it cannot be required yet. The
 * adjacent basic `keyUsage` constraint IS enforced, by the shared resolver.
 */

/**
 * A compiled set of operator-configured status-list trust anchors.
 *
 * Structurally the shared {@link X509TrustAnchors}, aliased under a
 * status-specific name so a call site reads honestly. The VALUES must never be
 * shared with another artifact's anchor set — see `x509/anchored-chain.ts`.
 */
export type StatusListTrustAnchors = X509TrustAnchors;

export type { ChainRejectionReason, ChainResolution } from '../x509/anchored-chain';

/**
 * A set of status-list anchors that trusts nothing.
 *
 * The value an unconfigured deployment gets, so "no anchors" is an object with
 * fail-closed behaviour rather than an `undefined` a caller might skip past.
 */
export const NO_STATUS_LIST_TRUST_ANCHORS: StatusListTrustAnchors = NO_X509_TRUST_ANCHORS;

/** How a malformed status-list anchor names itself to an operator. */
const STATUS_LIST_ANCHOR_DESCRIPTOR = Object.freeze({
  noun: 'status list trust anchor',
  issue: '#297',
});

/**
 * Compile operator-supplied PEM certificates into a status-list anchor set (#297).
 *
 * A malformed anchor throws loudly (an OPERATOR error) rather than being
 * dropped — dropping it would leave the operator believing an issuer is
 * anchored when it is not. The offending value goes on `details`, never into
 * the message.
 *
 * @param pems - PEM-encoded X.509 certificates; may be empty.
 * @returns a frozen anchor set.
 * @throws InvalidConfigurationError when an entry is not a parseable
 * certificate.
 */
export function createStatusListTrustAnchors(pems: readonly string[]): StatusListTrustAnchors {
  return createX509TrustAnchors(pems, STATUS_LIST_ANCHOR_DESCRIPTOR);
}

/**
 * Resolve the Status List Token's signing key from its `x5c` header (#297).
 *
 * Called with the UNVERIFIED protected header; see
 * {@link resolveAnchoredSigningCertificate} for the full contract and for every
 * check the chain is put through.
 *
 * @param x5c - the `x5c` member of the token's protected header, unverified.
 * @param anchors - the operator's configured STATUS-LIST anchors.
 * @param now - reference time for every validity window.
 * @returns the resolved leaf and its PEM key, or a reason for refusal. Never
 * throws.
 */
export function resolveStatusListSigningCertificate(
  x5c: unknown,
  anchors: StatusListTrustAnchors,
  now: Date
): ChainResolution {
  return resolveAnchoredSigningCertificate(x5c, anchors, now);
}

/**
 * Whether `leaf` actually speaks for `issuer`.
 *
 * The check that stops the most dangerous residual attack this design has: an
 * anchored certificate proves the holder is *someone* the operator's CA issued
 * to, not that they are the status issuer named by the token. Without a binding
 * from the certificate to the `iss` value, ANY holder of an anchored
 * certificate could sign a status list claiming to be any other issuer under
 * the same anchor — in a federation, that is every participant able to
 * un-revoke every other participant's credentials.
 *
 * The binding is `dNSName` SAN against the host of the `iss` URI, matching the
 * `x509_san_dns` semantics the profile layer already uses for the verifier
 * direction. The subject CN is explicitly NOT consulted (`subject: 'never'`):
 * CN-as-hostname was deprecated by RFC 2818 §3.1 and is trivially set to
 * anything by a CA that is not checking it.
 *
 * @param leaf - the resolved signing certificate.
 * @param issuer - the token's verified `iss` claim.
 * @returns whether the certificate authorises signing for that issuer.
 */
export function certificateBindsIssuer(leaf: X509Certificate, issuer: string): boolean {
  let host: string;
  try {
    const url = new URL(issuer);
    if (url.protocol !== 'https:') return false;
    host = url.hostname;
  } catch {
    return false;
  }
  if (host === '') return false;

  try {
    return leaf.checkHost(host, { subject: 'never' }) !== undefined;
  } catch {
    return false;
  }
}
