import { X509Certificate } from 'node:crypto';

import { InvalidConfigurationError } from '@qauth-labs/shared-errors';

import { summarizeConfiguredValue } from '../trust/configured-value';

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
 * module implements, against anchors the OPERATOR configured out of band.
 *
 * Without it the whole feature inverts into a vulnerability: a verifier that
 * fetches a document from an attacker-named URI and believes whatever it says
 * has not added revocation checking, it has added a way for an attacker to
 * assert that a revoked credential is valid.
 *
 * ## Built on `node:crypto`, not on a new dependency
 *
 * `X509Certificate` gives DER parsing, `checkIssued` (name and authority-key
 * matching), `verify` (the actual signature over the child certificate),
 * `ca`, the validity window and SAN matching. That is every primitive path
 * validation needs, in the platform, with no package added to a workspace whose
 * lockfile is contended.
 *
 * ## What is checked, and what is deliberately not
 *
 * Checked: chain bounds, strict base64, self-signed leaf refused, validity
 * window on every certificate INCLUDING the anchor, `cA` on every issuing
 * certificate, a real signature verification at every link, a path that
 * terminates at a configured anchor, the anchor absent from the chain, and an
 * EC P-256 leaf key (so an `ES256` header cannot be satisfied by a key of
 * another type).
 *
 * NOT checked: certificate revocation of the chain itself (CRL/OCSP), name
 * constraints, and policy OIDs. Each is a real gap and each is called out here
 * rather than left to be discovered: an operator's trust anchors are expected
 * to be a small, private, purpose-issued set, and the outer defence is that a
 * status list URI must already be on the operator's allowlist before any of
 * this runs.
 */

/** Largest `x5c` chain accepted, in certificates. */
const MAX_CHAIN_LENGTH = 8;

/** Largest single `x5c` entry accepted, in base64 characters (~12 KiB DER). */
const MAX_CERTIFICATE_BASE64_LENGTH = 16 * 1024;

/** The only leaf key type an `ES256` Status List Token may be signed with. */
const REQUIRED_LEAF_CURVE = 'prime256v1';

/**
 * A compiled set of operator-configured trust anchors.
 *
 * Opaque, like `StatusListUriAllowlist`: a caller can validate against it but
 * cannot enumerate it, so no error message can ever be built from its contents.
 */
export interface StatusListTrustAnchors {
  /** How many anchors were configured. Zero means nothing can ever validate. */
  readonly size: number;
  /** Internal — the parsed anchors. */
  readonly certificates: readonly X509Certificate[];
}

/**
 * A set of anchors that trusts nothing.
 *
 * The value an unconfigured deployment gets, so "no anchors" is an object with
 * fail-closed behaviour rather than an `undefined` a caller might skip past.
 */
export const NO_STATUS_LIST_TRUST_ANCHORS: StatusListTrustAnchors = Object.freeze({
  size: 0,
  certificates: Object.freeze([]),
});

/**
 * Compile operator-supplied PEM certificates into a trust-anchor set (#297).
 *
 * Anchors are the root of the whole status path's authority, so a malformed one
 * throws loudly (an OPERATOR error) rather than being dropped — dropping it
 * would leave the operator believing an issuer is anchored when it is not. The
 * offending value goes on `details`, never into the message, and is truncated:
 * a certificate is not a secret, but a 4 KiB PEM in a log line is a denial of
 * readability.
 *
 * @param pems - PEM-encoded X.509 certificates; may be empty.
 * @returns a frozen anchor set.
 * @throws InvalidConfigurationError when an entry is not a parseable
 * certificate.
 */
export function createStatusListTrustAnchors(pems: readonly string[]): StatusListTrustAnchors {
  if (!Array.isArray(pems)) {
    throw new InvalidConfigurationError(
      'Status list trust anchors must be an array of PEM-encoded X.509 certificates (#297).'
    );
  }

  const certificates: X509Certificate[] = [];
  for (const [index, pem] of pems.entries()) {
    let certificate: X509Certificate | undefined;
    try {
      certificate = typeof pem === 'string' ? new X509Certificate(pem) : undefined;
    } catch {
      certificate = undefined;
    }

    if (certificate === undefined) {
      throw new InvalidConfigurationError(
        'A status list trust anchor is not a parseable PEM-encoded X.509 certificate (#297). See this error\'s "details" for the position and the value.',
        { index, entry: summarizeConfiguredValue(pem) }
      );
    }

    certificates.push(certificate);
  }

  if (certificates.length === 0) return NO_STATUS_LIST_TRUST_ANCHORS;

  return Object.freeze({ size: certificates.length, certificates: Object.freeze(certificates) });
}

/** Why a chain was refused. Server-side detail only; never reaches a client. */
export type ChainRejectionReason =
  | 'malformed-x5c'
  | 'self-signed-leaf'
  | 'certificate-expired'
  | 'broken-link'
  | 'anchor-in-chain'
  | 'no-path-to-anchor'
  | 'unsupported-leaf-key';

/** The result of resolving a Status List Token's signing certificate. */
export type ChainResolution =
  | {
      readonly outcome: 'resolved';
      /** The end-entity certificate whose key signed the token. */
      readonly leaf: X509Certificate;
      /** The leaf's public key as SPKI PEM, ready for JOSE import. */
      readonly publicKeyPem: string;
    }
  | { readonly outcome: 'rejected'; readonly reason: ChainRejectionReason };

/**
 * Strictly decode a standard-alphabet base64 `x5c` entry (RFC 7515 §4.1.6).
 *
 * `x5c` is base64, NOT base64url, and `Buffer.from` is lenient enough to accept
 * either while silently discarding anything it does not recognise. A tolerant
 * decode of certificate bytes is a way to make two different byte strings parse
 * to the same certificate, so the alphabet is pinned before decoding.
 */
function decodeCertificateEntry(entry: unknown): Buffer | undefined {
  if (typeof entry !== 'string') return undefined;
  if (entry.length === 0 || entry.length > MAX_CERTIFICATE_BASE64_LENGTH) return undefined;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(entry)) return undefined;
  if (entry.length % 4 !== 0) return undefined;
  return Buffer.from(entry, 'base64');
}

/** Parse an `x5c` array into certificates, or `undefined` if any entry is bad. */
function parseChain(x5c: unknown): X509Certificate[] | undefined {
  if (!Array.isArray(x5c) || x5c.length === 0 || x5c.length > MAX_CHAIN_LENGTH) return undefined;

  const chain: X509Certificate[] = [];
  for (const entry of x5c) {
    const der = decodeCertificateEntry(entry);
    if (der === undefined) return undefined;
    try {
      chain.push(new X509Certificate(der));
    } catch {
      return undefined;
    }
  }
  return chain;
}

/** Whether `certificate` is inside its validity window at `now`. */
function isTemporallyValid(certificate: X509Certificate, now: Date): boolean {
  const from = certificate.validFromDate;
  const to = certificate.validToDate;
  if (from === undefined || to === undefined) return false;
  return from.getTime() <= now.getTime() && now.getTime() <= to.getTime();
}

/**
 * Whether `child` was genuinely issued by `issuer`.
 *
 * BOTH checks are required and neither is sufficient. `checkIssued` compares
 * names and authority/subject key identifiers — cheap, and entirely forgeable,
 * since an attacker writes their own certificate's issuer field. `verify` is
 * the cryptographic proof but says nothing about naming, so on its own it would
 * accept a certificate that verifies under a key it never claimed to be issued
 * by. Together they are "claims this parent, and that claim is true".
 */
function isIssuedBy(child: X509Certificate, issuer: X509Certificate): boolean {
  try {
    return child.checkIssued(issuer) && child.verify(issuer.publicKey);
  } catch {
    // A certificate carrying a key type this build of OpenSSL cannot verify
    // with reaches here. An unverifiable link is a broken link.
    return false;
  }
}

/** Whether a certificate is self-signed (verifies under its own public key). */
function isSelfSigned(certificate: X509Certificate): boolean {
  try {
    return certificate.verify(certificate.publicKey);
  } catch {
    return false;
  }
}

/** Whether the leaf's key is the EC P-256 key an `ES256` signature requires. */
function hasEs256LeafKey(leaf: X509Certificate): boolean {
  const key = leaf.publicKey;
  if (key.asymmetricKeyType !== 'ec') return false;
  return key.asymmetricKeyDetails?.namedCurve === REQUIRED_LEAF_CURVE;
}

/**
 * Resolve the Status List Token's signing key from its `x5c` header (#297).
 *
 * Called with the UNVERIFIED protected header — necessarily, because the key
 * needed to verify the signature is what this produces. Everything it returns
 * is therefore treated as attacker-supplied until the signature check that
 * follows succeeds; its job is only to decide which key that check may use, and
 * to refuse to nominate one that is not anchored.
 *
 * The chain is ordered leaf-first per RFC 7515 §4.1.6, and the trust anchor is
 * EXCLUDED from it (HAIP §6.1.1). An anchor found inside the chain is refused
 * outright rather than tolerated: a self-signed root shipped in `x5c` would
 * otherwise satisfy the path check against itself, which turns "chains to an
 * anchor" into "carries a copy of an anchor".
 *
 * @param x5c - the `x5c` member of the token's protected header, unverified.
 * @param anchors - the operator's configured anchors.
 * @param now - reference time for every validity window.
 * @returns the resolved leaf and its PEM key, or a reason for refusal. Never
 * throws.
 */
export function resolveStatusListSigningCertificate(
  x5c: unknown,
  anchors: StatusListTrustAnchors,
  now: Date
): ChainResolution {
  const chain = parseChain(x5c);
  if (chain === undefined) return { outcome: 'rejected', reason: 'malformed-x5c' };

  // `chain[0]` is safe: `parseChain` refuses an empty array.
  const leaf = chain[0] as X509Certificate;

  if (isSelfSigned(leaf)) return { outcome: 'rejected', reason: 'self-signed-leaf' };

  for (const certificate of chain) {
    if (!isTemporallyValid(certificate, now)) {
      return { outcome: 'rejected', reason: 'certificate-expired' };
    }
    if (anchors.certificates.some((anchor) => anchor.raw.equals(certificate.raw))) {
      return { outcome: 'rejected', reason: 'anchor-in-chain' };
    }
  }

  for (let index = 0; index < chain.length - 1; index += 1) {
    const child = chain[index] as X509Certificate;
    const parent = chain[index + 1] as X509Certificate;
    // An intermediate that is not a CA cannot issue: without this, a leaf
    // certificate legitimately issued under the anchor could be used to mint
    // certificates for any status issuer.
    if (parent.ca !== true) return { outcome: 'rejected', reason: 'broken-link' };
    if (!isIssuedBy(child, parent)) return { outcome: 'rejected', reason: 'broken-link' };
  }

  const top = chain[chain.length - 1] as X509Certificate;
  const anchored = anchors.certificates.some(
    (anchor) => anchor.ca === true && isTemporallyValid(anchor, now) && isIssuedBy(top, anchor)
  );
  if (!anchored) return { outcome: 'rejected', reason: 'no-path-to-anchor' };

  if (!hasEs256LeafKey(leaf)) return { outcome: 'rejected', reason: 'unsupported-leaf-key' };

  return {
    outcome: 'resolved',
    leaf,
    publicKeyPem: leaf.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
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
