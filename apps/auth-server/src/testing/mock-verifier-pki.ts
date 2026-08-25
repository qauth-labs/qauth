import { createTestCertificate, type TestCertificate, toPkcs8Pem } from './x509-der';

/**
 * TEST SUPPORT — an operator-supplied PKI for QAuth's OWN verifier identity
 * (issue #377).
 *
 * ## What it stands in for
 *
 * In the EU this is a QTSP-issued Wallet-Relying-Party Access Certificate: a
 * leaf issued under a CA the wallet's trust list already recognises. An operator
 * obtaining a real one is a CIR (EU) 2025/848 obligation, not something a test
 * can arrange — so this mints an equivalent three-tier chain and hands the
 * pieces to the two parties that need different halves of it:
 *
 * - **QAuth** gets the leaf's private key, the chain (leaf + intermediate) and
 *   the anchor, as the three environment variables an operator would set.
 * - **The wallet** gets the ANCHOR ONLY, and gets it out of band — never from
 *   the request. That asymmetry is the whole assertion: a signed request whose
 *   `x5c` carried its own anchor would validate against itself, which is not
 *   what "chains to a trust anchor" means.
 *
 * ## Three tiers, not two
 *
 * A leaf issued directly by the anchor would still be a non-self-signed chain
 * and would still validate — but it would leave `x5c` a single-element array,
 * and "the chain carries leaf + intermediates and NOT the anchor" would then be
 * indistinguishable from "the chain carries the leaf". The intermediate is what
 * makes that assertion mean something.
 */

/** A minted verifier PKI, in the two shapes its two consumers need. */
export interface MockVerifierPki {
  /** `OID4VP_VERIFIER_SIGNING_KEY` — the leaf's PKCS#8 private key. */
  readonly signingKeyPem: string;
  /**
   * `OID4VP_VERIFIER_CERTIFICATE_CHAIN` — leaf first, then the intermediate,
   * with the anchor DELIBERATELY absent.
   */
  readonly certificateChainPem: string;
  /** `OID4VP_VERIFIER_TRUST_ANCHORS` — the anchor, and only the anchor. */
  readonly trustAnchorPem: string;
  /**
   * The anchor as the WALLET holds it: out of band, from a trust list, never
   * from a request. The same bytes as {@link trustAnchorPem}; named separately
   * because a test that passed the wrong one would still pass, and the name is
   * what makes the reviewer notice.
   */
  readonly walletTrustAnchorPem: string;
  /** The leaf, for asserting on `x5c` and on the `x509_hash` digest. */
  readonly leaf: TestCertificate;
  /** The intermediate, for asserting it IS in `x5c`. */
  readonly intermediate: TestCertificate;
  /** The anchor, for asserting it is NOT in `x5c`. */
  readonly anchor: TestCertificate;
}

/** What {@link createMockVerifierPki} may vary. */
export interface CreateMockVerifierPkiOptions {
  /** Common-name stem for the three certificates. */
  readonly name?: string;
  /** End of the LEAF's validity window; defaults to the factory's own. */
  readonly leafNotAfter?: Date;
  /** Start of the LEAF's validity window; defaults to the factory's own. */
  readonly leafNotBefore?: Date;
}

/**
 * Mint an anchor → intermediate → leaf chain for the verifier identity.
 *
 * The leaf asserts `digitalSignature` and nothing else, which is what RFC 5280
 * §4.2.1.3 defines for signing an object that is not a certificate or a CRL —
 * and what `resolveAnchoredSigningCertificate` checks. The CAs assert
 * `keyCertSign`/`cRLSign` and NOT `digitalSignature`, which is what a conforming
 * CA looks like and what makes "an anchored intermediate signs the request
 * directly" a case the verifier refuses rather than a case this fixture cannot
 * express.
 *
 * @param options - see {@link CreateMockVerifierPkiOptions}.
 */
export function createMockVerifierPki(options: CreateMockVerifierPkiOptions = {}): MockVerifierPki {
  const name = options.name ?? 'qauth-verifier.example';

  const anchor = createTestCertificate({
    subject: `${name} Root CA`,
    ca: true,
    keyUsage: ['keyCertSign', 'cRLSign'],
  });

  const intermediate = createTestCertificate({
    subject: `${name} Issuing CA`,
    issuer: anchor,
    ca: true,
    keyUsage: ['keyCertSign', 'cRLSign'],
  });

  const leaf = createTestCertificate({
    subject: name,
    issuer: intermediate,
    keyUsage: ['digitalSignature'],
    ...(options.leafNotBefore === undefined ? {} : { notBefore: options.leafNotBefore }),
    ...(options.leafNotAfter === undefined ? {} : { notAfter: options.leafNotAfter }),
  });

  return {
    signingKeyPem: toPkcs8Pem(leaf.privateKey),
    // Concatenated exactly as `cat leaf.crt intermediate.crt` produces, which is
    // the form the env schema splits back into individual blocks.
    certificateChainPem: `${leaf.pem}${intermediate.pem}`,
    trustAnchorPem: anchor.pem,
    walletTrustAnchorPem: anchor.pem,
    leaf,
    intermediate,
    anchor,
  };
}

/**
 * The three environment variables an operator sets to provision this identity.
 *
 * Built from the PKI rather than written out by each suite, so a test cannot
 * configure a chain that does not match the key it also configured — which would
 * make the boot fail for an uninteresting reason.
 */
export function verifierIdentityEnvironment(pki: MockVerifierPki): Record<string, string> {
  return {
    OID4VP_VERIFIER_SIGNING_KEY: pki.signingKeyPem,
    OID4VP_VERIFIER_CERTIFICATE_CHAIN: pki.certificateChainPem,
    OID4VP_VERIFIER_TRUST_ANCHORS: pki.trustAnchorPem,
  };
}
