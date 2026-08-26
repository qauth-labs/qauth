import { createPrivateKey, createPublicKey, type KeyObject, X509Certificate } from 'node:crypto';

import { InvalidConfigurationError } from '@qauth-labs/shared-errors';

import {
  NO_VERIFIER_MATERIAL,
  type ProvisionedVerifierMaterial,
} from '../profiles/verifier-identity';
import { summarizeConfiguredValue } from '../trust/configured-value';
import {
  createX509TrustAnchors,
  resolveAnchoredSigningCertificate,
  type TrustAnchorDescriptor,
} from './anchored-chain';

/**
 * The Verifier's OWN signing identity: the ES256 key and X.509 chain QAuth
 * signs an OID4VP Authorization Request with (issue #377, Phase A).
 *
 * ## This is the third X.509 trust question, and it points the other way
 *
 * `anchored-chain.ts` already serves two callers — Status List Tokens (#297) and
 * key attestations (#308) — and both ask *"may I believe this artifact somebody
 * else signed?"*. This module asks the opposite: *"is the material an operator
 * gave US actually usable to prove who we are?"* Same path validation, opposite
 * direction, and deliberately the same implementation: the rules HAIP states for
 * a Verifier's chain are the ones `resolveAnchoredSigningCertificate` already
 * enforces — leaf not self-signed, every link genuinely issued, the trust anchor
 * EXCLUDED from `x5c`, an EC P-256 leaf key, and a leaf whose `keyUsage` (when
 * present) asserts `digitalSignature`. Writing a second DER walk so this
 * direction could own a copy is how one copy quietly stops enforcing something
 * the other still does.
 *
 * ## Why validation happens at BOOT
 *
 * Every failure this catches is an operator mistake whose runtime symptom is
 * identical and useless: a wallet rejects the signed request, so 100% of
 * presentations fail with no signal naming the cause. A mis-pasted intermediate,
 * an anchor accidentally left in the chain, a key that does not belong to the
 * leaf — none of them are visible from a log line at request time. Refusing the
 * boot is what turns them into one message an operator can act on.
 *
 * ## What this is NOT
 *
 * Not a token-issuance key, and never interchangeable with one. #298's risk note
 * is explicit that *"the two key sets must not be interchangeable"*: the key here
 * proves QAuth's identity TO A WALLET, while `@qauth-labs/server-jwt`'s keys sign
 * the access and ID tokens QAuth issues to its own relying parties. Nothing in
 * this module reaches the JWT plugin, nothing here is published in
 * `GET /.well-known/jwks.json`, and `apps/auth-server` has a test asserting both.
 *
 * @see https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html §5
 */

/** How a chain refusal names this anchor set to an operator. */
const VERIFIER_ANCHOR_DESCRIPTOR: TrustAnchorDescriptor = Object.freeze({
  noun: 'OID4VP verifier trust anchor',
  issue: '#377',
});

/** The only algorithm a Verifier may sign an OID4VP request with (HAIP §7). */
export const VERIFIER_REQUEST_SIGNING_ALGORITHM = 'ES256';

/** The only leaf key type an `ES256` signature may be produced with. */
const REQUIRED_LEAF_CURVE = 'prime256v1';

/**
 * The Verifier's usable signing identity — the output of a chain that VALIDATED.
 *
 * Only ever constructed by {@link createVerifierSigningMaterial}, so holding one
 * is itself the proof that the chain was anchored and the key matches the leaf.
 * A caller cannot assemble this from raw configuration and skip the checks.
 */
export interface VerifierSigningMaterial {
  /**
   * The ES256 private key as PKCS#8 PEM — NORMALISED, not verbatim.
   *
   * An operator may configure SEC1 (`BEGIN EC PRIVATE KEY`, what
   * `openssl ecparam -genkey` emits) or PKCS#8; this is always the latter,
   * because that is the only form `importPrivateSigningKey` accepts. See
   * {@link normalizeAndMatchPrivateKey} for why the conversion happens at boot
   * rather than the input being refused.
   *
   * Kept as PEM rather than an imported key object because importing is the
   * signing layer's concern and this library must not choose a JOSE backend for
   * it — `@qauth-labs/core-crypto`'s `importPrivateSigningKey` does that, at the
   * one place that signs.
   */
  readonly privateKeyPem: string;
  /**
   * The `x5c` header value: standard-alphabet base64 DER, LEAF FIRST
   * (RFC 7515 §4.1.6), with the trust anchor excluded.
   *
   * Anchor exclusion is not a preference. `resolveAnchoredSigningCertificate`
   * refuses a chain that contains one of the configured anchors outright, so a
   * chain that produced this value provably does not carry it — which is what
   * lets a wallet's own anchor decide the outcome instead of a copy the request
   * shipped with.
   */
  readonly x5c: readonly string[];
  /** DER of the leaf, i.e. the bytes `buildX509HashClientId` digests. */
  readonly leafDer: Uint8Array;
  /**
   * End of the leaf's validity window.
   *
   * Carried so the signing path can refuse an expired certificate rather than
   * emitting requests every wallet rejects. Boot-time validation cannot cover
   * this: a process that started in January is still running in December.
   */
  readonly leafNotAfter: Date;
}

/** Inputs to {@link createVerifierSigningMaterial}. */
export interface CreateVerifierSigningMaterialOptions {
  /**
   * ES256 private key as the OPERATOR supplied it — PKCS#8 or SEC1 PEM. It is
   * normalised to PKCS#8 on the way out; see {@link normalizeAndMatchPrivateKey}.
   */
  readonly privateKeyPem: string;
  /**
   * The chain as individual PEM certificates, LEAF FIRST, anchor excluded.
   *
   * Split into individual certificates by the configuration layer rather than
   * handed over as one bundle string, because `new X509Certificate(bundle)`
   * parses the first certificate and silently ignores the rest — a two-tier
   * chain passed whole would sign with a leaf whose intermediate never reached
   * the wallet.
   */
  readonly certificateChainPems: readonly string[];
  /** Anchors the chain must terminate at, as individual PEM certificates. */
  readonly trustAnchorPems: readonly string[];
  /** Reference time for every validity window. Defaults to now. */
  readonly now?: Date;
}

/** Parse one operator-supplied PEM certificate, or refuse with its position. */
function parseChainCertificate(pem: string, index: number): X509Certificate {
  try {
    return new X509Certificate(pem);
  } catch (error) {
    throw new InvalidConfigurationError(
      'The OID4VP verifier certificate chain contains an entry that is not a parseable PEM-encoded X.509 certificate (#377). See this error\'s "details" for the position and the value.',
      { index, entry: summarizeConfiguredValue(pem), cause: String(error) }
    );
  }
}

/**
 * The EC public-key members that identify a P-256 key uniquely.
 *
 * Compared instead of exported SPKI DER, which is sensitive to the point
 * CONVERSION FORM: a certificate whose issuer encoded the public point in
 * compressed form (RFC 5480 §2.2 permits it) re-exports compressed, while the
 * key derived from a PKCS#8 private key exports uncompressed — two different
 * byte strings for the same key. `x` and `y` are the coordinates themselves, so
 * they are equal exactly when the keys are.
 */
function publicKeyIdentity(key: KeyObject): string {
  const jwk = key.export({ format: 'jwk' });
  return `${String(jwk.crv)}.${String(jwk.x)}.${String(jwk.y)}`;
}

/** A private key accepted at boot, in the form the signing path requires. */
interface AcceptedPrivateKey {
  /** PKCS#8 PEM — see {@link normalizeAndMatchPrivateKey} for why normalised. */
  readonly pkcs8Pem: string;
}

/**
 * Refuse a private key that is not the leaf's own EC P-256 key, and hand back
 * the form the signing path will actually use.
 *
 * Two failures, both invisible until a wallet rejects a request:
 *
 *  - **The wrong key.** An operator who mounts last year's key beside this
 *    year's certificate produces a signature that verifies under a key nobody
 *    in the chain holds. Every wallet refuses it, and nothing in QAuth's own
 *    logs says why. Chain validation cannot substitute for this check.
 *  - **The right key in the wrong ENCODING.** `openssl ecparam -genkey` — the
 *    way most operators will produce a P-256 key — emits SEC1
 *    (`BEGIN EC PRIVATE KEY`). `createPrivateKey` accepts it, so a check written
 *    around `node:crypto` alone passes; `jose`'s `importPKCS8`, which the
 *    signing path uses, refuses it outright. The boot would then validate one
 *    thing and the request path use another.
 *
 * The second is fixed by NORMALISING rather than refusing, and that is a
 * deliberate departure from this codebase's usual refuse-don't-repair posture.
 * The two encodings are the same key with no security difference and no
 * ambiguity about intent — unlike a peer-supplied JWK, where a repair would hide
 * a broken or hostile counterparty. What the normalisation buys is stronger than
 * ergonomics: the bytes this function VALIDATED are the bytes the signing path
 * IMPORTS, so the class of "boot checked one form, signing used another" is
 * closed rather than narrowed.
 */
function normalizeAndMatchPrivateKey(
  privateKeyPem: string,
  leaf: X509Certificate
): AcceptedPrivateKey {
  let privateKey: KeyObject;

  try {
    privateKey = createPrivateKey(privateKeyPem);
  } catch (error) {
    throw new InvalidConfigurationError(
      'The OID4VP verifier signing key is not a readable PEM private key (#377). See this error\'s "details" for the underlying reason; the key itself is never logged.',
      { cause: error instanceof Error ? error.message : String(error) }
    );
  }

  if (
    privateKey.asymmetricKeyType !== 'ec' ||
    privateKey.asymmetricKeyDetails?.namedCurve !== REQUIRED_LEAF_CURVE
  ) {
    throw new InvalidConfigurationError(
      `The OID4VP verifier signing key must be an EC P-256 (prime256v1) private key — ${VERIFIER_REQUEST_SIGNING_ALGORITHM} is the algorithm HAIP §7 requires and the only one an OID4VP request object may be signed with here (#377).`
    );
  }

  // Normalised FIRST, and the identity check then runs on those exact bytes —
  // so what boot proved about the key is a property of the value the signing
  // path will import, not of the value the operator happened to write.
  const pkcs8Pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

  if (publicKeyIdentity(createPublicKey(pkcs8Pem)) !== publicKeyIdentity(leaf.publicKey)) {
    throw new InvalidConfigurationError(
      'The OID4VP verifier signing key does not belong to the leaf certificate of the configured chain (#377). Refusing to start rather than signing every Authorization Request with a key no wallet can find in the x5c header.'
    );
  }

  return { pkcs8Pem };
}

/**
 * Validate the operator's verifier key and chain, or refuse the boot (#377).
 *
 * The order is deliberate and each step is a different operator mistake:
 *
 *  1. **A chain is configured at all.** An empty chain cannot identify anyone.
 *  2. **Anchors are configured.** A chain with nothing to terminate at can never
 *     validate, so this fails here with a message naming the anchor variable
 *     rather than later as an opaque `no-path-to-anchor`.
 *  3. **Every entry parses**, reported with its position.
 *  4. **The chain is anchored** — delegated wholesale to
 *     `resolveAnchoredSigningCertificate`, which is where self-signed leaves,
 *     expired certificates, broken links, an anchor smuggled into the chain, a
 *     non-P-256 leaf key and a leaf its own issuer marked unfit for signing are
 *     each refused with a distinct reason.
 *  5. **The key belongs to the leaf, and is usable by the signing path** — see
 *     {@link normalizeAndMatchPrivateKey}.
 *
 * @param options - see {@link CreateVerifierSigningMaterialOptions}.
 * @returns the validated material, ready to sign request objects with.
 * @throws InvalidConfigurationError naming which half of the configuration is
 * wrong. Never a domain error with a client-facing status: this is a bootstrap
 * misconfiguration, and a 500 with a server-side stack trace is the right signal.
 */
export function createVerifierSigningMaterial(
  options: CreateVerifierSigningMaterialOptions
): VerifierSigningMaterial {
  const now = options.now ?? new Date();

  if (options.certificateChainPems.length === 0) {
    throw new InvalidConfigurationError(
      'An OID4VP verifier signing key is configured but no certificate chain is (#377). A wallet establishes the Verifier identity from the x5c header of the signed request object, so a key with no chain identifies nobody.'
    );
  }

  const anchors = createX509TrustAnchors(options.trustAnchorPems, VERIFIER_ANCHOR_DESCRIPTOR);

  if (anchors.size === 0) {
    throw new InvalidConfigurationError(
      'An OID4VP verifier certificate chain is configured but no trust anchor is (#377). The chain must terminate at an anchor the operator names — in the EU the QTSP that issued the WRPAC — and a chain validated against nothing is a chain nobody vouched for.'
    );
  }

  const chain = options.certificateChainPems.map(parseChainCertificate);
  const x5c = Object.freeze(chain.map((certificate) => certificate.raw.toString('base64')));

  const resolution = resolveAnchoredSigningCertificate(x5c, anchors, now);

  if (resolution.outcome !== 'resolved') {
    throw new InvalidConfigurationError(
      'The OID4VP verifier certificate chain did not validate against the configured trust anchors (#377). Refusing to start rather than presenting a Verifier identity QAuth cannot prove. See this error\'s "details" for which check refused it.',
      { reason: resolution.reason }
    );
  }

  const accepted = normalizeAndMatchPrivateKey(options.privateKeyPem, resolution.leaf);

  return Object.freeze({
    privateKeyPem: accepted.pkcs8Pem,
    x5c,
    leafDer: resolution.leaf.raw,
    leafNotAfter: resolution.leaf.validToDate,
  });
}

/**
 * The marker set that describes real signing material (#377).
 *
 * `ProvisionedVerifierMaterial` and `VerifierSigningMaterial` answer the same
 * question at two layers — the boot gate needs "what kind of material exists",
 * the builder needs the bytes — and deriving the first from the second is what
 * stops a deployment declaring a capability it did not actually configure.
 *
 * Only `non-self-signed-chain` is declared, never `leaf-cert`. A validated chain
 * does contain a leaf, but `x509_san_dns` needs a leaf whose `dNSName` SAN
 * matches QAuth's own origin, and nothing here checks that — so claiming it
 * would provision a prefix on a certificate that may not identify this host at
 * all.
 *
 * @param material - the validated material, or `undefined` when none is configured.
 * @returns the marker set to hand the boot gate and the builder.
 */
export function verifierMaterialProvisionedBy(
  material: VerifierSigningMaterial | undefined
): ProvisionedVerifierMaterial {
  return material === undefined
    ? NO_VERIFIER_MATERIAL
    : Object.freeze({ available: Object.freeze(['non-self-signed-chain' as const]) });
}
