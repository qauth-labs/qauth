import { timingSafeEqual } from 'node:crypto';

import { importPublicSigningKey, verifyWithHeader } from '@qauth-labs/core-crypto';
import { calculateJwkThumbprint, type JWK } from 'jose';

import type { X509TrustAnchors } from '../x509/anchored-chain';
import {
  createX509TrustAnchors,
  NO_X509_TRUST_ANCHORS,
  resolveAnchoredSigningCertificate,
} from '../x509/anchored-chain';
import { type AttackPotentialResistance, reduceAttackPotentialClaim } from './attack-potential';
import type { KeyStorageAssuranceRejectionReason } from './key-storage-assurance-rejection';

/**
 * OID4VCI Appendix D key attestation validation (issue #308, HAIP §4.5.1).
 *
 * ## Read this before assuming a Verifier is supposed to do any of it
 *
 * A key attestation is an ISSUANCE artifact. The normative mandate lives at the
 * OID4VCI Credential Endpoint, where an Issuer validates the wallet's
 * attestation before issuing; nothing in HAIP §5–§6 asks a Verifier to request
 * or validate one on the presentation path. `attesting-issuers.ts` explains why
 * that makes the TRANSITIVE path the primary one and this module the secondary.
 *
 * This module exists because some ecosystems do surface an attestation to the
 * Verifier, and #308's answer is a validation seam for that case rather than an
 * invented handshake for the general one. Where nothing is conveyed, nothing
 * here runs.
 *
 * ## What HAIP §4.5.1 states about the chain, verbatim
 *
 * > - The public key used to validate the signature on the key attestation MUST
 * >   be included in the `x5c` JOSE header of the key attestation
 * > - The X.509 certificate of the trust anchor MUST NOT be included in the
 * >   `x5c` JOSE header of the key attestation.
 * > - The X.509 certificate signing the key attestation MUST NOT be self-signed.
 * > - The X.509 certificate profiles to be used are out of scope of this
 * >   specification.
 *
 * All three prohibitions are enforced by {@link resolveAnchoredSigningCertificate},
 * which enforces the same three for the Status List Token (HAIP §6.1.1). The
 * fourth line is why nothing here inspects certificate policies or subject
 * naming: the profile is the operator's, and the anchor set is where the
 * operator expresses it.
 *
 * Anchoring is added on top of the three, and is not optional even though HAIP
 * does not spell it out: "MUST NOT include the trust anchor" is only meaningful
 * against a trust anchor that exists, and an attestation validated against an
 * unanchored chain proves nothing at all — anyone can mint a CA and attest their
 * own software key with it.
 *
 * ## The order of operations is the security property
 *
 * Exactly the order `status/status-list-token.ts` documents, for exactly the
 * same reason: the header that says which key signed the token is itself part
 * of the token, so it is used ONLY to nominate a key, the nomination is
 * constrained to anchored certificates, and nothing else is read until the
 * signature has verified. `typ` is then re-read from the AUTHENTICATED header —
 * it is the member that stops any other JWS the wallet provider's key ever
 * signed from being replayed here as a key attestation (RFC 8725 §3.11).
 *
 * ## The `cnf` binding is the check that makes the rest worth anything
 *
 * A key attestation is not addressed to QAuth, carries no audience, and is not
 * bound to this presentation. It is a statement about a key. So an attacker who
 * obtains ANY genuine attestation — captured, published by a wallet vendor, or
 * their own for a real hardware key — can attach it to a credential bound to a
 * software key they fully control, and every check above still passes. The only
 * thing that closes it is proving that a key the attestation attests IS the key
 * the credential is bound to, which #234 has already made the presenter
 * demonstrate possession of. That comparison is {@link attestsKey}, and removing
 * it would leave a validator that carefully verifies a certificate chain in
 * order to learn nothing.
 *
 * @see https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
 *   Appendix D (Key Attestation), §D.2 (Attack Potential Resistance)
 * @see https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html
 *   §4.5.1 (Key Attestation), §9.2 (Interoperable Key Attestations)
 */

/** The media type an Appendix D key attestation declares (`typ`). */
export const KEY_ATTESTATION_TYP = 'key-attestation+jwt';

/**
 * The only JWS algorithm a key attestation may use.
 *
 * HAIP §7 mandates ES256 at minimum and the `haip-1.0` profile declares nothing
 * else, so pinning it here is the profile's own floor rather than an extra
 * restriction — and it is what the anchored-chain resolver already assumes when
 * it demands an EC P-256 leaf key. A caller-supplied allowlist would be the
 * usual shape, but there is nothing to choose between: widening it would mean
 * accepting a signature the profile does not permit.
 */
const REQUIRED_KEY_ATTESTATION_ALG = 'ES256';

/** Longest attestation accepted, in bytes. */
const MAX_KEY_ATTESTATION_BYTES = 32 * 1024;

/** Longest protected header accepted, in base64url characters. */
const MAX_PROTECTED_HEADER_LENGTH = 16 * 1024;

/**
 * Upper bound on `attested_keys`.
 *
 * A DoS guard, not a spec limit. Batch issuance legitimately attests many keys
 * at once, and every entry costs a thumbprint computation on an unauthenticated
 * path, so the array is bounded before it is walked.
 */
const MAX_ATTESTED_KEYS = 64;

/**
 * Anchors a conveyed key attestation's `x5c` chain must terminate at.
 *
 * Structurally the shared {@link X509TrustAnchors}, aliased under a
 * name that says WHOSE certificates these are: wallet-provider CAs, which have
 * nothing to do with the credential issuers of #236 or the status issuers of
 * #297. Sharing one anchor set across those roles would let a status issuer's CA
 * attest hardware, which is not a claim it ever made.
 */
export type KeyAttestationTrustAnchors = X509TrustAnchors;

/** A key-attestation anchor set that trusts nothing, refusing every attestation. */
export const NO_KEY_ATTESTATION_TRUST_ANCHORS: KeyAttestationTrustAnchors = NO_X509_TRUST_ANCHORS;

/** How a malformed key-attestation anchor names itself to an operator. */
const KEY_ATTESTATION_ANCHOR_DESCRIPTOR = Object.freeze({
  noun: 'key attestation trust anchor',
  issue: '#308',
});

/**
 * Compile operator-supplied PEM certificates into a key-attestation anchor set.
 *
 * A malformed anchor throws loudly (an OPERATOR error) rather than being
 * dropped: dropping one would leave the operator believing a wallet provider is
 * anchored when it is not, which surfaces as every user of that wallet failing
 * to reach the assurance their credential carries. The offending value goes on
 * `details`, never into the message.
 *
 * @param pems - PEM-encoded X.509 certificates; may be empty.
 * @returns a frozen anchor set.
 * @throws InvalidConfigurationError when an entry is not a parseable
 * certificate.
 */
export function createKeyAttestationTrustAnchors(
  pems: readonly string[]
): KeyAttestationTrustAnchors {
  return createX509TrustAnchors(pems, KEY_ATTESTATION_ANCHOR_DESCRIPTOR);
}

/** The assurance an Appendix D attestation established. */
export interface ValidatedKeyAttestation {
  /**
   * The resistance level attested for the component STORING the key — the WSCD
   * question. Absent when the attestation carried no `key_storage` claim.
   */
  readonly keyStorage?: AttackPotentialResistance;
  /**
   * The resistance level attested for the USER AUTHENTICATION gating use of the
   * key. Reported separately because it answers a different question; #237 may
   * weigh it, this module never conflates it with {@link keyStorage}.
   */
  readonly userAuthentication?: AttackPotentialResistance;
}

/** Outcome of {@link validateKeyAttestation}. Never a thrown error. */
export type KeyAttestationValidation =
  | { readonly outcome: 'validated'; readonly attestation: ValidatedKeyAttestation }
  | { readonly outcome: 'rejected'; readonly reason: KeyStorageAssuranceRejectionReason };

/** Inputs for {@link validateKeyAttestation}. */
export interface ValidateKeyAttestationOptions {
  /** The conveyed attestation, as a compact JWS. Unverified and untrusted. */
  readonly attestation: unknown;
  /**
   * The credential's holder-binding key — `cnf.jwk`, exactly as #234 read it
   * from the issuer-signed payload.
   *
   * Consumed here and never returned: OID4VP §15.5–§15.6 treat holder key
   * material as a linkability defect and ADR-009 forbids keying an account on
   * it, so it may be COMPARED and must not be surfaced.
   */
  readonly confirmationJwk: JWK;
  /** Anchors the attestation's `x5c` chain must terminate at. */
  readonly anchors: KeyAttestationTrustAnchors;
  /** Reference time for every validity window. */
  readonly now: Date;
  /** Clock skew tolerance in seconds applied to `exp`/`nbf`/`iat`. */
  readonly clockToleranceSeconds?: number;
}

/** Reject anything that is not a plain JSON object. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Decode the protected header WITHOUT verifying anything.
 *
 * Attacker-controlled in full. Used for exactly two things — nominating a key
 * and pinning `alg` — and every member is re-read from the authenticated header
 * afterwards.
 */
function decodeUnverifiedProtectedHeader(token: string): Record<string, unknown> | undefined {
  const firstDot = token.indexOf('.');
  if (firstDot <= 0) return undefined;

  // A compact JWS has exactly three segments. Anything else is not one, and
  // counting here means the verifier is never handed a JWE or a flattened JSON
  // serialization to be confused by.
  if (token.split('.').length !== 3) return undefined;

  const encoded = token.slice(0, firstDot);
  if (encoded.length > MAX_PROTECTED_HEADER_LENGTH) return undefined;
  if (!/^[A-Za-z0-9_-]+$/.test(encoded)) return undefined;

  try {
    const parsed: unknown = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    return isRecord(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

/** Compare two thumbprints without an early-exit branch on content. */
function constantTimeEquals(left: string, right: string): boolean {
  const a = Buffer.from(left, 'utf8');
  const b = Buffer.from(right, 'utf8');
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/**
 * Whether any key the attestation attests IS the credential's `cnf` key.
 *
 * Compared by RFC 7638 JWK thumbprint rather than member-by-member: the
 * thumbprint is computed over the canonical required members only, so two
 * encodings of the same key (different `kid`, `alg`, `use`, member order, or an
 * extra member a wallet added) compare equal, while any difference in the key
 * ITSELF does not. A structural comparison would have to decide which members
 * matter, and every wrong answer to that question is either a false rejection
 * of a legitimate wallet or a false acceptance of a different key.
 *
 * A key whose thumbprint cannot be computed — wrong `kty`, missing members,
 * not an object — is skipped rather than treated as a match. If the CREDENTIAL's
 * key is the unusable one, no attested key can match it and the whole
 * attestation is refused, which is the fail-closed outcome.
 */
async function attestsKey(
  attestedKeys: readonly unknown[],
  confirmationJwk: JWK
): Promise<boolean> {
  let expected: string;
  try {
    expected = await calculateJwkThumbprint(confirmationJwk);
  } catch {
    return false;
  }

  for (const candidate of attestedKeys) {
    if (!isRecord(candidate)) continue;

    let actual: string;
    try {
      actual = await calculateJwkThumbprint(candidate as JWK);
    } catch {
      continue;
    }

    if (constantTimeEquals(actual, expected)) return true;
  }

  return false;
}

/**
 * Validate a conveyed OID4VCI Appendix D key attestation (#308).
 *
 * Never throws: every failure is a `rejected` outcome carrying a server-side
 * reason. A throw here would become a 500 for an attacker-supplied document and
 * would make failure modes distinguishable by response code — the exact
 * enumeration `key-storage-assurance-rejection.ts` exists to prevent.
 *
 * @param options - see {@link ValidateKeyAttestationOptions}.
 * @returns the attested levels, or the reason the attestation was refused.
 */
export async function validateKeyAttestation(
  options: ValidateKeyAttestationOptions
): Promise<KeyAttestationValidation> {
  const { attestation, confirmationJwk, anchors, now } = options;

  if (typeof attestation !== 'string' || attestation.length === 0) {
    return { outcome: 'rejected', reason: 'attestation-malformed' };
  }
  if (Buffer.byteLength(attestation, 'utf8') > MAX_KEY_ATTESTATION_BYTES) {
    return { outcome: 'rejected', reason: 'attestation-malformed' };
  }

  const unverifiedHeader = decodeUnverifiedProtectedHeader(attestation);
  if (unverifiedHeader === undefined) {
    return { outcome: 'rejected', reason: 'attestation-malformed' };
  }
  if (unverifiedHeader['alg'] !== REQUIRED_KEY_ATTESTATION_ALG) {
    return { outcome: 'rejected', reason: 'attestation-malformed' };
  }

  const chain = resolveAnchoredSigningCertificate(unverifiedHeader['x5c'], anchors, now);
  if (chain.outcome === 'rejected') {
    // HAIP §4.5.1 names two of these prohibitions explicitly, so they keep their
    // own server-side reasons: an operator debugging a wallet ecosystem needs to
    // know which sentence of the profile its attestation violates. Everything
    // else — no path to an anchor, a broken link, an expired certificate, an
    // unusable leaf key — is one outcome, because they are all "this chain does
    // not reach anything this deployment anchors".
    switch (chain.reason) {
      case 'self-signed-leaf':
        return { outcome: 'rejected', reason: 'attestation-certificate-self-signed' };
      case 'anchor-in-chain':
        return { outcome: 'rejected', reason: 'attestation-anchor-in-chain' };
      case 'malformed-x5c':
        return { outcome: 'rejected', reason: 'attestation-malformed' };
      default:
        return { outcome: 'rejected', reason: 'attestation-chain-unanchored' };
    }
  }

  let claims: Record<string, unknown>;
  let protectedHeader: Record<string, unknown>;
  try {
    const key = await importPublicSigningKey(chain.publicKeyPem, REQUIRED_KEY_ATTESTATION_ALG);
    const verified = await verifyWithHeader(attestation, key, {
      algorithms: [REQUIRED_KEY_ATTESTATION_ALG],
      currentDate: now,
      ...(options.clockToleranceSeconds !== undefined
        ? { clockTolerance: options.clockToleranceSeconds }
        : {}),
    });
    claims = verified.claims;
    protectedHeader = verified.protectedHeader;
  } catch {
    // Bad signature, expired attestation, unusable key — one outcome,
    // deliberately.
    return { outcome: 'rejected', reason: 'attestation-signature-invalid' };
  }

  // Re-read from the AUTHENTICATED header. The header decoded above is
  // attacker-controlled and was only ever a key nomination.
  if (protectedHeader['typ'] !== KEY_ATTESTATION_TYP) {
    return { outcome: 'rejected', reason: 'attestation-malformed' };
  }

  if (!isRecord(claims)) {
    return { outcome: 'rejected', reason: 'attestation-malformed' };
  }

  // Appendix D makes `iat` mandatory. Enforced because an attestation with no
  // issuance time cannot be reasoned about for freshness at all, and because a
  // `jwtVerify` that saw no temporal claim would have checked nothing.
  const issuedAt = claims['iat'];
  if (typeof issuedAt !== 'number' || !Number.isFinite(issuedAt)) {
    return { outcome: 'rejected', reason: 'attestation-malformed' };
  }

  const toleranceSeconds = options.clockToleranceSeconds ?? 0;
  if (issuedAt - toleranceSeconds > Math.floor(now.getTime() / 1000)) {
    return { outcome: 'rejected', reason: 'attestation-signature-invalid' };
  }

  const attestedKeys = claims['attested_keys'];
  if (
    !Array.isArray(attestedKeys) ||
    attestedKeys.length === 0 ||
    attestedKeys.length > MAX_ATTESTED_KEYS
  ) {
    return { outcome: 'rejected', reason: 'attestation-malformed' };
  }

  if (!(await attestsKey(attestedKeys, confirmationJwk))) {
    return { outcome: 'rejected', reason: 'attested-key-mismatch' };
  }

  const keyStorage = reduceAttackPotentialClaim(claims['key_storage']);
  const userAuthentication = reduceAttackPotentialClaim(claims['user_authentication']);

  return {
    outcome: 'validated',
    attestation: Object.freeze({
      ...(keyStorage === undefined ? {} : { keyStorage }),
      ...(userAuthentication === undefined ? {} : { userAuthentication }),
    }),
  };
}
