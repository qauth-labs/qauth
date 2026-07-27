/**
 * TEST SUPPORT — a working OID4VCI Appendix D key attestation issuer (#308).
 *
 * Lives in `testing/`, OUTSIDE `src/`, for the reason `sd-jwt-vc.fixture.ts`
 * states and `src/test-support-boundary.test.ts` enforces: this module mints
 * real, correctly-signed attestations under a real certificate chain, so
 * leaving it next to the validator it exists to attack would put an attestation
 * minter one careless import away from the package's shipped source.
 *
 * ## Why real certificates and real signatures
 *
 * Every rejection path #308 has is only reachable by producing an attestation
 * that is CORRECT in every respect but one — a genuine ES256 signature under a
 * self-signed certificate, a valid chain that happens to carry the anchor, an
 * impeccable attestation over somebody else's key. A recorded fixture cannot be
 * bent that way without also breaking its signature, which would make several
 * different tests all pass for the same uninteresting reason.
 *
 * The certificate factory itself is `src/status/test/x509-fixtures.ts`, reused
 * rather than duplicated: #297 already needed exactly this (P-256 keys,
 * `ecdsa-with-SHA256`, `basicConstraints`, `keyUsage`) and a second DER encoder
 * would be a second thing to get subtly wrong.
 */

import { CompactSign, type JWK } from 'jose';

import {
  createKeyAttestationTrustAnchors,
  KEY_ATTESTATION_TYP,
  type KeyAttestationTrustAnchors,
} from '../src/attestation/key-attestation';
import {
  createTestCertificate,
  type TestCertificate,
  type TestKeyUsage,
} from '../src/status/test/x509-fixtures';

/** A wallet-provider PKI: an anchor, an issuing CA under it, and a signing leaf. */
export interface KeyAttestationPki {
  /** The trust anchor. NEVER included in an `x5c` header (HAIP §4.5.1). */
  readonly root: TestCertificate;
  /** The issuing CA the attestation signer sits under. */
  readonly intermediate: TestCertificate;
  /** The end-entity certificate that signs attestations. */
  readonly leaf: TestCertificate;
  /** The compiled anchor set a resolver is configured with. */
  readonly anchors: KeyAttestationTrustAnchors;
}

/** Inputs for {@link createKeyAttestationPki}. */
export interface CreateKeyAttestationPkiOptions {
  /** `keyUsage` bits on the signing leaf; omit for an unconstrained one. */
  readonly leafKeyUsage?: readonly TestKeyUsage[];
  /** Validity window of the signing leaf, for the expired-certificate cases. */
  readonly leafNotBefore?: Date;
  readonly leafNotAfter?: Date;
}

/** Build a two-tier wallet-provider PKI. */
export function createKeyAttestationPki(
  options: CreateKeyAttestationPkiOptions = {}
): KeyAttestationPki {
  const root = createTestCertificate({
    subject: 'Wallet Provider Root CA',
    ca: true,
    keyUsage: ['keyCertSign', 'cRLSign'],
  });

  const intermediate = createTestCertificate({
    subject: 'Wallet Provider Issuing CA',
    issuer: root,
    ca: true,
    keyUsage: ['keyCertSign', 'cRLSign'],
  });

  const leaf = createTestCertificate({
    subject: 'Wallet Provider Key Attestation Signer',
    issuer: intermediate,
    keyUsage: options.leafKeyUsage ?? ['digitalSignature'],
    ...(options.leafNotBefore === undefined ? {} : { notBefore: options.leafNotBefore }),
    ...(options.leafNotAfter === undefined ? {} : { notAfter: options.leafNotAfter }),
  });

  return {
    root,
    intermediate,
    leaf,
    anchors: createKeyAttestationTrustAnchors([root.pem]),
  };
}

/** What {@link issueKeyAttestation} may vary. Defaults validate cleanly. */
export interface IssueKeyAttestationOptions {
  /** The public keys this attestation attests. */
  readonly attestedKeys: readonly JWK[];
  /** `key_storage` levels (OID4VCI Appendix D §D.2). */
  readonly keyStorage?: readonly string[];
  /** `user_authentication` levels. */
  readonly userAuthentication?: readonly string[];
  readonly iat?: number;
  readonly exp?: number;
  /** JOSE `typ`; override to test cross-token confusion. */
  readonly typ?: string;
  /** JOSE `alg`; override to test algorithm pinning. */
  readonly alg?: string;
  /** The certificate whose key signs; defaults to the PKI's leaf. */
  readonly signer?: TestCertificate;
  /** The `x5c` chain to present; defaults to `[leaf, intermediate]`. */
  readonly x5c?: readonly string[];
  /** Merged into the payload last. */
  readonly payloadOverrides?: Record<string, unknown>;
  /** Merged into the protected header last. */
  readonly headerOverrides?: Record<string, unknown>;
}

/**
 * Play the WALLET PROVIDER: sign an Appendix D key attestation.
 *
 * @param pki - the provider PKI the attestation chains under.
 * @param options - what to attest and how to bend it.
 * @returns the compact JWS, ready to hand to the validator.
 */
export async function issueKeyAttestation(
  pki: KeyAttestationPki,
  options: IssueKeyAttestationOptions
): Promise<string> {
  const signer = options.signer ?? pki.leaf;
  const nowSeconds = Math.floor(Date.now() / 1000);

  const payload: Record<string, unknown> = {
    iss: 'https://wallet-provider.example',
    iat: options.iat ?? nowSeconds,
    attested_keys: options.attestedKeys,
    ...(options.exp === undefined ? {} : { exp: options.exp }),
    ...(options.keyStorage === undefined ? {} : { key_storage: options.keyStorage }),
    ...(options.userAuthentication === undefined
      ? {}
      : { user_authentication: options.userAuthentication }),
    ...(options.payloadOverrides ?? {}),
  };

  return new CompactSign(Buffer.from(JSON.stringify(payload), 'utf8'))
    .setProtectedHeader({
      alg: options.alg ?? 'ES256',
      typ: options.typ ?? KEY_ATTESTATION_TYP,
      x5c: [...(options.x5c ?? [signer.x5c, pki.intermediate.x5c])],
      ...(options.headerOverrides ?? {}),
    })
    .sign(signer.keys.privateKey);
}
