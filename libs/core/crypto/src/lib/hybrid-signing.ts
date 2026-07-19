import type { SignatureAlgorithm } from './algorithms';
import { getSignatureBackend } from './backend-registry';
import { CryptoVerificationError } from './errors';
import {
  PQC_ALG_ML_DSA_65,
  PQC_HEADER_ALG_MEMBER,
  PQC_HEADER_KID_MEMBER,
} from './hybrid-constants';
import type { MlDsaKey, SigningKey } from './keys';
import { sign, type SignOptions, type VerifyOptions, verifyWithHeader } from './signing';

/**
 * Hybrid PQC signing (ADR-005, #245): a DETACHED PARALLEL signature combining a
 * classical Ed25519 signature (compatibility) with an ML-DSA-65 signature
 * (forward security).
 *
 * ## Wire shape (the compatibility guarantee)
 *
 * A hybrid token IS an ordinary Ed25519 compact JWS produced by the existing
 * {@link sign} path — a stock JOSE verifier validates `token` byte-for-byte and
 * ignores the extra NON-critical `pqc_alg`/`pqc_kid` protected-header members
 * (#245 AC#2: classical-only verifiers keep working with zero changes). The
 * ML-DSA-65 signature covers the IDENTICAL JWS signing-input and is carried
 * ALONGSIDE in {@link HybridSignedToken.pqcSignature}, NEVER inside the compact
 * string. A PQC-capable verifier checks both components.
 *
 * ## What this is NOT
 *
 * This deliberately deviates from the strict single-alg-id + concatenated
 * composite of the LAMPS / `draft-ietf-jose-pq-composite-sigs` line of drafts
 * (which a stock verifier cannot parse,
 * violating AC#2). A CLASSICAL verifier cannot be forced to reject a stripped
 * token, because `pqc_alg` must stay non-critical for it to keep working.
 *
 * A PQC-AWARE verifier, however, does not get that latitude: since #275 (#248
 * finding F1) {@link verifyHybrid} treats a PRESENT, Ed25519-SIGNED `pqc_alg`
 * as BINDING — the detached signature must then be present and valid
 * regardless of the `requirePqc` flag. Downgrade resistance is therefore an
 * ISSUER-SIGNED control on this code path, not a per-call policy toggle;
 * `requirePqc` only governs tokens whose issuer made no PQC assertion at all.
 */
export interface HybridSigningKey {
  /** Classical Ed25519 private key (existing JWT signing key). */
  ed: SigningKey;
  /** ML-DSA-65 private key (#243 backend / #244 native). */
  mlDsa: MlDsaKey;
  /** Optional classical key id, stamped into the protected header. */
  edKid?: string;
  /** Optional ML-DSA key id, stamped as `pqc_kid` for JWKS resolution (#246). */
  mlDsaKid?: string;
}

/**
 * Resolves the ML-DSA-65 public key to verify with, from the key id the ISSUER
 * SIGNED into the `pqc_kid` protected-header member (#248 F5).
 *
 * The argument is always the value read from the Ed25519-verified protected
 * header — never an unauthenticated transport field — so an attacker cannot
 * steer verification at a key of their choosing. Return `undefined` when the
 * kid is unknown; {@link verifyHybrid} then fails closed.
 *
 * @param signedPqcKid - Verified `pqc_kid`, or `undefined` when the issuer
 *   stamped no key id (single-active-key deployments).
 */
export type MlDsaKeyResolver = (
  signedPqcKid: string | undefined
) => MlDsaKey | undefined | Promise<MlDsaKey | undefined>;

export interface HybridVerifyKey {
  /** Classical Ed25519 public key. */
  ed: SigningKey;
  /**
   * ML-DSA-65 public key, or a {@link MlDsaKeyResolver} invoked with the SIGNED
   * `pqc_kid`. Pass a resolver whenever more than one ML-DSA key may be active
   * (rotation, multi-issuer JWKS); a bare key is the single-active-key case.
   */
  mlDsa: MlDsaKey | MlDsaKeyResolver;
}

/**
 * The operator-enabled signature algorithms (`SIGNING_ALGORITHM_MODE`, threaded
 * from `cryptoEnv.enabledSignatureAlgorithms`) that gate the PQC component.
 *
 * REQUIRED, never defaulted (#248 F7/F11): the hybrid path previously reached
 * for the noble backend directly, which both bypassed the operator allowlist —
 * a deployment running `SIGNING_ALGORITHM_MODE=ed25519` would still emit ML-DSA
 * signatures — and made the native backend unreachable. Routing through
 * {@link getSignatureBackend} makes the allowlist authoritative and lets a
 * registered native backend serve the same call sites.
 */
export interface PqcBackendSelection {
  /** Operator-enabled algorithms; `ML-DSA-65` must be among them. */
  enabledSignatureAlgorithms: readonly SignatureAlgorithm[];
}

export interface HybridSignedToken {
  /** The classical Ed25519 compact JWS — a complete, stock-verifiable token. */
  token: string;
  /** base64url detached ML-DSA-65 signature over `token`'s JWS signing-input. */
  pqcSignature: string;
  /**
   * The parallel PQC algorithm (`ML-DSA-65`). This is an UNAUTHENTICATED
   * transport hint: {@link verifyHybrid} cross-checks it against the signed
   * `pqc_alg` protected-header member and rejects on mismatch. Never use it to
   * negotiate an algorithm on its own.
   *
   * There is deliberately NO `pqcKid` companion field (#248 F5): a key id that
   * drives key resolution must come from the signed header, so carrying an
   * unsigned copy would only invite misuse.
   */
  pqcAlg: typeof PQC_ALG_ML_DSA_65;
}

/**
 * The JWS signing-input of a compact JWS: the `base64url(header).base64url(payload)`
 * prefix (RFC 7515 §5.1) as UTF-8 bytes — the EXACT preimage the JWS signature
 * covers. Both the Ed25519 and ML-DSA signatures sign this, so any header/payload
 * mutation breaks both and neither can be swapped.
 */
export function extractJwsSigningInput(compactJws: string): Uint8Array {
  const lastDot = compactJws.lastIndexOf('.');
  if (lastDot <= 0) {
    throw new CryptoVerificationError('invalid', { detail: 'not a compact JWS' });
  }
  return new TextEncoder().encode(compactJws.slice(0, lastDot));
}

/**
 * Produce a hybrid-signed token: an Ed25519 compact JWS with `kid`/`pqc_alg`/
 * `pqc_kid` in its (signed) protected header, plus a detached ML-DSA-65
 * signature over the same signing-input.
 */
export async function signHybrid(
  claims: Record<string, unknown>,
  keys: HybridSigningKey,
  options: SignOptions & PqcBackendSelection
): Promise<HybridSignedToken> {
  // Resolve BEFORE signing: a disabled ML-DSA-65 must abort the whole
  // operation, never leave a classical-only token behind as a silent downgrade.
  const backend = getSignatureBackend('ML-DSA-65', options.enabledSignatureAlgorithms);
  const header: Record<string, unknown> = {
    [PQC_HEADER_ALG_MEMBER]: PQC_ALG_ML_DSA_65,
  };
  if (keys.edKid !== undefined) header['kid'] = keys.edKid;
  if (keys.mlDsaKid !== undefined) header[PQC_HEADER_KID_MEMBER] = keys.mlDsaKid;

  const token = await sign(claims, keys.ed, 'EdDSA', { ...options, header });
  const signingInput = extractJwsSigningInput(token);
  const pqcSignature = Buffer.from(backend.sign(keys.mlDsa, signingInput)).toString('base64url');

  // The key id is deliberately NOT echoed as an unsigned transport field: the
  // authoritative copy is the `pqc_kid` member inside the Ed25519-signed
  // protected header, which is what verifyHybrid resolves keys from (#248 F5).
  return { token, pqcSignature, pqcAlg: PQC_ALG_ML_DSA_65 };
}

/**
 * Verify a hybrid token. Always verifies the classical Ed25519 component
 * (`token`), then applies the PQC policy below and returns the verified claims.
 *
 * ## Downgrade resistance is ISSUER-SIGNED (#248 F1)
 *
 * Every PQC decision is driven by the Ed25519-AUTHENTICATED protected header,
 * never by the unsigned transport fields of {@link HybridSignedToken}:
 *
 * - **Signed `pqc_alg` present** → BINDING, irrespective of `requirePqc`. The
 *   detached signature MUST be present and valid, and `hybrid.pqcAlg` must
 *   match the signed value. Stripping `pqcSignature` off such a token is
 *   rejected even with `requirePqc: false` — an attacker cannot strip their way
 *   back to classical-only.
 * - **No signed `pqc_alg`** → the issuer asserted nothing post-quantum. With
 *   `requirePqc: true` the token is rejected; otherwise it verifies as an
 *   ordinary Ed25519 token. Any attached `pqcSignature` is IGNORED, because
 *   nothing the issuer signed vouches for it.
 *
 * The ML-DSA key is resolved from the signed `pqc_kid` (#248 F5) when the
 * caller supplies a {@link MlDsaKeyResolver}.
 *
 * @throws CryptoVerificationError if the classical component fails, if a signed
 * PQC assertion is unsatisfied (absent/mismatched/invalid signature), if no
 * ML-DSA key resolves for the signed `pqc_kid`, or if `requirePqc` is set on a
 * token carrying no signed PQC assertion.
 */
export async function verifyHybrid(
  hybrid: HybridSignedToken,
  keys: HybridVerifyKey,
  options: VerifyOptions & PqcBackendSelection & { requirePqc: boolean }
): Promise<Record<string, unknown>> {
  // 1. Classical Ed25519 — covers the header (incl. pqc_alg/pqc_kid) + payload.
  //    `algorithms` is pinned AFTER the spread so a caller cannot inject `none`.
  const { claims, protectedHeader } = await verifyWithHeader(hybrid.token, keys.ed, {
    ...options,
    algorithms: ['EdDSA'],
  });

  // 2. Read the issuer's PQC assertion from the AUTHENTICATED header only.
  const signedPqcAlg = protectedHeader[PQC_HEADER_ALG_MEMBER];
  const hasPqcSignature = typeof hybrid.pqcSignature === 'string' && hybrid.pqcSignature.length > 0;

  if (signedPqcAlg === undefined) {
    // No issuer-signed PQC assertion. An attached signature is unvouched-for,
    // so it can neither be trusted nor satisfy a `requirePqc` policy.
    if (options.requirePqc) {
      throw new CryptoVerificationError('invalid', {
        detail: 'PQC signature required but the signed header asserts no pqc_alg',
      });
    }
    return claims;
  }

  // From here the issuer SIGNED a PQC assertion: it is binding.
  if (signedPqcAlg !== PQC_ALG_ML_DSA_65) {
    throw new CryptoVerificationError('invalid', {
      detail: `unsupported signed pqc_alg: ${String(signedPqcAlg)}`,
    });
  }
  if (!hasPqcSignature) {
    throw new CryptoVerificationError('invalid', {
      detail: 'signed pqc_alg present but PQC signature absent (downgrade attempt)',
    });
  }
  // Cross-check the unsigned transport hint against the signed truth: they must
  // agree, so a mismatched hint can never route verification elsewhere.
  if (hybrid.pqcAlg !== signedPqcAlg) {
    throw new CryptoVerificationError('invalid', {
      detail: 'pqcAlg does not match the signed pqc_alg header',
    });
  }

  // 3. Resolve the ML-DSA key from the SIGNED pqc_kid (#248 F5).
  const signedPqcKid = protectedHeader[PQC_HEADER_KID_MEMBER];
  if (signedPqcKid !== undefined && typeof signedPqcKid !== 'string') {
    throw new CryptoVerificationError('invalid', {
      detail: 'signed pqc_kid is not a string',
    });
  }
  const mlDsaKey = typeof keys.mlDsa === 'function' ? await keys.mlDsa(signedPqcKid) : keys.mlDsa;
  if (mlDsaKey === undefined) {
    throw new CryptoVerificationError('invalid', {
      detail: 'no ML-DSA-65 key resolved for the signed pqc_kid',
    });
  }

  const signingInput = extractJwsSigningInput(hybrid.token);
  const signatureBytes = new Uint8Array(Buffer.from(hybrid.pqcSignature, 'base64url'));
  // Throws CryptoVerificationError('invalid') on any failure.
  // The cross product of #275 and #276: the key comes from the SIGNED pqc_kid
  // (F5), and the backend from the operator allowlist (F7/F11). Taking either
  // branch's line alone silently drops the other's control.
  getSignatureBackend('ML-DSA-65', options.enabledSignatureAlgorithms).verify(
    mlDsaKey,
    signingInput,
    signatureBytes
  );

  return claims;
}
