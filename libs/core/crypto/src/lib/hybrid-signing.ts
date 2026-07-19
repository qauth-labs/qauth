import type { SignatureAlgorithm } from './algorithms';
import { getSignatureBackend } from './backend-registry';
import { CryptoVerificationError } from './errors';
import {
  PQC_ALG_ML_DSA_65,
  PQC_HEADER_ALG_MEMBER,
  PQC_HEADER_KID_MEMBER,
} from './hybrid-constants';
import type { MlDsaKey, SigningKey } from './keys';
import { sign, type SignOptions, verify, type VerifyOptions } from './signing';

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
 * violating AC#2). Downgrade resistance within a single bearer token is
 * therefore a VERIFIER-POLICY concern (`requirePqc`), not cryptographic — the
 * `pqc_alg` member must be non-critical to keep classical verifiers working, so
 * it cannot force rejection. Documented for the #248 security review.
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

export interface HybridVerifyKey {
  /** Classical Ed25519 public key. */
  ed: SigningKey;
  /** ML-DSA-65 public key. */
  mlDsa: MlDsaKey;
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
  /** The parallel PQC algorithm (`ML-DSA-65`); mirrors the `pqc_alg` header. */
  pqcAlg: typeof PQC_ALG_ML_DSA_65;
  /** The ML-DSA key id, if configured (for JWKS resolution, #246). */
  pqcKid?: string;
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

  return {
    token,
    pqcSignature,
    pqcAlg: PQC_ALG_ML_DSA_65,
    ...(keys.mlDsaKid !== undefined ? { pqcKid: keys.mlDsaKid } : {}),
  };
}

/**
 * Verify a hybrid token. Always verifies the classical Ed25519 component
 * (`token`) via the stock {@link verify}. The ML-DSA-65 component is verified
 * when present; with `requirePqc: true` an absent or invalid PQC signature is
 * rejected. Returns the verified claims.
 *
 * @throws CryptoVerificationError if either verified component fails, or if
 * `requirePqc` is set and the PQC signature is missing.
 */
export async function verifyHybrid(
  hybrid: HybridSignedToken,
  keys: HybridVerifyKey,
  options: VerifyOptions & PqcBackendSelection & { requirePqc: boolean }
): Promise<Record<string, unknown>> {
  // 1. Classical Ed25519 — covers the header (incl. pqc_alg/pqc_kid) + payload.
  const claims = await verify(hybrid.token, keys.ed, { ...options, algorithms: ['EdDSA'] });

  // 2. PQC component.
  const hasPqc = typeof hybrid.pqcSignature === 'string' && hybrid.pqcSignature.length > 0;
  if (!hasPqc) {
    if (options.requirePqc) {
      throw new CryptoVerificationError('invalid', {
        detail: 'PQC signature required but absent (possible downgrade)',
      });
    }
    return claims;
  }

  if (hybrid.pqcAlg !== PQC_ALG_ML_DSA_65) {
    throw new CryptoVerificationError('invalid', {
      detail: `unsupported pqc_alg: ${String(hybrid.pqcAlg)}`,
    });
  }
  const signingInput = extractJwsSigningInput(hybrid.token);
  const signatureBytes = new Uint8Array(Buffer.from(hybrid.pqcSignature, 'base64url'));
  // Throws CryptoVerificationError('invalid') on any failure.
  getSignatureBackend('ML-DSA-65', options.enabledSignatureAlgorithms).verify(
    keys.mlDsa,
    signingInput,
    signatureBytes
  );

  return claims;
}
