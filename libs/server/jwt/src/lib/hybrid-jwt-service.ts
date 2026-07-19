import {
  type HybridSignedToken,
  type HybridSigningKey,
  type HybridVerifyKey,
  type PqcBackendSelection,
  signHybrid,
  verifyHybrid,
} from '@qauth-labs/core-crypto';

import type { SignAccessTokenPayload, SignIdTokenPayload } from '../types/jwt-service';
import {
  ACCESS_TOKEN_TYP,
  buildAccessTokenClaims,
  buildIdTokenClaims,
  ID_TOKEN_TYP,
} from './jwt-service';

/**
 * Hybrid (Ed25519 + ML-DSA-65) JWT signing wrappers (ADR-005, #245).
 *
 * These reuse the EXACT claim shaping of the classical {@link signAccessToken} /
 * {@link signIdToken} (via the shared `buildAccessTokenClaims` /
 * `buildIdTokenClaims`) and return a {@link HybridSignedToken}: an ordinary
 * Ed25519 compact JWS (`.token`) plus a detached ML-DSA-65 signature
 * (`.pqcSignature`). Classical verifiers validate `.token` unmodified.
 *
 * This is a CAPABILITY + integration point (#245 scope): it is NOT wired into
 * the live auth-server token routes, and the classical signers are unchanged.
 * HTTP delivery of `pqcSignature` (reference-token vs inline) is #247; JWKS
 * publication of the ML-DSA key is #246; enable-by-default awaits the #248
 * security review (flag `HYBRID_SIGNING_ENABLED`, default off).
 *
 * Every entry point takes a {@link PqcBackendSelection} carrying the operator's
 * `enabledSignatureAlgorithms` (#248 F7/F11). It is a REQUIRED parameter, not a
 * defaulted one: the ML-DSA backend must be resolved through the
 * `SIGNING_ALGORITHM_MODE` allowlist at every call site, so a deployment that
 * has not enabled ML-DSA-65 cannot produce or accept a PQC component.
 */
export async function signHybridAccessToken(
  payload: SignAccessTokenPayload,
  keys: HybridSigningKey,
  issuer: string,
  expiresIn: number,
  backend: PqcBackendSelection
): Promise<HybridSignedToken> {
  const { claims, audience } = buildAccessTokenClaims(payload);
  // #283: `typ` must be stamped on the hybrid path too, or a deployment that
  // flips `HYBRID_SIGNING_ENABLED` on would silently start minting access
  // tokens a `typ`-enforcing resource server rejects. It rides in the same
  // Ed25519-SIGNED protected header as `pqc_alg`/`pqc_kid` (ADR-005) and is
  // non-critical, so classical verifiers are unaffected.
  return signHybrid(claims, keys, {
    issuer,
    expiresIn,
    audience,
    typ: ACCESS_TOKEN_TYP,
    ...backend,
  });
}

export async function signHybridIdToken(
  payload: SignIdTokenPayload,
  keys: HybridSigningKey,
  issuer: string,
  expiresIn: number,
  backend: PqcBackendSelection
): Promise<HybridSignedToken> {
  const { claims, audience } = buildIdTokenClaims(payload);
  return signHybrid(claims, keys, {
    issuer,
    expiresIn,
    audience,
    typ: ID_TOKEN_TYP,
    ...backend,
  });
}

/**
 * Verify a hybrid access token: the classical Ed25519 component always, and the
 * ML-DSA-65 component when `requirePqc` (or when a PQC signature is present).
 * Returns the verified claims. The live verify path stays classical-only for
 * #245; this is the tested capability #249 promotes into introspection/mcp-guard.
 */
export async function verifyHybridAccessToken(
  hybrid: HybridSignedToken,
  keys: HybridVerifyKey,
  options: PqcBackendSelection & {
    audience?: string | string[];
    issuer?: string;
    requirePqc: boolean;
  }
): Promise<Record<string, unknown>> {
  return verifyHybrid(hybrid, keys, {
    algorithms: ['EdDSA'],
    requirePqc: options.requirePqc,
    enabledSignatureAlgorithms: options.enabledSignatureAlgorithms,
    ...(options.issuer !== undefined ? { issuer: options.issuer } : {}),
    ...(options.audience !== undefined ? { audience: options.audience } : {}),
  });
}
