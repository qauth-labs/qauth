import {
  type HybridSignedToken,
  type HybridSigningKey,
  type HybridVerifyKey,
  signHybrid,
  verifyHybrid,
} from '@qauth-labs/core-crypto';

import type { SignAccessTokenPayload, SignIdTokenPayload } from '../types/jwt-service';
import { buildAccessTokenClaims, buildIdTokenClaims } from './jwt-service';

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
 */
export async function signHybridAccessToken(
  payload: SignAccessTokenPayload,
  keys: HybridSigningKey,
  issuer: string,
  expiresIn: number
): Promise<HybridSignedToken> {
  const { claims, audience } = buildAccessTokenClaims(payload);
  return signHybrid(claims, keys, { issuer, expiresIn, audience });
}

export async function signHybridIdToken(
  payload: SignIdTokenPayload,
  keys: HybridSigningKey,
  issuer: string,
  expiresIn: number
): Promise<HybridSignedToken> {
  const { claims, audience } = buildIdTokenClaims(payload);
  return signHybrid(claims, keys, { issuer, expiresIn, audience });
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
  options: { audience?: string | string[]; issuer?: string; requirePqc: boolean }
): Promise<Record<string, unknown>> {
  return verifyHybrid(hybrid, keys, {
    algorithms: ['EdDSA'],
    requirePqc: options.requirePqc,
    ...(options.issuer !== undefined ? { issuer: options.issuer } : {}),
    ...(options.audience !== undefined ? { audience: options.audience } : {}),
  });
}
