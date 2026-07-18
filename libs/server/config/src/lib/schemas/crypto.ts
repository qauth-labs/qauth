import type { SignatureAlgorithm } from '@qauth-labs/core-crypto';
import { z } from 'zod';

/**
 * Crypto / signing environment configuration (ADR-005, #243).
 *
 * `SIGNING_ALGORITHM_MODE` is the runtime algorithm-selection flag: both the
 * classical Ed25519 path and the post-quantum ML-DSA-65 backend are compiled
 * in, and this env var decides which are ENABLED at runtime (no compile-time
 * lock-in). It gates the CAPABILITY (ML-DSA-65 key generation / signing /
 * verification via the byte-level signature backend), NOT token issuance —
 * QAuth does not yet emit ML-DSA-signed JWTs (no finalized JOSE `alg`; the JWS
 * carrier is #245, JWKS publication is #246, and token-size / introspection
 * posture is #247). Turning ML-DSA on here is safe and produces zero change to
 * issued tokens until those land.
 *
 * FAIL-SAFE DEFAULT: `ed25519` (classical only) — post-quantum is strictly
 * opt-in, so an unconfigured deployment is unaffected.
 */
export const cryptoEnvSchema = z
  .object({
    SIGNING_ALGORITHM_MODE: z.enum(['ed25519', 'ed25519+ml-dsa-65']).default('ed25519'),
  })
  .transform((data) => {
    const enabledSignatureAlgorithms: readonly SignatureAlgorithm[] =
      data.SIGNING_ALGORITHM_MODE === 'ed25519+ml-dsa-65'
        ? (['EdDSA', 'ML-DSA-65'] as const)
        : (['EdDSA'] as const);
    return {
      SIGNING_ALGORITHM_MODE: data.SIGNING_ALGORITHM_MODE,
      enabledSignatureAlgorithms,
    };
  });

/** Crypto / signing environment configuration type. */
export type CryptoEnv = z.infer<typeof cryptoEnvSchema>;
