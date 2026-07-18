import { readFileSync } from 'node:fs';

import type { SignatureAlgorithm } from '@qauth-labs/core-crypto';
import { z } from 'zod';

/**
 * Crypto / signing environment configuration (ADR-005, #243 + #245).
 *
 * `SIGNING_ALGORITHM_MODE` (#243) is the runtime algorithm-selection flag —
 * both the classical Ed25519 path and the ML-DSA-65 backend are compiled in,
 * and this decides which are ENABLED at runtime.
 *
 * `HYBRID_SIGNING_ENABLED` (#245) turns on hybrid (Ed25519 + ML-DSA-65)
 * signing CAPABILITY. It is a CAPABILITY flag: with it on, jwt-service can
 * produce hybrid tokens, but the live auth-server token routes and verify path
 * are unchanged until the JWKS (#246), token-size (#247), and security-review
 * (#248) work lands. Enabling it REQUIRES `SIGNING_ALGORITHM_MODE` =
 * `ed25519+ml-dsa-65` AND a configured ML-DSA private key — enforced at
 * startup (fail-fast). All three coupled fields live in this ONE schema so the
 * cross-check is actually enforceable (separately-parsed schemas cannot see
 * each other's fields).
 *
 * FAIL-SAFE DEFAULTS: `ed25519`, hybrid off — post-quantum is strictly opt-in.
 */
function resolveMlDsaSeed(directValue?: string, filePath?: string): string | undefined {
  if (filePath) {
    const fromFile = readFileSync(filePath, 'utf-8').trim();
    if (fromFile.length > 0) return fromFile;
  }
  if (directValue && directValue.trim().length > 0) return directValue.trim();
  return undefined;
}

export const cryptoEnvSchema = z
  .object({
    SIGNING_ALGORITHM_MODE: z.enum(['ed25519', 'ed25519+ml-dsa-65']).default('ed25519'),
    HYBRID_SIGNING_ENABLED: z
      .enum(['true', 'false', '1', '0'])
      .default('false')
      .transform((v) => v === 'true' || v === '1'),
    /** ML-DSA-65 private key as a base64url 32-byte seed (#243 export form). */
    JWT_MLDSA_PRIVATE_KEY: z.string().optional(),
    /** Path to a file containing the base64url ML-DSA-65 seed. */
    JWT_MLDSA_PRIVATE_KEY_PATH: z.string().optional(),
    /** Key id for the ML-DSA key, published as `pqc_kid` / in JWKS (#246). */
    JWT_MLDSA_KID: z.string().optional(),
  })
  .superRefine((data, ctx) => {
    if (!data.HYBRID_SIGNING_ENABLED) return;
    if (data.SIGNING_ALGORITHM_MODE !== 'ed25519+ml-dsa-65') {
      ctx.addIssue({
        code: 'custom',
        path: ['SIGNING_ALGORITHM_MODE'],
        message: "HYBRID_SIGNING_ENABLED=true requires SIGNING_ALGORITHM_MODE='ed25519+ml-dsa-65'.",
      });
    }
    if (
      resolveMlDsaSeed(data.JWT_MLDSA_PRIVATE_KEY, data.JWT_MLDSA_PRIVATE_KEY_PATH) === undefined
    ) {
      ctx.addIssue({
        code: 'custom',
        path: ['JWT_MLDSA_PRIVATE_KEY'],
        message:
          'HYBRID_SIGNING_ENABLED=true requires an ML-DSA key: set JWT_MLDSA_PRIVATE_KEY or JWT_MLDSA_PRIVATE_KEY_PATH.',
      });
    }
  })
  .transform((data) => {
    const enabledSignatureAlgorithms: readonly SignatureAlgorithm[] =
      data.SIGNING_ALGORITHM_MODE === 'ed25519+ml-dsa-65'
        ? (['EdDSA', 'ML-DSA-65'] as const)
        : (['EdDSA'] as const);
    return {
      SIGNING_ALGORITHM_MODE: data.SIGNING_ALGORITHM_MODE,
      HYBRID_SIGNING_ENABLED: data.HYBRID_SIGNING_ENABLED,
      JWT_MLDSA_PRIVATE_KEY: resolveMlDsaSeed(
        data.JWT_MLDSA_PRIVATE_KEY,
        data.JWT_MLDSA_PRIVATE_KEY_PATH
      ),
      JWT_MLDSA_KID: data.JWT_MLDSA_KID,
      enabledSignatureAlgorithms,
    };
  });

/** Crypto / signing environment configuration type. */
export type CryptoEnv = z.infer<typeof cryptoEnvSchema>;
