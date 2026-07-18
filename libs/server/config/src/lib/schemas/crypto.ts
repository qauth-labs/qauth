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
 * `PQC_TOKEN_DELIVERY` (#247) selects how the ML-DSA-65 component reaches a
 * verifier when hybrid is on. A hybrid token's detached ML-DSA-65 signature is
 * a fixed ~4412 base64url bytes (measured — see `server-jwt`'s
 * `token-size.bench.test.ts`); that alone exceeds a 4 KB cookie and a 2 KB URL,
 * and an inlined compound token (~5128 B) exceeds both. `reference` (the
 * DEFAULT) keeps the bearer token a plain ~716 B Ed25519 JWS and delivers the
 * PQC material out-of-band via RFC 7662 introspection (a POST body, no
 * header/cookie ceiling). `self-contained` is allowed ONLY with an explicit
 * `PQC_SELF_CONTAINED_ACK=true`, so no deployment can SILENTLY ship tokens that
 * blow header/cookie limits (ADR-005 / #247 AC#3).
 *
 * FAIL-SAFE DEFAULTS: `ed25519`, hybrid off, `reference` delivery — post-quantum
 * is strictly opt-in and size-safe by default.
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
    /**
     * How the PQC (ML-DSA-65) component is delivered when hybrid is on (#247).
     * `reference` (default) → introspection-first, bearer stays a small Ed25519
     * JWS. `self-contained` → the operator intends to carry the ~4.4 KB PQC
     * material with the token; permitted only alongside `PQC_SELF_CONTAINED_ACK`.
     */
    PQC_TOKEN_DELIVERY: z.enum(['reference', 'self-contained']).default('reference'),
    /**
     * Explicit acknowledgement that `self-contained` PQC delivery ships a
     * ~4.4 KB detached signature that exceeds cookie/URL budgets and must only
     * run over large-buffer request headers (#247 AC#3). Required to select
     * `self-contained`; ignored otherwise.
     */
    PQC_SELF_CONTAINED_ACK: z
      .enum(['true', 'false', '1', '0'])
      .default('false')
      .transform((v) => v === 'true' || v === '1'),
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
    // #247 AC#3: self-contained hybrid tokens carry a ~4.4 KB detached ML-DSA
    // signature that overflows cookie/URL budgets — never let a deployment pick
    // it silently. Reference/introspection delivery is the safe default.
    if (data.PQC_TOKEN_DELIVERY === 'self-contained' && !data.PQC_SELF_CONTAINED_ACK) {
      ctx.addIssue({
        code: 'custom',
        path: ['PQC_TOKEN_DELIVERY'],
        message:
          "PQC_TOKEN_DELIVERY='self-contained' ships a ~4.4 KB detached ML-DSA-65 signature that exceeds 4 KB cookie and 2 KB URL limits. Set PQC_SELF_CONTAINED_ACK=true to confirm a large-buffer header-only delivery channel, or use the default PQC_TOKEN_DELIVERY='reference' (introspection).",
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
      // #247: effective PQC delivery. Only meaningful when hybrid is on; a
      // classical (Ed25519-only) deployment issues small self-contained JWTs and
      // has no PQC component to deliver, so the field is reported as-is for
      // observability but drives nothing until hybrid issuance is wired.
      PQC_TOKEN_DELIVERY: data.PQC_TOKEN_DELIVERY,
      enabledSignatureAlgorithms,
    };
  });

/** Crypto / signing environment configuration type. */
export type CryptoEnv = z.infer<typeof cryptoEnvSchema>;
