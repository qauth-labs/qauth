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
 * `HYBRID_SIGNING_ENABLED` (#245, #275) turns on hybrid (Ed25519 + ML-DSA-65)
 * access-token issuance. Enabling it REQUIRES `SIGNING_ALGORITHM_MODE` =
 * `ed25519+ml-dsa-65` — enforced here at startup (fail-fast). The ML-DSA-65
 * key is the realm's, in its key store (ADR-019 Decision 9, #491): a fresh
 * deployment generates the pair, `JWT_MLDSA_PRIVATE_KEY` imports one, and the
 * key boot step refuses to start a realm whose active token keys are half a
 * pair. The coupled fields live in this ONE schema so the cross-check is
 * actually enforceable (separately-parsed schemas cannot see each other's
 * fields).
 *
 * `PQC_TOKEN_DELIVERY` (#247) names how the ML-DSA-65 component reaches a
 * verifier when hybrid is on. A hybrid token's detached ML-DSA-65 signature is
 * a fixed ~4412 base64url bytes (measured — see `server-jwt`'s
 * `token-size.bench.test.ts`); that alone exceeds a 4 KB cookie and a 2 KB URL,
 * and an inlined compound token (~5128 B) exceeds both. `reference`, the only
 * value, keeps the bearer token a plain ~716 B Ed25519 JWS and delivers the
 * PQC material out-of-band via RFC 7662 introspection (a POST body, no
 * header/cookie ceiling). `self-contained`, which would carry it with the
 * token, is refused until it is built (#875): the server never had a way to
 * deliver it, so accepting the value left the operator believing a setting
 * that changed nothing. `PQC_SELF_CONTAINED_ACK`, its acknowledgement, is a
 * removed key (`registry/removed.ts`).
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

/** FIPS 204 ML-DSA-65 seed (ξ) length in bytes — the canonical private form. */
const ML_DSA_65_SEED_BYTES = 32;

/** base64url alphabet, unpadded (RFC 4648 §5) — what `exportKey` emits. */
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

/**
 * Why a configured ML-DSA seed is unusable, or `null` when it is valid (#248 F8).
 *
 * The config layer previously checked only PRESENCE, so a truncated, padded, or
 * standard-base64 seed sailed through startup and failed much later — deep in
 * the crypto layer, at first signing, in production. Validating the DECODED
 * length here keeps the fail-fast promise the rest of this schema makes.
 *
 * `Buffer.from(_, 'base64url')` is lenient (it silently ignores characters
 * outside the alphabet and truncates a trailing partial group), so the alphabet
 * is checked explicitly BEFORE decoding — otherwise `"AAAA...!!"` would decode
 * to a plausible-looking 32 bytes.
 */
function describeInvalidMlDsaSeed(seed: string): string | null {
  if (!BASE64URL_PATTERN.test(seed)) {
    return 'it is not unpadded base64url (allowed characters: A-Z a-z 0-9 - _; no "=" padding, no "+" or "/")';
  }
  const decoded = Buffer.from(seed, 'base64url');
  if (decoded.length !== ML_DSA_65_SEED_BYTES) {
    return `it decodes to ${decoded.length} bytes, expected exactly ${ML_DSA_65_SEED_BYTES}`;
  }
  return null;
}

/**
 * Why a `PQC_TOKEN_DELIVERY` other than `reference` stops the boot (#875).
 * `self-contained` was accepted once, behind `PQC_SELF_CONTAINED_ACK`, and
 * changed nothing: the server always delivered by reference.
 */
const PQC_TOKEN_DELIVERY_REFUSAL =
  "PQC_TOKEN_DELIVERY must be 'reference': introspection returns a hybrid token's ML-DSA-65 signature as pqc_signature. 'self-contained', which would carry the signature with the token, is not built. Unset PQC_TOKEN_DELIVERY or set it to 'reference'.";

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
     * `reference`, the only value: the bearer stays a small Ed25519 JWS, the
     * signature is stored under the token's `jti`, and introspection returns
     * it as `pqc_signature`. Any other value stops the boot (#875).
     */
    PQC_TOKEN_DELIVERY: z
      .enum(['reference'], { error: PQC_TOKEN_DELIVERY_REFUSAL })
      .default('reference'),
  })
  .superRefine((data, ctx) => {
    // #248 F8: a CONFIGURED seed must be well-formed whether or not hybrid is
    // on — a deployment that stages the key before flipping the flag should
    // learn about a bad seed now, not at the moment it enables PQC signing.
    // The seed value itself is NEVER echoed into the issue message.
    const configuredSeed = resolveMlDsaSeed(
      data.JWT_MLDSA_PRIVATE_KEY,
      data.JWT_MLDSA_PRIVATE_KEY_PATH
    );
    if (configuredSeed !== undefined) {
      const problem = describeInvalidMlDsaSeed(configuredSeed);
      if (problem !== null) {
        ctx.addIssue({
          code: 'custom',
          path: [
            data.JWT_MLDSA_PRIVATE_KEY_PATH
              ? 'JWT_MLDSA_PRIVATE_KEY_PATH'
              : 'JWT_MLDSA_PRIVATE_KEY',
          ],
          message: `The ML-DSA-65 private key must be a base64url-encoded ${ML_DSA_65_SEED_BYTES}-byte seed, but ${problem}.`,
        });
      }
    }

    if (!data.HYBRID_SIGNING_ENABLED) return;
    // The switch describes what the deployment's signer issues, so every
    // process of a hybrid deployment sets it, whatever its roles (#495): a
    // process without the signer verifies hybrid tokens with the realm's
    // published ML-DSA-65 keys (#491), and answers 503 when asked to sign.
    if (data.SIGNING_ALGORITHM_MODE !== 'ed25519+ml-dsa-65') {
      ctx.addIssue({
        code: 'custom',
        path: ['SIGNING_ALGORITHM_MODE'],
        message: "HYBRID_SIGNING_ENABLED=true requires SIGNING_ALGORITHM_MODE='ed25519+ml-dsa-65'.",
      });
    }
    // No ML-DSA-65 variable is required (#491): the realm's key store holds
    // the hybrid pair, a fresh deployment generates it, and the key boot step
    // refuses to start a realm whose active token keys are half a pair.
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
      // #247: the PQC delivery, always `reference` (#875). Only meaningful
      // when hybrid is on; a classical (Ed25519-only) deployment has no PQC
      // component to deliver.
      PQC_TOKEN_DELIVERY: data.PQC_TOKEN_DELIVERY,
      enabledSignatureAlgorithms,
    };
  });

/** Crypto / signing environment configuration type. */
export type CryptoEnv = z.infer<typeof cryptoEnvSchema>;
