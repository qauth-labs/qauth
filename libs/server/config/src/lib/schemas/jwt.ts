import { readFileSync } from 'node:fs';

import { z } from 'zod';

/**
 * Helper function to read key from file path
 */
function readKeyFromFile(filePath: string): string {
  try {
    const content = readFileSync(filePath, 'utf-8');
    return content.trim();
  } catch (error) {
    if (error instanceof Error) {
      if ('code' in error && error.code === 'ENOENT') {
        throw new Error(`JWT key file not found: ${filePath}`, { cause: error });
      }
      if ('code' in error && error.code === 'EACCES') {
        throw new Error(`Permission denied reading JWT key file: ${filePath}`, { cause: error });
      }
      throw new Error(`Failed to read JWT key file ${filePath}: ${error.message}`, {
        cause: error,
      });
    }
    throw error;
  }
}

/**
 * Helper function to resolve key from either file path or direct value
 * File paths take precedence over direct values for security and consistency
 */
function resolveKey(
  directKey: string | undefined,
  filePath: string | undefined
): string | undefined {
  // Prefer file path over direct key (for security and consistency with documentation)
  if (filePath) {
    const key = readKeyFromFile(filePath);
    // Ensure we don't return an empty key from a file
    if (key && key.length > 0) {
      return key;
    }
  }
  // Fallback to direct key if provided and not empty
  if (directKey && directKey.trim().length > 0) {
    return directKey.trim();
  }
  return undefined;
}

/**
 * JWT environment configuration schema
 * JWT token generation and validation settings
 *
 * Tokens are signed with each realm's keys in the encrypted key store (ADR-019
 * Decision 9, #491). The key variables are read only by the default realm's
 * key boot step, which imports a key the store lacks: at the first boot after
 * the upgrade, or to replace a stored key until rotation through the store
 * ships. All of them are optional; a fresh deployment without them generates
 * its keys.
 *
 * Supports both environment variables and file paths:
 * - JWT_PRIVATE_KEY or JWT_PRIVATE_KEY_PATH (both optional)
 * - JWT_PUBLIC_KEY or JWT_PUBLIC_KEY_PATH (both optional)
 */
export const jwtEnvSchema = z
  .object({
    /**
     * EdDSA private key in PEM format (optional). The key boot step imports it
     * into the default realm's key store when the store lacks it; tokens are
     * signed with the stored key.
     */
    JWT_PRIVATE_KEY: z.string().optional(),

    /**
     * Path to EdDSA private key file in PEM format (optional). Takes precedence
     * over JWT_PRIVATE_KEY.
     */
    JWT_PRIVATE_KEY_PATH: z.string().optional(),

    /**
     * EdDSA public key in PEM format (optional)
     * If not provided, can be derived from private key
     */
    JWT_PUBLIC_KEY: z.string().optional(),

    /**
     * Path to EdDSA public key file in PEM format (optional)
     * If not provided, can be derived from private key
     */
    JWT_PUBLIC_KEY_PATH: z.string().optional(),

    /**
     * RS256 (RSASSA-PKCS1-v1_5 + SHA-256) private key in PKCS#8 PEM (OPTIONAL,
     * #309). When provided, ID tokens are signed with RS256 by default and the
     * derived RSA public key is published in the JWKS — unblocking OIDC
     * Basic/Config OP certification (#286), which hard-fails an EdDSA-only OP.
     * Absent → EdDSA-only, exactly as before (backward compatible). Access
     * tokens are unaffected (always EdDSA).
     */
    JWT_RS256_PRIVATE_KEY: z.string().optional(),

    /**
     * Path to the RS256 private key file in PKCS#8 PEM (OPTIONAL, #309). Takes
     * precedence over {@link JWT_RS256_PRIVATE_KEY} (see {@link resolveKey}).
     */
    JWT_RS256_PRIVATE_KEY_PATH: z.string().optional(),

    /**
     * RS256 public key in SPKI PEM (OPTIONAL, #309). When omitted the public key
     * is derived from the RS256 private key (public material only). Provide only
     * when the private key is not available to this process.
     */
    JWT_RS256_PUBLIC_KEY: z.string().optional(),

    /**
     * Path to the RS256 public key file in SPKI PEM (OPTIONAL, #309).
     */
    JWT_RS256_PUBLIC_KEY_PATH: z.string().optional(),

    /**
     * Stable key identifier published in the RS256 RSA JWK `kid` (OPTIONAL,
     * #309). Recommended so the RSA entry carries a `kid` distinct from the
     * EdDSA key; distinctness is enforced at boot.
     */
    JWT_RS256_KID: z.string().optional(),

    /**
     * JWT issuer URL (required): the 'iss' claim in JWT tokens.
     *
     * A single-realm (simple mode) setting, with `DEFAULT_REALM_NAME` (ADR-019
     * Decision 1, #484). At first boot it becomes the default realm's issuer,
     * stored without a trailing slash, and its host becomes the realm's primary
     * host. Both are permanent: a later boot with a different value refuses to
     * start. A path keeps working, since only the host routes requests, and
     * the boot warns about it and about a trailing slash.
     */
    JWT_ISSUER: z.url('JWT issuer must be a valid URL'),

    /**
     * Access token expiration in seconds (default: 900 = 15 minutes).
     *
     * This is the `short` tier baseline used by the `staging` and `production`
     * environment profiles (ADR-008 §5, issue #197). The `development` profile
     * uses {@link DEV_ACCESS_TOKEN_LIFESPAN} instead so local tokens can be
     * long-lived for convenience without ever loosening production.
     */
    ACCESS_TOKEN_LIFESPAN: z.coerce.number().int().positive().default(900),

    /**
     * Access token expiration in seconds for the `development` environment
     * profile only (ADR-008 §5, issue #197 — the `long` lifespan tier). Default
     * 28800 = 8 hours: a comfortable local-dev session that never applies to a
     * `staging`/`production` client (their effective tier is always `short`,
     * resolved via `resolveEnvironmentPolicy`). FAIL-SAFE: a client whose
     * environment is unset resolves to `production` and therefore NEVER receives
     * this longer lifespan.
     */
    DEV_ACCESS_TOKEN_LIFESPAN: z.coerce
      .number()
      .int()
      .positive()
      .default(8 * 60 * 60),

    /**
     * Refresh token expiration in seconds (default: 604800 = 7 days)
     */
    REFRESH_TOKEN_LIFESPAN: z.coerce.number().int().positive().default(604800),
  })
  .transform((data) => {
    // Resolve the OPTIONAL private key: prefer file path, fallback to direct key.
    // Undefined when unconfigured: the key store holds the realm's keys.
    const privateKey = resolveKey(data.JWT_PRIVATE_KEY, data.JWT_PRIVATE_KEY_PATH);

    // Resolve public key: prefer file path, fallback to direct key
    const publicKey = resolveKey(data.JWT_PUBLIC_KEY, data.JWT_PUBLIC_KEY_PATH);

    // Resolve the OPTIONAL RS256 key pair (#309). Undefined when unconfigured,
    // which keeps the server EdDSA-only (backward compatible).
    const rs256PrivateKey = resolveKey(data.JWT_RS256_PRIVATE_KEY, data.JWT_RS256_PRIVATE_KEY_PATH);
    const rs256PublicKey = resolveKey(data.JWT_RS256_PUBLIC_KEY, data.JWT_RS256_PUBLIC_KEY_PATH);

    // Return resolved configuration
    return {
      JWT_PRIVATE_KEY: privateKey,
      JWT_PUBLIC_KEY: publicKey,
      JWT_RS256_PRIVATE_KEY: rs256PrivateKey,
      JWT_RS256_PUBLIC_KEY: rs256PublicKey,
      JWT_RS256_KID: data.JWT_RS256_KID,
      JWT_ISSUER: data.JWT_ISSUER,
      ACCESS_TOKEN_LIFESPAN: data.ACCESS_TOKEN_LIFESPAN,
      DEV_ACCESS_TOKEN_LIFESPAN: data.DEV_ACCESS_TOKEN_LIFESPAN,
      REFRESH_TOKEN_LIFESPAN: data.REFRESH_TOKEN_LIFESPAN,
    };
  });

/**
 * JWT environment configuration type
 */
export type JwtEnv = z.infer<typeof jwtEnvSchema>;
