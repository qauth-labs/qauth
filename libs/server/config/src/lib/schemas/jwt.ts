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
        throw new Error(`JWT key file not found: ${filePath}`);
      }
      if ('code' in error && error.code === 'EACCES') {
        throw new Error(`Permission denied reading JWT key file: ${filePath}`);
      }
      throw new Error(`Failed to read JWT key file ${filePath}: ${error.message}`);
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
    return readKeyFromFile(filePath);
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
 * Supports both environment variables and file paths:
 * - JWT_PRIVATE_KEY or JWT_PRIVATE_KEY_PATH (one required)
 * - JWT_PUBLIC_KEY or JWT_PUBLIC_KEY_PATH (both optional)
 */
export const jwtEnvSchema = z
  .object({
    /**
     * EdDSA private key in PEM format (optional if JWT_PRIVATE_KEY_PATH is provided)
     * Used to sign JWT tokens
     */
    JWT_PRIVATE_KEY: z.string().optional(),

    /**
     * Path to EdDSA private key file in PEM format (optional if JWT_PRIVATE_KEY is provided)
     * Used to sign JWT tokens
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
     * JWT issuer URL (required)
     * Used as the 'iss' claim in JWT tokens
     */
    JWT_ISSUER: z.url('JWT issuer must be a valid URL'),

    /**
     * Access token expiration in seconds (default: 900 = 15 minutes)
     */
    ACCESS_TOKEN_LIFESPAN: z.coerce.number().int().positive().default(900),

    /**
     * Refresh token expiration in seconds (default: 604800 = 7 days)
     */
    REFRESH_TOKEN_LIFESPAN: z.coerce.number().int().positive().default(604800),
  })
  .superRefine((data, ctx) => {
    // Validate that at least one private key source is provided
    const hasPrivateKey = data.JWT_PRIVATE_KEY && data.JWT_PRIVATE_KEY.trim().length > 0;
    const hasPrivateKeyPath = !!data.JWT_PRIVATE_KEY_PATH;

    if (!hasPrivateKey && !hasPrivateKeyPath) {
      ctx.addIssue({
        code: 'custom',
        message:
          'JWT private key is required. Provide either JWT_PRIVATE_KEY or JWT_PRIVATE_KEY_PATH',
        path: ['JWT_PRIVATE_KEY'],
      });
    }
  })
  .transform((data) => {
    // Resolve private key: prefer file path, fallback to direct key
    const privateKey = resolveKey(data.JWT_PRIVATE_KEY, data.JWT_PRIVATE_KEY_PATH);

    // Private key is guaranteed to be defined after superRefine validation
    if (!privateKey) {
      throw new Error(
        'JWT private key is required. Provide either JWT_PRIVATE_KEY or JWT_PRIVATE_KEY_PATH'
      );
    }

    // Resolve public key only if private key exists: prefer file path, fallback to direct key
    const publicKey = resolveKey(data.JWT_PUBLIC_KEY, data.JWT_PUBLIC_KEY_PATH);

    // Return resolved configuration
    return {
      JWT_PRIVATE_KEY: privateKey,
      JWT_PUBLIC_KEY: publicKey,
      JWT_ISSUER: data.JWT_ISSUER,
      ACCESS_TOKEN_LIFESPAN: data.ACCESS_TOKEN_LIFESPAN,
      REFRESH_TOKEN_LIFESPAN: data.REFRESH_TOKEN_LIFESPAN,
    };
  });

/**
 * JWT environment configuration type
 */
export type JwtEnv = z.infer<typeof jwtEnvSchema>;
