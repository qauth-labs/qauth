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
  .transform((data) => {
    // Resolve private key: prefer direct key, fallback to file path
    let privateKey: string | undefined;
    if (data.JWT_PRIVATE_KEY && data.JWT_PRIVATE_KEY.trim().length > 0) {
      privateKey = data.JWT_PRIVATE_KEY.trim();
    } else if (data.JWT_PRIVATE_KEY_PATH) {
      privateKey = readKeyFromFile(data.JWT_PRIVATE_KEY_PATH);
    }

    // Validate private key is provided
    if (!privateKey || privateKey.length === 0) {
      throw new Error(
        'JWT private key is required. Provide either JWT_PRIVATE_KEY or JWT_PRIVATE_KEY_PATH'
      );
    }

    // Resolve public key: prefer direct key, fallback to file path
    let publicKey: string | undefined;
    if (data.JWT_PUBLIC_KEY && data.JWT_PUBLIC_KEY.trim().length > 0) {
      publicKey = data.JWT_PUBLIC_KEY.trim();
    } else if (data.JWT_PUBLIC_KEY_PATH) {
      publicKey = readKeyFromFile(data.JWT_PUBLIC_KEY_PATH);
    }

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
