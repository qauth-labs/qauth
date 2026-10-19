import { passwordSchema } from '@qauth-labs/shared-validation';
import { z } from 'zod';

import { boundedEmail } from './common';

/**
 * Registration request schema
 */
export const registerSchema = z.object({
  // Every request `email` is bounded at 254 characters before its format check.
  email: boundedEmail('Invalid email format'),
  password: passwordSchema,
  realmId: z.uuid('Invalid realm ID format').optional(),
});

/**
 * Registration request type
 */
export type RegisterRequest = z.infer<typeof registerSchema>;

/**
 * Registration response schema (`202 Accepted`).
 *
 * Every address gets this same body, whether a new account was created or the
 * address already had one (ANT-2026-SPEMY9GU). It therefore carries nothing
 * that could differ between the two: no user id, no timestamps, no "created"
 * flag. What happens next arrives by email.
 */
export const registerResponseSchema = z.object({
  message: z.string(),
});

/**
 * Registration response type
 */
export type RegisterResponse = z.infer<typeof registerResponseSchema>;

/**
 * Email verification request body schema (POST /auth/verify)
 * Token must be a 64-character hex string (256-bit random value). The password
 * is the one chosen at registration: the token proves the mailbox, the password
 * proves the registrant, and verification needs both to be the same person.
 */
export const verifyBodySchema = z.object({
  token: z
    .string()
    .length(64, 'Token must be exactly 64 characters')
    .regex(/^[0-9a-fA-F]{64}$/, 'Token must be a valid hex string'),
  password: passwordSchema.min(1),
});

/**
 * Email verification request body type
 */
export type VerifyBody = z.infer<typeof verifyBodySchema>;

/**
 * Email verification response schema
 */
export const verifyResponseSchema = z.object({
  message: z.string(),
  email: z.email(),
});

/**
 * Email verification response type
 */
export type VerifyResponse = z.infer<typeof verifyResponseSchema>;

/**
 * Resend verification request schema
 */
export const resendVerificationSchema = z.object({
  // Counted in Redis for every request, account or not, so it is bounded.
  email: boundedEmail('Invalid email format'),
});

/**
 * Resend verification request type
 */
export type ResendVerificationRequest = z.infer<typeof resendVerificationSchema>;

/**
 * Resend verification response schema
 */
export const resendVerificationResponseSchema = z.object({
  message: z.string(),
});

/**
 * Resend verification response type
 */
export type ResendVerificationResponse = z.infer<typeof resendVerificationResponseSchema>;

/**
 * Login request schema
 */
export const loginSchema = z.object({
  // A refused sign-in writes the address to `audit_logs`, so it is bounded.
  email: boundedEmail('Invalid email format'),
  // Bounded like registration: Argon2id verification hashes every byte, so an
  // unbounded field is attacker-sized CPU work on the login path too.
  password: passwordSchema,
});

/**
 * Login request type
 */
export type LoginRequest = z.infer<typeof loginSchema>;

/**
 * Login response schema
 */
export const loginResponseSchema = z.object({
  access_token: z.string(),
  refresh_token: z.string(),
  expires_in: z.number(),
  token_type: z.literal('Bearer'),
});

/**
 * Login response type
 */
export type LoginResponse = z.infer<typeof loginResponseSchema>;

/**
 * Logout request headers schema
 * Validates Authorization header format
 */
export const logoutHeadersSchema = z.object({
  authorization: z
    .string()
    .regex(/^Bearer .+$/, 'Authorization header must be in format: Bearer <token>'),
});

/**
 * Logout request headers type
 */
export type LogoutHeaders = z.infer<typeof logoutHeadersSchema>;

/**
 * Logout response schema
 */
export const logoutResponseSchema = z.object({
  success: z.literal(true),
  message: z.literal('Successfully logged out'),
});

/**
 * Logout response type
 */
export type LogoutResponse = z.infer<typeof logoutResponseSchema>;
