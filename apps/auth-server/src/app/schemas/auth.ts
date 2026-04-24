import { z } from 'zod';

/**
 * Registration request schema
 */
export const registerSchema = z.object({
  email: z.email('Invalid email format'),
  password: z.string(),
  realmId: z.uuid('Invalid realm ID format').optional(),
});

/**
 * Registration request type
 */
export type RegisterRequest = z.infer<typeof registerSchema>;

/**
 * Registration response schema (user data without password_hash)
 */
export const registerResponseSchema = z.object({
  id: z.uuid(),
  email: z.email(),
  emailVerified: z.boolean(),
  realmId: z.uuid(),
  createdAt: z.number(),
  updatedAt: z.number().nullable(),
});

/**
 * Registration response type (user data without password_hash)
 */
export type RegisterResponse = z.infer<typeof registerResponseSchema>;

/**
 * Email verification query parameter schema
 * Token must be a 64-character hex string (256-bit random value)
 */
export const verifyQuerySchema = z.object({
  token: z
    .string()
    .length(64, 'Token must be exactly 64 characters')
    .regex(/^[0-9a-fA-F]{64}$/, 'Token must be a valid hex string'),
});

/**
 * Email verification query parameter type
 */
export type VerifyQuery = z.infer<typeof verifyQuerySchema>;

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
  email: z.email('Invalid email format'),
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
  email: z.email('Invalid email format'),
  password: z.string(),
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
