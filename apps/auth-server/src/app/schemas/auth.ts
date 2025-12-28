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
