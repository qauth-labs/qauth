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
 * Registration response type (user data without password_hash)
 */
export interface RegisterResponse {
  id: string;
  email: string;
  emailVerified: boolean;
  realmId: string;
  createdAt: number;
  updatedAt: number | null;
}
