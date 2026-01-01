import { z } from 'zod';

/**
 * Error response schema (matches error handler output)
 */
export const errorResponseSchema = z.object({
  error: z.string(),
  statusCode: z.number(),
});

/**
 * Error response type
 */
export type ErrorResponse = z.infer<typeof errorResponseSchema>;
