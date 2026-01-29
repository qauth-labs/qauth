import { z } from 'zod';

/**
 * OAuth 2.1 authorize query parameters (GET /oauth/authorize).
 * RFC 6749 4.1.1, RFC 7636 PKCE.
 */
export const authorizeQuerySchema = z.object({
  response_type: z.literal('code'),
  client_id: z.string().min(1),
  redirect_uri: z.url(),
  code_challenge: z
    .string()
    .min(43)
    .max(128)
    .regex(/^[A-Za-z0-9._~-]+$/),
  code_challenge_method: z.literal('S256'),
  state: z.string().max(255).optional(),
  scope: z.string().optional(),
  nonce: z.string().max(255).optional(),
});

export type AuthorizeQuery = z.infer<typeof authorizeQuerySchema>;

/**
 * OAuth 2.1 token exchange body (POST /oauth/token, authorization_code grant).
 * RFC 6749 4.1.3, RFC 7636 PKCE. client_secret_post (MVP).
 */
export const tokenExchangeBodySchema = z.object({
  grant_type: z.literal('authorization_code'),
  code: z.string().min(1),
  redirect_uri: z.string().min(1),
  client_id: z.string().min(1),
  code_verifier: z
    .string()
    .min(43)
    .max(128)
    .regex(/^[A-Za-z0-9._~-]+$/),
  client_secret: z.string().min(1),
});

export type TokenExchangeBody = z.infer<typeof tokenExchangeBodySchema>;

/**
 * OAuth token response (same shape as login/refresh).
 * RFC 6749 5.1.
 */
export const tokenExchangeResponseSchema = z.object({
  access_token: z.string(),
  refresh_token: z.string(),
  expires_in: z.number(),
  token_type: z.literal('Bearer'),
});

export type TokenExchangeResponse = z.infer<typeof tokenExchangeResponseSchema>;
