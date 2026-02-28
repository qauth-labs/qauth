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

/**
 * Token introspection request body (POST /oauth/introspect).
 * RFC 7662 2.1. Uses application/x-www-form-urlencoded in transport.
 */
export const introspectRequestSchema = z.object({
  token: z.string().min(1),
  token_type_hint: z.string().max(64).optional(),
  client_id: z.string().min(1),
  client_secret: z.string().min(1),
});

export type IntrospectRequest = z.infer<typeof introspectRequestSchema>;

/**
 * Token introspection response body.
 * RFC 7662 2.2.
 */
export const introspectResponseSchema = z.object({
  active: z.boolean(),
  sub: z.string().optional(),
  client_id: z.string().optional(),
  exp: z.number().optional(),
  iat: z.number().optional(),
  iss: z.string().optional(),
  token_type: z.literal('Bearer').optional(),
});

export type IntrospectResponse = z.infer<typeof introspectResponseSchema>;

/**
 * OIDC userinfo response schema (GET /userinfo).
 * Returns selected claims for the authenticated end-user.
 */
export const userinfoResponseSchema = z.object({
  sub: z.string().min(1),
  email: z.email(),
  email_verified: z.boolean(),
});

export type UserinfoResponse = z.infer<typeof userinfoResponseSchema>;
