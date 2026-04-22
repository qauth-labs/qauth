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
 *
 * `client_id` / `client_secret` are optional here because OAuth 2.1 also
 * accepts `client_secret_basic` via the HTTP `Authorization: Basic ...`
 * header. The route handler enforces that at least one auth method is used.
 */
export const tokenExchangeAuthCodeBodySchema = z.object({
  grant_type: z.literal('authorization_code'),
  code: z.string().min(1),
  redirect_uri: z.string().min(1),
  client_id: z.string().min(1).optional(),
  code_verifier: z
    .string()
    .min(43)
    .max(128)
    .regex(/^[A-Za-z0-9._~-]+$/),
  client_secret: z.string().min(1).optional(),
});

/**
 * OAuth 2.1 client credentials grant body (POST /oauth/token).
 * RFC 6749 4.4. Used for machine-to-machine authentication.
 * `scope` is optional and space-separated.
 */
export const tokenExchangeClientCredsBodySchema = z.object({
  grant_type: z.literal('client_credentials'),
  client_id: z.string().min(1).optional(),
  client_secret: z.string().min(1).optional(),
  scope: z.string().optional(),
});

/**
 * Discriminated union of supported token grant bodies.
 */
export const tokenExchangeBodySchema = z.discriminatedUnion('grant_type', [
  tokenExchangeAuthCodeBodySchema,
  tokenExchangeClientCredsBodySchema,
]);

export type TokenExchangeAuthCodeBody = z.infer<typeof tokenExchangeAuthCodeBodySchema>;
export type TokenExchangeClientCredsBody = z.infer<typeof tokenExchangeClientCredsBodySchema>;
export type TokenExchangeBody = z.infer<typeof tokenExchangeBodySchema>;

/**
 * OAuth token response.
 * RFC 6749 5.1. `refresh_token` and `scope` are optional (client_credentials
 * grants MUST NOT include refresh_token per RFC 6749 4.4.3).
 */
export const tokenExchangeResponseSchema = z.object({
  access_token: z.string(),
  refresh_token: z.string().optional(),
  expires_in: z.number(),
  token_type: z.literal('Bearer'),
  scope: z.string().optional(),
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
  aud: z.union([z.string(), z.array(z.string())]).optional(),
  scope: z.string().optional(),
  token_type: z.literal('Bearer').optional(),
});

export type IntrospectResponse = z.infer<typeof introspectResponseSchema>;

/**
 * OIDC userinfo response schema (GET /userinfo).
 * Returns selected claims for the authenticated end-user.
 */
export const userinfoResponseSchema = z.object({
  sub: z.string().min(1),
  email: z.email().optional(),
  email_verified: z.boolean().optional(),
});

export type UserinfoResponse = z.infer<typeof userinfoResponseSchema>;
