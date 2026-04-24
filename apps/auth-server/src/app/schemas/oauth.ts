import { z } from 'zod';

/**
 * RFC 8707 §2: `resource` is an absolute URI without fragment, identifying
 * the protected resource the access token is intended for. Clients MAY
 * include multiple values (one per resource). We accept either a single
 * string or an array; the route normalizes to an array.
 *
 * Coerced to string[] so downstream code (authorize/token routes, DB
 * repositories, `resolveAudience`) can treat all cases uniformly.
 */
const resourceEntrySchema = z
  .url()
  .max(2048)
  .refine((v) => !v.includes('#'), { message: 'resource must not contain a fragment' });

export const resourceParamSchema = z
  .union([resourceEntrySchema, z.array(resourceEntrySchema).max(10)])
  .optional()
  .transform((v) => (v === undefined ? undefined : Array.isArray(v) ? v : [v]));

/**
 * OAuth 2.1 authorize query parameters (GET /oauth/authorize).
 * RFC 6749 4.1.1, RFC 7636 PKCE, RFC 8707 Resource Indicators.
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
  resource: resourceParamSchema,
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
  // RFC 8707 §2: when present, MUST match the resource set bound to the
  // authorization code. Enforced in the handler, not the schema.
  resource: resourceParamSchema,
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
  // RFC 8707 §2: machine clients request a resource at mint time; handler
  // uses it as the token `aud` (overrides client.audience when present).
  resource: resourceParamSchema,
});

/**
 * OAuth 2.1 refresh_token grant body (POST /oauth/token).
 * RFC 6749 §6. Supports rotation and optional scope down-scoping.
 *
 * `client_id` / `client_secret` remain optional here — confidential
 * clients authenticate via `client_secret_basic` or `client_secret_post`;
 * public clients (PKCE, `token_endpoint_auth_method: none`) present only
 * their `client_id` and rely on refresh-token ownership for binding.
 *
 * The refresh-token format is the hex pair produced by
 * `jwtUtils.generateRefreshToken()` (64-char lowercase hex). Strict
 * validation keeps malformed tokens out of DB lookups.
 */
export const tokenExchangeRefreshBodySchema = z.object({
  grant_type: z.literal('refresh_token'),
  refresh_token: z
    .string()
    .length(64, 'refresh_token must be exactly 64 characters')
    .regex(/^[0-9a-fA-F]{64}$/, 'refresh_token must be a valid hex string'),
  client_id: z.string().min(1).optional(),
  client_secret: z.string().min(1).optional(),
  scope: z.string().optional(),
  // RFC 8707 §2: on refresh, resource MUST be a subset of the one bound
  // to the original authorization code. Enforced in the handler.
  resource: resourceParamSchema,
});

/**
 * Discriminated union of supported token grant bodies.
 */
export const tokenExchangeBodySchema = z.discriminatedUnion('grant_type', [
  tokenExchangeAuthCodeBodySchema,
  tokenExchangeClientCredsBodySchema,
  tokenExchangeRefreshBodySchema,
]);

export type TokenExchangeAuthCodeBody = z.infer<typeof tokenExchangeAuthCodeBodySchema>;
export type TokenExchangeClientCredsBody = z.infer<typeof tokenExchangeClientCredsBodySchema>;
export type TokenExchangeRefreshBody = z.infer<typeof tokenExchangeRefreshBodySchema>;
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
 *
 * `client_id` / `client_secret` are optional because clients may also
 * authenticate with `client_secret_basic` via the HTTP `Authorization`
 * header. The route handler enforces that at least one auth method is used.
 */
export const introspectRequestSchema = z.object({
  token: z.string().min(1),
  token_type_hint: z.string().max(64).optional(),
  client_id: z.string().min(1).optional(),
  client_secret: z.string().min(1).optional(),
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
 * Dynamic Client Registration request body (POST /oauth/register).
 * RFC 7591 §2. Accepts the common subset of client metadata fields; any
 * unknown keys are allowed and echoed back per §3.2.1 (server MAY omit,
 * but we round-trip recognized fields only to keep DB shape bounded).
 *
 * Policy notes:
 *   - `token_endpoint_auth_method=none` marks the client as public
 *     (PKCE required).
 *   - Grant/response type consistency is enforced in the route handler,
 *     not in the schema, so we can surface a structured OAuth error.
 *   - `scope` is space-separated per RFC 7591 §2 / RFC 6749 §3.3.
 *   - RFC 7591 §3.2 requires servers to ignore unrecognized metadata fields,
 *     so this schema uses Zod's default strip behaviour (no `.strict()`).
 */
export const dynamicClientRegistrationRequestSchema = z.object({
  client_name: z.string().min(1).max(255).optional(),
  redirect_uris: z.array(z.string().min(1).max(2048)).max(20).optional(),
  grant_types: z
    .array(z.enum(['authorization_code', 'refresh_token', 'client_credentials']))
    .max(8)
    .optional(),
  response_types: z
    .array(z.enum(['code']))
    .max(4)
    .optional(),
  token_endpoint_auth_method: z
    .enum(['none', 'client_secret_basic', 'client_secret_post'])
    .optional(),
  scope: z.string().max(2048).optional(),
  client_uri: z.url().max(2048).optional(),
  logo_uri: z.url().max(2048).optional(),
  tos_uri: z.url().max(2048).optional(),
  policy_uri: z.url().max(2048).optional(),
  contacts: z.array(z.email().max(255)).max(10).optional(),
  software_id: z.string().max(255).optional(),
  software_version: z.string().max(64).optional(),
});

export type DynamicClientRegistrationRequest = z.infer<
  typeof dynamicClientRegistrationRequestSchema
>;

/**
 * Dynamic Client Registration response body.
 * RFC 7591 §3.2.1. `client_secret` is omitted for public clients.
 * `client_id_issued_at` / `client_secret_expires_at` are seconds-since-epoch
 * (not milliseconds).
 */
export const dynamicClientRegistrationResponseSchema = z.object({
  client_id: z.string(),
  client_secret: z.string().optional(),
  client_id_issued_at: z.number().int().nonnegative(),
  // RFC 7591: 0 means "does not expire". We emit 0 for non-expiring secrets.
  client_secret_expires_at: z.number().int().nonnegative().optional(),
  client_name: z.string().optional(),
  redirect_uris: z.array(z.string()).optional(),
  grant_types: z.array(z.string()),
  response_types: z.array(z.string()),
  token_endpoint_auth_method: z.string(),
  scope: z.string().optional(),
  client_uri: z.string().optional(),
  logo_uri: z.string().optional(),
  tos_uri: z.string().optional(),
  policy_uri: z.string().optional(),
  contacts: z.array(z.string()).optional(),
  software_id: z.string().optional(),
  software_version: z.string().optional(),
});

export type DynamicClientRegistrationResponse = z.infer<
  typeof dynamicClientRegistrationResponseSchema
>;

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
