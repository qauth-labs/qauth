import { z } from 'zod';

/**
 * Client-management API schemas (issue #85, task 2.2.1).
 *
 * These power the developer portal's client-management screens. Payloads are
 * app-specific (not RFC 6749/7591 wire formats), so fields are camelCase per
 * the project's API-design convention.
 *
 * The shared response shape below is the foundation the rest of Phase 2.2
 * (#86 create, #87 get-one, #88 update, #89 delete, #90 regenerate-secret)
 * builds on. It deliberately exposes only safe, non-sensitive fields:
 * `client_secret_hash` is NEVER serialized here.
 */

/**
 * A single OAuth client as returned by the management API. Safe fields only —
 * the secret hash and any internal-only columns are intentionally omitted.
 */
export const clientSchema = z.object({
  id: z.uuid(),
  clientId: z.string(),
  name: z.string(),
  description: z.string().nullable(),
  redirectUris: z.array(z.string()),
  scopes: z.array(z.string()),
  grantTypes: z.array(z.string()),
  responseTypes: z.array(z.string()),
  tokenEndpointAuthMethod: z.string(),
  enabled: z.boolean(),
  requirePkce: z.boolean(),
  createdAt: z.number(),
  updatedAt: z.number(),
  lastUsedAt: z.number().nullable(),
});

/**
 * A single OAuth client (safe fields).
 */
export type Client = z.infer<typeof clientSchema>;

/**
 * Response body for `GET /api/clients` — the authenticated developer's clients.
 */
export const listClientsResponseSchema = z.object({
  clients: z.array(clientSchema),
});

/**
 * Response type for `GET /api/clients`.
 */
export type ListClientsResponse = z.infer<typeof listClientsResponseSchema>;

/**
 * The OAuth grant types this server supports (mirrors the `grant_type`
 * pg enum in `@qauth-labs/infra-db`). `password`/`implicit` were removed in
 * OAuth 2.1, so they are intentionally absent.
 */
export const grantTypeSchema = z.enum([
  'authorization_code',
  'refresh_token',
  'client_credentials',
]);

/**
 * Supported response types. OAuth 2.1 only retains `code` (implicit removed).
 */
export const responseTypeSchema = z.enum(['code']);

/**
 * Supported token-endpoint client-authentication methods (mirrors the
 * `token_endpoint_auth_method` pg enum).
 */
export const tokenEndpointAuthMethodSchema = z.enum([
  'client_secret_post',
  'client_secret_basic',
  'private_key_jwt',
  'none',
]);

/**
 * Request body for `POST /api/clients` (issue #86).
 *
 * The developer never supplies `client_id` or `client_secret` — both are
 * server-generated. `developerId`/`realmId` are derived from the access token
 * and the default realm, never the request body (prevents mass-assignment).
 *
 * `redirectUris` and the grant/response-type combination are validated for
 * RFC 7591/OAuth 2.1 consistency in the route handler (shared with the update
 * path). Defaults mirror the dynamic-client-registration policy:
 * authorization_code + refresh_token, `code`, public client (PKCE).
 */
export const createClientRequestSchema = z.object({
  name: z.string().min(1).max(255),
  description: z.string().max(2000).nullish(),
  redirectUris: z.array(z.url()).default([]),
  scopes: z.array(z.string()).default([]),
  grantTypes: z.array(grantTypeSchema).nonempty().optional(),
  responseTypes: z.array(responseTypeSchema).optional(),
  tokenEndpointAuthMethod: tokenEndpointAuthMethodSchema.optional(),
});

/**
 * Request type for `POST /api/clients`.
 */
export type CreateClientRequest = z.infer<typeof createClientRequestSchema>;

/**
 * Response body for `POST /api/clients` — the only place (besides
 * regenerate-secret) the plaintext `client_secret` is ever returned. The
 * developer must persist it now; it is unrecoverable afterwards because only
 * the argon2id hash is stored. Public clients
 * (`tokenEndpointAuthMethod === 'none'`) get no `clientSecret`.
 */
export const createClientResponseSchema = clientSchema.extend({
  clientSecret: z.string().optional(),
});

/**
 * Response type for `POST /api/clients`.
 */
export type CreateClientResponse = z.infer<typeof createClientResponseSchema>;

/**
 * Request body for `PATCH /api/clients/:id` (issue #88).
 *
 * Every field is optional (partial update). Identity and secret columns
 * (`clientId`, `clientSecretHash`, `developerId`, `realmId`) are intentionally
 * absent — they can never be mutated through this endpoint. At least one field
 * must be present.
 */
export const updateClientRequestSchema = z
  .object({
    name: z.string().min(1).max(255),
    description: z.string().max(2000).nullable(),
    redirectUris: z.array(z.url()),
    scopes: z.array(z.string()),
    grantTypes: z.array(grantTypeSchema).nonempty(),
    responseTypes: z.array(responseTypeSchema),
    tokenEndpointAuthMethod: tokenEndpointAuthMethodSchema,
    enabled: z.boolean(),
  })
  .partial()
  .refine((body) => Object.keys(body).length > 0, {
    message: 'At least one field must be provided',
  });

/**
 * Request type for `PATCH /api/clients/:id`.
 */
export type UpdateClientRequest = z.infer<typeof updateClientRequestSchema>;

/**
 * Response body for `POST /api/clients/:id/regenerate-secret` (issue #90).
 *
 * Returns the safe projection plus the freshly issued plaintext `clientSecret`
 * exactly once. Regeneration is only meaningful for confidential clients, so
 * `clientSecret` is always present here.
 */
export const regenerateSecretResponseSchema = clientSchema.extend({
  clientSecret: z.string(),
});

/**
 * Response type for `POST /api/clients/:id/regenerate-secret`.
 */
export type RegenerateSecretResponse = z.infer<typeof regenerateSecretResponseSchema>;
