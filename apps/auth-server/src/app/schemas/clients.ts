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
