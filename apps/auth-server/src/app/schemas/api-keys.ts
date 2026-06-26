import { z } from 'zod';

/**
 * Static developer API key management API schemas (ADR-008 §6, issue #97).
 *
 * Powers the developer portal's API-key screens (#98). Payloads are
 * app-specific (not an RFC wire format), so fields are camelCase per the
 * project's API-design convention. The response shape deliberately exposes only
 * non-secret fields: the `key_hash` is NEVER serialized, and the plaintext key
 * appears exactly once — in the create response.
 */

/**
 * A single API key as returned by the management API — masked, non-secret
 * fields only. `prefix` and `last4` together render a "qauth_…•••• abcd"
 * display; the full key and its hash are never present here.
 */
export const apiKeySchema = z.object({
  id: z.uuid(),
  clientId: z.uuid(),
  name: z.string(),
  /** Public lookup handle (`qauth_<id>`); non-secret, safe to display. */
  prefix: z.string(),
  /** Trailing 4 chars of the secret, for masked display. */
  last4: z.string(),
  createdAt: z.number(),
  lastUsedAt: z.number().nullable(),
  /** Set once the key has been revoked; a revoked key never authenticates. */
  revokedAt: z.number().nullable(),
});

/** A single masked API key (safe fields). */
export type ApiKeyView = z.infer<typeof apiKeySchema>;

/**
 * Response body for `GET /api/clients/:clientId/api-keys`.
 */
export const listApiKeysResponseSchema = z.object({
  apiKeys: z.array(apiKeySchema),
});

/** Response type for the list endpoint. */
export type ListApiKeysResponse = z.infer<typeof listApiKeysResponseSchema>;

/**
 * Request body for `POST /api/clients/:clientId/api-keys`.
 *
 * The developer supplies only a human-readable `name`; the server generates the
 * key, prefix, and hash. `clientId`/`developerId`/`realmId` are derived from the
 * path and the access token, never the body (prevents mass-assignment).
 */
export const createApiKeyRequestSchema = z.object({
  name: z.string().min(1).max(255),
});

/** Request type for the create endpoint. */
export type CreateApiKeyRequest = z.infer<typeof createApiKeyRequestSchema>;

/**
 * Response body for `POST /api/clients/:clientId/api-keys` — the ONLY place the
 * plaintext `key` is ever returned. The developer must persist it now; it is
 * unrecoverable afterwards because only the argon2id hash is stored.
 */
export const createApiKeyResponseSchema = apiKeySchema.extend({
  /** Full plaintext key (`qauth_<id>_<secret>`). Shown once; never recoverable. */
  key: z.string(),
});

/** Response type for the create endpoint. */
export type CreateApiKeyResponse = z.infer<typeof createApiKeyResponseSchema>;
