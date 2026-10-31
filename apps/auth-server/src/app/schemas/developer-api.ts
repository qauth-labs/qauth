import { z } from 'zod';

import {
  CLIENT_GRANT_TYPES_MAX,
  CLIENT_REDIRECT_URIS_MAX,
  CLIENT_RESPONSE_TYPES_MAX,
  CLIENT_SCOPES_MAX,
  clientScopeSchema,
  grantTypeSchema,
  responseTypeSchema,
  tokenEndpointAuthMethodSchema,
} from './clients';
import { boundedArray, exactUrl } from './common';

/**
 * The representations of the developer API, `/developer/v1-rc.0` (#524), in
 * the API conventions (#506): `camelCase` members, except that a member that
 * carries a registered OAuth client metadata value keeps its RFC 7591 name
 * (`client_id`, `client_name`, `redirect_uris`, `grant_types`,
 * `response_types`, `token_endpoint_auth_method`, `client_secret`); ids are
 * UUIDs; times are RFC 3339 strings; request objects refuse unknown members.
 *
 * `scopes` stays a list, as the client stores it: RFC 7591's `scope` is one
 * space-separated string, a different value, so the registered name does not
 * apply.
 *
 * The legacy `/api/clients` keeps its own shapes (`schemas/clients.ts`).
 */

const description = z.string().max(2000);
const clientName = z.string().min(1).max(255);
const redirectUris = boundedArray(z.array(exactUrl()), CLIENT_REDIRECT_URIS_MAX);
const scopes = boundedArray(z.array(clientScopeSchema), CLIENT_SCOPES_MAX);
const grantTypes = boundedArray(z.array(grantTypeSchema).nonempty(), CLIENT_GRANT_TYPES_MAX);
const responseTypes = boundedArray(z.array(responseTypeSchema), CLIENT_RESPONSE_TYPES_MAX);

/**
 * One OAuth client the developer owns. Safe fields only: the secret hash and
 * the internal columns are never serialized. `environment` and
 * `staticApiKeysAllowed` are the client's EFFECTIVE environment policy
 * (ADR-008 §7), resolved against its realm's ceiling, and read-only, as is
 * `suspended`, which only an operator sets.
 */
export const developerClientSchema = z.object({
  id: z.uuid(),
  client_id: z.string(),
  client_name: z.string(),
  description: z.string().nullable(),
  redirect_uris: z.array(z.string()),
  scopes: z.array(z.string()),
  grant_types: z.array(z.string()),
  response_types: z.array(z.string()),
  token_endpoint_auth_method: z.string(),
  enabled: z.boolean(),
  suspended: z.boolean(),
  requirePkce: z.boolean(),
  environment: z.enum(['development', 'staging', 'production']),
  staticApiKeysAllowed: z.boolean(),
  createdAt: z.iso.datetime(),
  updatedAt: z.iso.datetime(),
  lastUsedAt: z.iso.datetime().nullable(),
});

export type DeveloperClient = z.infer<typeof developerClientSchema>;

/**
 * The answer of a create: the client, and its secret when it is confidential.
 * The plaintext `client_secret` appears here and in a regeneration, never
 * again: only its argon2id hash is stored.
 */
export const createdDeveloperClientSchema = developerClientSchema.extend({
  client_secret: z.string().optional(),
});

/** The answer of a secret regeneration: the client and its new secret. */
export const regeneratedDeveloperClientSchema = developerClientSchema.extend({
  client_secret: z.string(),
});

/**
 * The body of a create. The server generates `client_id` and, for a
 * confidential client, `client_secret`; the owner and the realm come from the
 * token and the request, never the body. Left out, the members take the
 * defaults of dynamic registration: `authorization_code` and `refresh_token`,
 * the `code` response type and a public client (`none`, PKCE).
 */
export const createDeveloperClientRequestSchema = z.strictObject({
  client_name: clientName,
  description: description.nullable().optional(),
  redirect_uris: redirectUris.prefault([]),
  scopes: scopes.prefault([]),
  grant_types: grantTypes.optional(),
  response_types: responseTypes.optional(),
  token_endpoint_auth_method: tokenEndpointAuthMethodSchema.optional(),
});

export type CreateDeveloperClientRequest = z.infer<typeof createDeveloperClientRequestSchema>;

/**
 * A JSON Merge Patch (RFC 7396) of a client, sent as
 * `application/merge-patch+json`. A member left out keeps its value; a list is
 * replaced whole. A member set to `null` takes the value a create gives it
 * when it is left out: `description` none, `redirect_uris` and `scopes` empty,
 * `grant_types`, `response_types` and `token_endpoint_auth_method` the
 * defaults of dynamic registration, `enabled` true. `client_name` has no
 * default, so a patch that sets it to `null` is refused with 422.
 * `client_id`, the secret, the owner and the operator's settings are not
 * members: a patch that names one is refused with 400.
 */
export const developerClientPatchSchema = z.strictObject({
  client_name: clientName.nullable().optional(),
  description: description.nullable().optional(),
  redirect_uris: redirectUris.nullable().optional(),
  scopes: scopes.nullable().optional(),
  grant_types: grantTypes.nullable().optional(),
  response_types: responseTypes.nullable().optional(),
  token_endpoint_auth_method: tokenEndpointAuthMethodSchema.nullable().optional(),
  enabled: z.boolean().nullable().optional(),
});

export type DeveloperClientPatch = z.infer<typeof developerClientPatchSchema>;

/**
 * One static API key of a client (ADR-008 §6): masked, non-secret fields
 * only. `prefix` and `last4` render a "qauth_…•••• abcd" display; the full
 * key and its hash are never present. `clientId` is the `id` of the client
 * the key belongs to.
 */
export const developerApiKeySchema = z.object({
  id: z.uuid(),
  clientId: z.uuid(),
  name: z.string(),
  prefix: z.string(),
  last4: z.string(),
  createdAt: z.iso.datetime(),
  lastUsedAt: z.iso.datetime().nullable(),
  revokedAt: z.iso.datetime().nullable(),
});

/** The answer of a mint: the key's fields and, this once, the plaintext `key`. */
export const mintedDeveloperApiKeySchema = developerApiKeySchema.extend({
  key: z.string(),
});

/** The body of a mint: only a name; the server generates the key. */
export const createDeveloperApiKeyRequestSchema = z.strictObject({
  name: z.string().min(1).max(255),
});
