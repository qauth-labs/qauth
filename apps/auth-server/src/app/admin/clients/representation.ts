import { createHash } from 'node:crypto';

import { canonicalizeJson } from '@qauth-labs/fastify-plugin-db';
import {
  FIRST_PARTY_FLOWS,
  FIRST_PARTY_PROFILES,
  FIRST_PARTY_REASON_MAX_LENGTH,
} from '@qauth-labs/shared-validation';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import { rfc3339, rfc3339OrNull } from '../../api-conventions/time';
import { ENVIRONMENTS } from '../../helpers/environment-policy';
import { AGENT_MODES } from '../../helpers/scope-modes';

/**
 * THE CLIENT REPRESENTATION OF THE ADMIN API (ADR-020 §3, issue #632): every
 * client of a realm as an admin reads it, whoever owns it, and the state its
 * operations classify, render and bind an approval to.
 *
 * It never holds `client_secret_hash`, nor any other column the schema below
 * does not name: {@link adminClientOf} builds it member by member, and the
 * response schema strips what it does not name. A stored JWK keeps its public
 * members only.
 *
 * The operator-set columns no admin operation writes yet (the audience, the
 * ID-JAG targets, the passkey origins, the hosted flows) are left out: the
 * seed manifest still sets them, and a later operation adds each, with its
 * entry in the field table (`./fields.ts`).
 *
 * Kept apart from the definitions (`./operations.ts`), which the operation
 * registry imports, and from the routes: it imports no environment.
 */

/** The grant types a client may hold (the `grant_type` enum of `oauth_clients`). */
export const CLIENT_GRANT_TYPES = [
  'authorization_code',
  'refresh_token',
  'client_credentials',
  'urn:ietf:params:oauth:grant-type:jwt-bearer',
  'urn:ietf:params:oauth:grant-type:token-exchange',
] as const;

/** The response types a client may hold. */
export const CLIENT_RESPONSE_TYPES = ['code'] as const;

/** How a client may authenticate at the token endpoint (RFC 7591 §2). */
export const CLIENT_AUTH_METHODS = [
  'client_secret_post',
  'client_secret_basic',
  'private_key_jwt',
  'none',
] as const;

/** The most redirect URIs, post-logout redirect URIs or scopes one client lists. */
export const CLIENT_LIST_MAX = 50;

/** The longest URI the representation takes. */
export const CLIENT_URI_MAX_LENGTH = 2048;

/** The longest description. */
export const CLIENT_DESCRIPTION_MAX_LENGTH = 2000;

/** The longest a client's own access token may live: a day, the realm's own bound. */
export const CLIENT_ACCESS_TOKEN_LIFESPAN_MAX = 86400;

/** The longest a client's own refresh token may live: 90 days, the realm's own bound. */
export const CLIENT_REFRESH_TOKEN_LIFESPAN_MAX = 7776000;

/**
 * The members of a JWK that hold private key material (RFC 7518 §6): never
 * shown, even on a row written by hand. Registration refuses a key with one.
 */
const PRIVATE_JWK_MEMBERS = new Set(['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']);

const isoTime = z.iso.datetime();

/** A client's JWK Set, as the representation shows it: public members only. */
const jwkSetSchema = z.object({ keys: z.array(z.record(z.string(), z.unknown())) });

/** A `native_backend` client's policy (ADR-017 Decision 2), every member present. */
export const adminFirstPartyPolicySchema = z
  .object({
    flows: z.array(z.enum(FIRST_PARTY_FLOWS)),
    emailCodeAfterPassword: z.boolean(),
    pkceRequired: z.boolean(),
  })
  .meta({ id: 'AdminClientFirstPartyPolicy' });

/** The client representation. */
export const adminClientSchema = z
  .object({
    id: z.uuid().meta({ description: 'The id the admin API names the client by.' }),
    client_id: z.string().meta({
      description:
        'The OAuth client_id. For a client registered from a Client ID Metadata Document, the URL of that document.',
    }),
    name: z.string(),
    description: z.string().nullable(),
    developerId: z.uuid().nullable().meta({
      description:
        'The developer account that owns the client, or null: an operator registered it, an admin did, it registered itself, or its owner was deleted. Read-only.',
    }),
    provisionedByOperator: z.boolean().meta({
      description:
        'Whether an operator provisioned the client (the seed manifest, the system client, the admin API): only such a client takes a verified domain, and its authorization errors are redirected. Read-only.',
    }),
    dynamicallyRegistered: z.boolean().meta({
      description: 'Whether the client registered itself (RFC 7591). Read-only.',
    }),
    metadataDocument: z.string().nullable().meta({
      description:
        'The Client ID Metadata Document the client’s settings come from, or null. A client with one is read-only here: its document is where it is changed (ADR-012 Decision 3). Read-only.',
    }),
    enabled: z.boolean().meta({
      description:
        'The owner’s switch. clients.enable turns it on for a client no developer owns. Read-only here.',
    }),
    suspended: z.boolean().meta({
      description:
        'Whether an operator suspended the client: it obtains no token until clients.enable lifts the suspension. Read-only here.',
    }),
    suspendedAt: isoTime.nullable(),
    redirectUris: z.array(z.string()),
    postLogoutRedirectUris: z.array(z.string()),
    backchannelLogoutUri: z.string().nullable(),
    backchannelLogoutUriSource: z.enum(['client', 'admin']).nullable().meta({
      description:
        'Who set the back-channel logout URI: client, its own registration or document; admin, an operator or an admin, whose URI the deployment egress allowlist may let reach a private address. Read-only.',
    }),
    backchannelLogoutSessionRequired: z.boolean(),
    scopes: z.array(z.string()),
    clientCredentialsScopes: z.array(z.string()).nullable().meta({
      description:
        'The scopes the client_credentials grant may issue, out of scopes; null for any of them.',
    }),
    grantTypes: z.array(z.enum(CLIENT_GRANT_TYPES)),
    responseTypes: z.array(z.enum(CLIENT_RESPONSE_TYPES)),
    tokenEndpointAuthMethod: z.enum(CLIENT_AUTH_METHODS),
    jwks: jwkSetSchema.nullable().meta({
      description: 'The public keys of a private_key_jwt client, inline; public members only.',
    }),
    jwksUri: z.string().nullable(),
    requirePkce: z.boolean(),
    dpopBoundAccessTokens: z.boolean().meta({
      description: 'Whether every access token of the client is bound to a DPoP key (RFC 9449).',
    }),
    environment: z.enum(ENVIRONMENTS).meta({
      description:
        'The environment the client declares (ADR-008); the realm’s ceiling may make it stricter.',
    }),
    isAgent: z.boolean(),
    maxAgentMode: z.enum(AGENT_MODES).nullable(),
    verifiedDomain: z.string().nullable().meta({
      description:
        'The domain an operator verified for the client (ADR-019 Decision 6), which every screen that names the client shows first.',
    }),
    firstPartyProfile: z.enum(FIRST_PARTY_PROFILES).nullable().meta({
      description:
        'The first-party profile an operator set (ADR-017 Decision 2), or null when the client is not first party.',
    }),
    firstPartyPolicy: adminFirstPartyPolicySchema.nullable().meta({
      description: 'A native_backend client’s policy; null for any other.',
    }),
    firstPartyReason: z.string().max(FIRST_PARTY_REASON_MAX_LENGTH).nullable().meta({
      description: 'The written reason for the first-party profile, exactly with one.',
    }),
    accessTokenLifespanSeconds: z.int().nullable().meta({
      description:
        'The client’s own access token lifetime, never longer than the realm’s; null for the realm’s. The token endpoint takes the shorter of the two.',
    }),
    refreshTokenLifespanSeconds: z.int().nullable().meta({
      description:
        'The client’s own refresh token lifetime, never longer than the realm’s; null for the realm’s.',
    }),
    createdAt: isoTime,
    updatedAt: isoTime,
    lastUsedAt: isoTime.nullable().meta({
      description: 'When the client last obtained a token. Not part of the ETag.',
    }),
  })
  .meta({ id: 'AdminClient' });

/** A client, as the admin API shows it. */
export type AdminClient = z.infer<typeof adminClientSchema>;

/** One `oauth_clients` row, as the repository returns it. */
export type OAuthClientRecord = NonNullable<
  Awaited<ReturnType<FastifyInstance['repositories']['oauthClients']['findById']>>
>;

/**
 * The Client ID Metadata Document a client's settings come from: its
 * `client_id`, the document's URL, for a CIMD client; `null` for any other.
 */
export function metadataDocumentOf(row: {
  readonly clientId: string;
  readonly metadata: Record<string, unknown> | null;
}): string | null {
  return row.metadata?.['registrationType'] === 'cimd' ? row.clientId : null;
}

/** Whether a client registered itself (RFC 7591). */
export function isDynamicallyRegistered(row: {
  readonly dynamicRegisteredAt: number | null;
  readonly metadata: Record<string, unknown> | null;
}): boolean {
  return row.dynamicRegisteredAt !== null || row.metadata?.['registrationType'] === 'dynamic';
}

/** A stored JWK Set with its public members only, or `null`. */
function publicJwks(jwks: OAuthClientRecord['jwks']): AdminClient['jwks'] {
  if (jwks === null || typeof jwks !== 'object' || !Array.isArray(jwks.keys)) return null;
  return {
    keys: jwks.keys.map((key) =>
      Object.fromEntries(
        Object.entries(key ?? {}).filter(([member]) => !PRIVATE_JWK_MEMBERS.has(member))
      )
    ),
  };
}

/**
 * A first-party policy in the names the representation gives its members
 * (camelCase), from the names `oauth_clients.first_party_policy` stores them
 * under (#631). A member it does not know is kept as it is, so the check
 * still refuses it.
 */
export function shownFirstPartyPolicy(policy: unknown): unknown {
  if (typeof policy !== 'object' || policy === null || Array.isArray(policy)) return policy;
  const { email_code_after_password, pkce_required, ...rest } = policy as Record<string, unknown>;
  return {
    ...rest,
    ...(email_code_after_password === undefined
      ? {}
      : { emailCodeAfterPassword: email_code_after_password }),
    ...(pkce_required === undefined ? {} : { pkceRequired: pkce_required }),
  };
}

/** A first-party policy in the names the column stores (#631): {@link shownFirstPartyPolicy} undone. */
export function storedFirstPartyPolicy(policy: unknown): unknown {
  if (typeof policy !== 'object' || policy === null || Array.isArray(policy)) return policy;
  const { emailCodeAfterPassword, pkceRequired, ...rest } = policy as Record<string, unknown>;
  return {
    ...rest,
    ...(emailCodeAfterPassword === undefined
      ? {}
      : { email_code_after_password: emailCodeAfterPassword }),
    ...(pkceRequired === undefined ? {} : { pkce_required: pkceRequired }),
  };
}

/** A stored first-party policy, as the representation shows it, or `null`. */
function firstPartyPolicyOf(policy: unknown): AdminClient['firstPartyPolicy'] {
  const parsed = adminFirstPartyPolicySchema.safeParse(shownFirstPartyPolicy(policy));
  return parsed.success ? parsed.data : null;
}

/** The representation of a stored client. Never its secret hash. */
export function adminClientOf(row: OAuthClientRecord): AdminClient {
  return {
    id: row.id,
    client_id: row.clientId,
    name: row.name,
    description: row.description,
    developerId: row.developerId,
    provisionedByOperator: row.provisionedByOperator,
    dynamicallyRegistered: isDynamicallyRegistered(row),
    metadataDocument: metadataDocumentOf(row),
    enabled: row.enabled,
    suspended: row.suspended,
    suspendedAt: rfc3339OrNull(row.suspendedAt),
    redirectUris: [...row.redirectUris],
    postLogoutRedirectUris: [...row.postLogoutRedirectUris],
    backchannelLogoutUri: row.backchannelLogoutUri,
    backchannelLogoutUriSource: row.backchannelLogoutUriSource as 'client' | 'admin' | null,
    backchannelLogoutSessionRequired: row.backchannelLogoutSessionRequired,
    scopes: [...row.scopes],
    clientCredentialsScopes:
      row.clientCredentialsScopes === null ? null : [...row.clientCredentialsScopes],
    grantTypes: [...row.grantTypes] as AdminClient['grantTypes'],
    responseTypes: [...row.responseTypes] as AdminClient['responseTypes'],
    tokenEndpointAuthMethod: row.tokenEndpointAuthMethod,
    jwks: publicJwks(row.jwks),
    jwksUri: row.jwksUri,
    requirePkce: row.requirePkce,
    dpopBoundAccessTokens: row.dpopBoundAccessTokens,
    environment: row.environment,
    isAgent: row.isAgent,
    maxAgentMode: row.maxAgentMode,
    verifiedDomain: row.verifiedDomain,
    firstPartyProfile: row.firstPartyProfile,
    firstPartyPolicy:
      row.firstPartyProfile === 'native_backend' ? firstPartyPolicyOf(row.firstPartyPolicy) : null,
    firstPartyReason: row.firstPartyReason,
    accessTokenLifespanSeconds: row.accessTokenLifespanSeconds,
    refreshTokenLifespanSeconds: row.refreshTokenLifespanSeconds,
    createdAt: rfc3339(row.createdAt),
    updatedAt: rfc3339(row.updatedAt),
    lastUsedAt: rfc3339OrNull(row.lastUsedAt),
  };
}

/**
 * The version of a client: the SHA-256 digest, base64url, of the canonical
 * JSON of its representation without `lastUsedAt`, which every token the
 * client obtains moves: were it in the version, a pending edit or approval
 * would go stale on the client's next token. Every member an operation reads
 * or writes is in it, `updatedAt` included. The client's `ETag`, quoted.
 */
export function adminClientVersion(client: AdminClient): string {
  const { lastUsedAt: _lastUsedAt, ...versioned } = client;
  return createHash('sha256').update(canonicalizeJson(versioned), 'utf8').digest('base64url');
}
