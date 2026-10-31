import { randomBytes, randomUUID } from 'node:crypto';

import {
  BadRequestError,
  InvalidClientMetadataError,
  InvalidRedirectUriError,
  JWTInvalidError,
  NotFoundError,
} from '@qauth-labs/shared-errors';
import type { EventDataOf, RegisteredEventType } from '@qauth-labs/shared-events';
import { isReservedQauthScope } from '@qauth-labs/shared-validation';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';

import { env } from '../../config/env';
import { assertDeveloperClientLimit } from './developer-client-limit';
import { validateRedirectUri } from './dynamic-client-registration';
import { type EnvironmentPolicy, resolveEnvironmentPolicy } from './environment-policy';
import { dynamicRegistrationScopesOf } from './realm-policy-readers';
import { requestRealm } from './request-realm';
import { emitUserEvent, type UserEventOptions } from './user-events';

/**
 * Client management for a developer: the domain logic of the legacy
 * `/api/clients` routes and of the developer API's `/developer/v1-rc.0/clients`
 * (#524), shared so the two cannot drift on what matters: ownership, the
 * realm's scope allowlist, the grant and redirect rules, the one-time secret
 * and the events. Each route keeps only its own representation.
 *
 * Ownership is scoped strictly by `oauth_clients.developer_id`, so a developer
 * only ever sees and manages their own clients. A client that exists but is
 * owned by another developer is reported as **404** (not 403), so the API
 * never leaks the existence of clients the caller does not own (ADR-012).
 */

/**
 * The shape of a single `oauth_clients` row as returned by the repository.
 * Derived from the decorator type so we stay decoupled from
 * `@qauth-labs/infra-db` (auth-server depends on it only transitively via
 * `@qauth-labs/fastify-plugin-db`), matching the boundary that
 * `helpers/client-auth.ts` keeps with its `OAuthClientLike` type.
 */
export type OAuthClientRow = Awaited<
  ReturnType<FastifyInstance['repositories']['oauthClients']['listByDeveloper']>
>[number];

/**
 * A database transaction, as the repositories take it. Derived from the
 * decorator type for the same reason as {@link OAuthClientRow}.
 */
export type DbTransaction = Parameters<
  FastifyInstance['repositories']['oauthClients']['findByIdForUpdate']
>[2];

/** The realm row the repository returns, or nothing. */
type RealmRowOrMissing = Awaited<ReturnType<FastifyInstance['repositories']['realms']['findById']>>;

// `oauth_clients.developer_id` is a UUID column. `request.jwtPayload.sub` is a
// developer's `users.id` (a UUID) for user tokens, but for the
// `client_credentials` grant `sub` equals the `client_id` — an opaque
// varchar, not a UUID. Querying Postgres with a non-UUID value would raise
// `22P02` (invalid input syntax for type uuid) and surface as a 500. Since a
// non-UUID subject can never own a UUID-keyed client row, treat it as
// "no clients" rather than letting it reach the database.
const uuidSubjectSchema = z.uuid();

/** Whether `subject` can own a client: a UUID `users.id`. */
export function isDeveloperSubject(subject: string): boolean {
  return uuidSubjectSchema.safeParse(subject).success;
}

/**
 * Pull the developer's `users.id` off the verified JWT. The guard populates
 * `jwtPayload`, but we guard `sub` explicitly so we never act with an
 * undefined owner (defense-in-depth).
 */
export function requireDeveloperId(request: { jwtPayload?: { sub?: string } }): string {
  const sub = request.jwtPayload?.sub;
  if (!sub) {
    throw new JWTInvalidError('Missing JWT payload');
  }
  return sub;
}

/**
 * Resolve a client the caller is allowed to act on, or throw `NotFoundError`.
 *
 * - A non-UUID subject (e.g. a `client_credentials` token whose `sub` is a
 *   `client_id`) can never own a UUID-keyed row → 404 without a DB hit.
 * - A row owned by a different developer is reported as **404, not 403**, so
 *   the API never confirms the existence of clients the caller does not own
 *   (avoids enumeration; OWASP API1/A01 BOLA).
 * - A client of another realm than the request's is not found at all (#489),
 *   the same 404.
 *
 * With `tx`, the row is read inside that transaction and locked until it ends
 * (`SELECT … FOR UPDATE`), for an update conditional on what it read (#524).
 */
export async function resolveOwnedClient(
  fastify: FastifyInstance,
  request: FastifyRequest,
  developerId: string,
  id: string,
  tx?: DbTransaction
): Promise<OAuthClientRow> {
  if (!isDeveloperSubject(developerId)) {
    throw new NotFoundError('OAuthClient', id);
  }

  const realmId = requestRealm(request).id;
  const client =
    tx === undefined
      ? await fastify.repositories.oauthClients.findById(realmId, id)
      : await fastify.repositories.oauthClients.findByIdForUpdate(realmId, id, tx);
  if (!client || client.developerId !== developerId) {
    throw new NotFoundError('OAuthClient', id);
  }
  return client;
}

/**
 * Resolve a client's EFFECTIVE environment policy (ADR-008 §7) by pairing it
 * with its realm ceiling. Routes through {@link resolveEnvironmentPolicy} — the
 * single source of truth — so a response's `environment` /
 * `staticApiKeysAllowed` always agree with what the static-API-key gate (#97)
 * enforces, including a realm pinned to `production`. A missing realm fails
 * safe to `production`.
 */
export async function resolveClientPolicy(
  fastify: FastifyInstance,
  client: OAuthClientRow
): Promise<EnvironmentPolicy> {
  const realm = await fastify.repositories.realms.findById(client.realmId);
  return resolveEnvironmentPolicy(client, realm ?? null);
}

/**
 * Each row with its effective policy. Realms are cached per id within the
 * call, so a developer's clients (which all share the developer's realm) cost
 * a single realm lookup, not one per client.
 */
export async function withClientPolicies(
  fastify: FastifyInstance,
  rows: readonly OAuthClientRow[]
): Promise<Array<{ client: OAuthClientRow; policy: EnvironmentPolicy }>> {
  const realmCache = new Map<string, RealmRowOrMissing>();
  const result = [];
  for (const row of rows) {
    if (!realmCache.has(row.realmId)) {
      realmCache.set(row.realmId, await fastify.repositories.realms.findById(row.realmId));
    }
    result.push({
      client: row,
      policy: resolveEnvironmentPolicy(row, realmCache.get(row.realmId) ?? null),
    });
  }
  return result;
}

/**
 * Enforce OAuth 2.1 / RFC 7591 grant_type ⇄ response_type ⇄ redirect_uri
 * consistency, the same invariants `validateAndNormalize` applies to dynamic
 * registration:
 *
 * - `authorization_code` requires the `code` response type.
 * - `response_types` without `authorization_code` is unsupported.
 * - `client_credentials` cannot be a public client (`none`) — a public client
 *   holds no secret and so cannot authenticate at the token endpoint
 *   (RFC 6749 §4.4).
 * - A user-involving grant (`authorization_code` / `refresh_token`) requires at
 *   least one `redirect_uri`; without one the client can never complete a
 *   user-agent flow (mirrors DCR's `redirect_uris is required …` rejection).
 *
 * Throws on any violation what `/oauth/register` throws for the same one
 * (#513): `InvalidRedirectUriError` (400 `invalid_redirect_uri`) for the
 * missing redirect URIs, `InvalidClientMetadataError` (400
 * `invalid_client_metadata`) for the rest. Each call site has already resolved
 * the effective grant/response/auth/redirect values (request value or
 * persisted value for partial updates).
 */
function assertGrantResponseConsistency(input: {
  grantTypes: string[];
  responseTypes: string[];
  tokenEndpointAuthMethod: string;
  redirectUris: string[];
}): void {
  const { grantTypes, responseTypes, tokenEndpointAuthMethod, redirectUris } = input;

  if (grantTypes.includes('authorization_code') && !responseTypes.includes('code')) {
    throw new InvalidClientMetadataError(
      'authorization_code grant requires the "code" response type'
    );
  }
  if (!grantTypes.includes('authorization_code') && responseTypes.length > 0) {
    throw new InvalidClientMetadataError(
      'response_types without authorization_code grant is not supported'
    );
  }
  if (tokenEndpointAuthMethod === 'none' && grantTypes.includes('client_credentials')) {
    throw new InvalidClientMetadataError(
      'client_credentials grant requires a confidential client (token_endpoint_auth_method must not be "none")'
    );
  }
  const userInvolving =
    grantTypes.includes('authorization_code') || grantTypes.includes('refresh_token');
  if (userInvolving && redirectUris.length === 0) {
    throw new InvalidRedirectUriError(
      'redirect_uris is required for grants that involve a user-agent (authorization_code / refresh_token)'
    );
  }
}

/**
 * Resolve the realm's effective dynamic-registration scope allowlist exactly
 * as `/oauth/register` does. The REST create/update paths reuse this same
 * policy so a developer cannot self-grant a scope through the management API
 * that the realm would refuse at dynamic registration — keeping the two
 * client-creation paths consistent.
 *
 * The list is read from the database, not from the realm resolver's row
 * (`request.realm`), which can be up to its cache time old (#487): a list an
 * operator set since then must apply. A realm that no longer exists permits
 * no scope. A realm with no policies yet (#516) reads as its fill will leave
 * it, and nothing is written: the boot step stores the fill, the first node
 * to boot winning.
 */
async function resolveRealmAllowedScopes(
  fastify: FastifyInstance,
  realmId: string
): Promise<string[]> {
  const realm = await fastify.repositories.realms.findById(realmId);
  if (!realm) return [];
  return dynamicRegistrationScopesOf(fastify.policyStore, realm);
}

/**
 * Cap requested `scopes` against the realm allowlist, rejecting anything
 * outside it with `InvalidClientMetadataError` (400 `invalid_client_metadata`,
 * as `/oauth/register` answers it; #513). Empty allowlist means no custom
 * scopes are permitted.
 *
 * A scope in QAuth's reserved `qauth:` namespace (#507) is never in the
 * allowlist, so it gets the same refusal as any other scope the realm does not
 * allow. The allowlist cannot hold one, and the namespace is left out of it
 * here too, since the list of a realm with no policies yet comes from the
 * environment's seed.
 */
function assertScopesAllowed(requested: string[], realmAllowedScopes: string[]): void {
  const disallowed = requested.filter(
    (s) => !realmAllowedScopes.includes(s) || isReservedQauthScope(s)
  );
  if (disallowed.length > 0) {
    throw new InvalidClientMetadataError(`scope not permitted: ${disallowed.join(' ')}`);
  }
}

/**
 * Generate a fresh 32-byte (256-bit) client secret and its argon2id hash.
 * Returns both so the plaintext can be surfaced exactly once in the response
 * while only the hash is ever persisted. The plaintext is never logged.
 */
async function generateClientSecret(
  fastify: FastifyInstance
): Promise<{ plaintext: string; hash: string }> {
  const plaintext = randomBytes(32).toString('hex');
  const hash = await fastify.passwordHasher.hashPassword(plaintext);
  return { plaintext, hash };
}

/**
 * Record a client-management event best-effort: a failed write MUST NOT
 * propagate.
 *
 * This matters most on the secret-bearing paths (create / regenerate): the
 * client row (or rotated secret hash) is already committed, so throwing here
 * would 500 *after* the only copy of the plaintext secret was generated,
 * leaving the developer with a client they can never authenticate. We log the
 * failure and continue so the one-time secret still reaches the response.
 *
 * The developer acts, as the user of the management token; the client is the
 * event's subject and its `client`, by its public `client_id`.
 */
async function emitClientEventBestEffort<Type extends RegisteredEventType>(
  fastify: FastifyInstance,
  request: FastifyRequest,
  type: Type,
  data: EventDataOf<Type>,
  event: { developerId: string; client: Pick<OAuthClientRow, 'clientId' | 'realmId'> }
): Promise<void> {
  const options: UserEventOptions = {
    realmId: event.client.realmId,
    userId: event.developerId,
    subject: { type: 'client', id: event.client.clientId },
    clientId: event.client.clientId,
    actor: 'user',
  };
  try {
    await emitUserEvent(request, type, data, options);
  } catch (err) {
    fastify.log.warn(
      { err, event: type, clientId: event.client.clientId },
      'Failed to record a client-management event (non-fatal)'
    );
  }
}

/** The settings a developer gives a new client; every route maps its own body onto these. */
export interface NewClientSettings {
  name: string;
  description?: string | null;
  redirectUris?: string[];
  scopes?: string[];
  grantTypes?: string[];
  responseTypes?: string[];
  tokenEndpointAuthMethod?: string;
}

/** The settings an update writes: each one present is replaced, each one absent kept. */
export interface ClientSettingsChange {
  name?: string;
  description?: string | null;
  redirectUris?: string[];
  scopes?: string[];
  grantTypes?: string[];
  responseTypes?: string[];
  tokenEndpointAuthMethod?: string;
  enabled?: boolean;
}

/** The defaults of a new client's settings, as dynamic registration has them. */
export const NEW_CLIENT_DEFAULTS = {
  grantTypes: ['authorization_code', 'refresh_token'],
  responseTypes: ['code'],
  tokenEndpointAuthMethod: 'none',
} as const;

/**
 * Create a client owned by `developerId` in the request's realm, with the
 * checks of dynamic registration, and record `client.created`.
 *
 * Every check runs before the argon2id hash, so a refused request never pays
 * it or persists. Confidential clients get a real secret, returned once as
 * `clientSecret`; public clients (auth method `none`) store a non-verifiable
 * sentinel hash, so the NOT NULL column is satisfied without minting a usable
 * secret, and the hash length never leaks the client type.
 *
 * @throws JWTInvalidError when the subject is not a user, who alone owns clients
 */
export async function createDeveloperClient(
  fastify: FastifyInstance,
  request: FastifyRequest,
  developerId: string,
  settings: NewClientSettings
): Promise<{ client: OAuthClientRow; policy: EnvironmentPolicy; clientSecret?: string }> {
  // `developer_id` is a UUID column; a non-UUID subject (client_credentials
  // token) cannot own a client and must not be allowed to create one.
  if (!isDeveloperSubject(developerId)) {
    throw new JWTInvalidError('A user access token is required to create clients');
  }

  const grantTypes = settings.grantTypes ?? [...NEW_CLIENT_DEFAULTS.grantTypes];
  const responseTypes = settings.responseTypes ?? [...NEW_CLIENT_DEFAULTS.responseTypes];
  const tokenEndpointAuthMethod =
    settings.tokenEndpointAuthMethod ?? NEW_CLIENT_DEFAULTS.tokenEndpointAuthMethod;
  // Zod applies the defaults, but default defensively so this is also correct
  // when called without the schema layer (unit tests).
  const redirectUris = settings.redirectUris ?? [];
  // De-duplicated, as dynamic registration does: the allowlist check accepts
  // any number of repeats of an allowed scope, and the row would store them all.
  const scopes = [...new Set(settings.scopes ?? [])];

  for (const uri of redirectUris) {
    validateRedirectUri(uri, env.REDIRECT_URI_CUSTOM_SCHEMES);
  }
  assertGrantResponseConsistency({
    grantTypes,
    responseTypes,
    tokenEndpointAuthMethod,
    redirectUris,
  });

  const realm = requestRealm(request);

  // Cap requested scopes against the realm policy *before* hashing — a
  // policy-violating request must not pay the argon2id cost or persist.
  const allowedScopes = await resolveRealmAllowedScopes(fastify, realm.id);
  assertScopesAllowed(scopes, allowedScopes);

  // The per-developer ceiling, also before hashing. It bounds the lists.
  await assertDeveloperClientLimit(fastify, realm.id, developerId);

  const clientId = randomUUID();

  const isPublic = tokenEndpointAuthMethod === 'none';
  let plaintextSecret: string | undefined;
  let clientSecretHash: string;
  if (isPublic) {
    clientSecretHash = await fastify.passwordHasher.hashPassword(randomBytes(32).toString('hex'));
  } else {
    const secret = await generateClientSecret(fastify);
    plaintextSecret = secret.plaintext;
    clientSecretHash = secret.hash;
  }

  const created = await fastify.repositories.oauthClients.create({
    realmId: realm.id,
    clientId,
    clientSecretHash,
    name: settings.name,
    description: settings.description ?? null,
    redirectUris,
    scopes,
    grantTypes: grantTypes as OAuthClientRow['grantTypes'],
    responseTypes: responseTypes as OAuthClientRow['responseTypes'],
    tokenEndpointAuthMethod: tokenEndpointAuthMethod as OAuthClientRow['tokenEndpointAuthMethod'],
    // Project-wide default: require PKCE for all clients (OAuth 2.1 §4.1.3
    // / RFC 9700). Public clients MUST; confidential clients SHOULD.
    requirePkce: true,
    enabled: true,
    developerId,
    // ANT-2026-O8U3P920: a developer account is self-service (anyone can
    // open one), so its clients are never operator-provisioned and their
    // authorization errors are shown on the issuer, not redirected. Pinned
    // here, never read from the body; no update writes it either.
    provisionedByOperator: false,
    // ADR-011 (#434): ID-JAG targets are operator state, set only by the
    // seed manifest. Pinned empty here; `UpdateOAuthClient` excludes the
    // column, so an update cannot write it either.
    idJagTargets: [],
    // RFC 9449 §5.2 (#480): DPoP-bound access tokens are operator state
    // too, pinned here and excluded from `UpdateOAuthClient`.
    dpopBoundAccessTokens: false,
    // ADR-019 Decision 6 (#593): a developer cannot verify their own
    // client's domain. Admin state, pinned here and excluded from
    // `UpdateOAuthClient`.
    verifiedDomain: null,
  });

  // Best-effort: the client (and its secret hash) is already committed, so
  // a failing event write must not 500 and lose the one-time plaintext.
  await emitClientEventBestEffort(
    fastify,
    request,
    'urn:qauth:event:client.created:v1-rc.0',
    {
      registration: 'developer_api',
      isPublic,
      grantTypes,
      scopes,
      authMethod: tokenEndpointAuthMethod,
    },
    { developerId, client: { clientId, realmId: realm.id } }
  );

  // The request's realm, as the resolver read it, so the response's
  // effective environment respects the realm ceiling without a lookup.
  const policy = resolveEnvironmentPolicy(created, realm);
  return {
    client: created,
    policy,
    ...(plaintextSecret === undefined ? {} : { clientSecret: plaintextSecret }),
  };
}

/**
 * Apply `change` to `existing`, a client the caller owns, and return the row
 * written: the update of the legacy `PATCH /api/clients/:id` and of the
 * developer API's merge patch (#524).
 *
 * The *effective* configuration is validated: each field from the change when
 * present, else the persisted value. This catches an update that would leave
 * the client in an inconsistent state (e.g. removing authorization_code while
 * keeping response_types, or dropping the last redirect_uri from an
 * authorization_code client). The scopes the change ADDS are capped against
 * the realm's allowlist; a scope the client already holds is not checked
 * again, so a client keeps one the realm no longer allows (or an operator
 * gave it) while its owner edits another field and sends its scopes back.
 *
 * An empty change writes nothing and records no event. With `tx` the write
 * joins that transaction; the `client.updated` event is recorded by
 * {@link recordClientUpdated} once it commits.
 *
 * @returns the row after the update, and the names of the settings written
 */
export async function applyClientChange(
  fastify: FastifyInstance,
  existing: OAuthClientRow,
  change: ClientSettingsChange,
  tx?: DbTransaction
): Promise<{ client: OAuthClientRow; fields: string[] }> {
  // De-duplicated before the allowlist check and the write, as on create.
  const scopes = change.scopes === undefined ? undefined : [...new Set(change.scopes)];

  const grantTypes = change.grantTypes ?? existing.grantTypes;
  const responseTypes = change.responseTypes ?? existing.responseTypes;
  const tokenEndpointAuthMethod =
    change.tokenEndpointAuthMethod ?? existing.tokenEndpointAuthMethod;
  const redirectUris = change.redirectUris ?? existing.redirectUris;

  if (change.redirectUris) {
    for (const uri of change.redirectUris) {
      validateRedirectUri(uri, env.REDIRECT_URI_CUSTOM_SCHEMES);
    }
  }
  assertGrantResponseConsistency({
    grantTypes,
    responseTypes,
    tokenEndpointAuthMethod,
    redirectUris,
  });

  if (scopes !== undefined) {
    const added = scopes.filter((scope) => !existing.scopes.includes(scope));
    if (added.length > 0) {
      const allowedScopes = await resolveRealmAllowedScopes(fastify, existing.realmId);
      assertScopesAllowed(added, allowedScopes);
    }
  }

  // An operator's `provisioned_by_operator` vouches for the redirect URIs as
  // the operator wrote them (ANT-2026-O8U3P920). An owner who changes them
  // voids that, so the client loses the automatic error redirects.
  const redirectUrisChanged =
    change.redirectUris !== undefined &&
    JSON.stringify(change.redirectUris) !== JSON.stringify(existing.redirectUris);

  const changes = {
    ...(change.name !== undefined ? { name: change.name } : {}),
    ...(change.description !== undefined ? { description: change.description } : {}),
    ...(change.redirectUris !== undefined ? { redirectUris: change.redirectUris } : {}),
    ...(redirectUrisChanged ? { provisionedByOperator: false } : {}),
    ...(scopes !== undefined ? { scopes } : {}),
    ...(change.grantTypes !== undefined
      ? { grantTypes: change.grantTypes as OAuthClientRow['grantTypes'] }
      : {}),
    ...(change.responseTypes !== undefined
      ? { responseTypes: change.responseTypes as OAuthClientRow['responseTypes'] }
      : {}),
    ...(change.tokenEndpointAuthMethod !== undefined
      ? {
          tokenEndpointAuthMethod:
            change.tokenEndpointAuthMethod as OAuthClientRow['tokenEndpointAuthMethod'],
        }
      : {}),
    // `enabled` is the owner's switch, both ways. An operator who must keep
    // a client off suspends it (`oauth_clients.suspended`), which no route
    // writes and this one never reads from the body (ANT-2026-DR5XI3LV).
    ...(change.enabled !== undefined ? { enabled: change.enabled } : {}),
  };
  const fields = Object.keys(changes);
  if (fields.length === 0) {
    return { client: existing, fields };
  }
  const { oauthClients } = fastify.repositories;
  const updated =
    tx === undefined
      ? await oauthClients.update(existing.realmId, existing.id, changes)
      : await oauthClients.update(existing.realmId, existing.id, changes, tx);
  return { client: updated, fields };
}

/**
 * Record `client.updated` for a change {@link applyClientChange} wrote: the
 * names of the settings written, never their values. Best-effort, and nothing
 * for an empty change.
 */
export async function recordClientUpdated(
  fastify: FastifyInstance,
  request: FastifyRequest,
  developerId: string,
  client: Pick<OAuthClientRow, 'clientId' | 'realmId'>,
  fields: string[]
): Promise<void> {
  if (fields.length === 0) return;
  await emitClientEventBestEffort(
    fastify,
    request,
    'urn:qauth:event:client.updated:v1-rc.0',
    { fields },
    { developerId, client }
  );
}

/**
 * Delete a client the caller owns and record `client.deleted`. Ownership is
 * checked before deleting: delete-by-id alone cannot enforce it.
 */
export async function deleteDeveloperClient(
  fastify: FastifyInstance,
  request: FastifyRequest,
  developerId: string,
  id: string
): Promise<void> {
  const existing = await resolveOwnedClient(fastify, request, developerId, id);

  await fastify.repositories.oauthClients.delete(existing.realmId, id);

  await emitClientEventBestEffort(
    fastify,
    request,
    'urn:qauth:event:client.deleted:v1-rc.0',
    {},
    { developerId, client: existing }
  );
}

/**
 * Issue a new secret for a confidential client the caller owns, and record
 * `client.secret_rotated`. The previous secret stops working at once.
 *
 * @throws BadRequestError for a public client (auth method `none`), which
 *   holds no usable secret: regenerating would mint a credential the client
 *   cannot present
 */
export async function regenerateDeveloperClientSecret(
  fastify: FastifyInstance,
  request: FastifyRequest,
  developerId: string,
  id: string
): Promise<{ client: OAuthClientRow; policy: EnvironmentPolicy; clientSecret: string }> {
  const existing = await resolveOwnedClient(fastify, request, developerId, id);

  if (existing.tokenEndpointAuthMethod === 'none') {
    throw new BadRequestError(
      'Cannot regenerate a secret for a public client (token_endpoint_auth_method is "none")'
    );
  }

  const { plaintext, hash } = await generateClientSecret(fastify);

  const updated = await fastify.repositories.oauthClients.update(existing.realmId, id, {
    clientSecretHash: hash,
  });

  // Best-effort: the new secret hash is already committed and the old one
  // invalidated, so a failing event write must not 500 and lose the one-time
  // plaintext (the client would be locked out of its own secret).
  await emitClientEventBestEffort(
    fastify,
    request,
    'urn:qauth:event:client.secret_rotated:v1-rc.0',
    {},
    { developerId, client: updated }
  );

  const policy = await resolveClientPolicy(fastify, updated);
  return { client: updated, policy, clientSecret: plaintext };
}
