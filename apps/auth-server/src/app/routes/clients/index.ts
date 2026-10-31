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
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { env } from '../../../config/env';
import { assertDeveloperClientLimit } from '../../helpers/developer-client-limit';
import { validateRedirectUri } from '../../helpers/dynamic-client-registration';
import { type EnvironmentPolicy, resolveEnvironmentPolicy } from '../../helpers/environment-policy';
import { createRequireManagementJwt } from '../../helpers/management-token';
import { realmRateLimitKey } from '../../helpers/realm-rate-limit';
import { requestRealm } from '../../helpers/request-realm';
import { emitUserEvent, type UserEventOptions } from '../../helpers/user-events';
import {
  clientSchema,
  type CreateClientRequest,
  createClientRequestSchema,
  createClientResponseSchema,
  listClientsResponseSchema,
  regenerateSecretResponseSchema,
  type UpdateClientRequest,
  updateClientRequestSchema,
} from '../../schemas/clients';
import { registerApiKeyRoutes } from './api-keys';

/**
 * The shape of a single `oauth_clients` row as returned by the repository.
 * Derived from the decorator type so we stay decoupled from
 * `@qauth-labs/infra-db` (auth-server depends on it only transitively via
 * `@qauth-labs/fastify-plugin-db`), matching the boundary that
 * `helpers/client-auth.ts` keeps with its `OAuthClientLike` type.
 */
type OAuthClientRow = Awaited<
  ReturnType<FastifyInstance['repositories']['oauthClients']['listByDeveloper']>
>[number];

/**
 * Client-management JSON API (Phase 2.2, task 2.2.1 — issue #85).
 *
 * This module is the shared foundation for the whole T2 client-management
 * surface (#85 list, #86 create, #87 get-one, #88 update, #89 delete,
 * #90 regenerate-secret). It is mounted at `/api/clients` via the
 * `autoPrefix` export below — the route manifest registers it under
 * `autoPrefix` rather than the directory-derived prefix, so sibling routes added here register
 * against the resource root (`/`, `/:id`, `/:id/secret`, …) and land under
 * `/api/clients`.
 *
 * Auth model
 * ----------
 * Every endpoint requires the developer-portal management token via
 * `createRequireManagementJwt` (Bearer JWT): the access token `/auth/login`
 * mints for the system client, which the portal stores and sends as
 * `Authorization: Bearer <token>`. The guard runs `fastify.requireJwt`
 * (signature, issuer, revocation) and then `assertManagementToken`, which
 * rejects a token issued to any other client, bound to any other audience, or
 * carrying an `act` claim. Both throw `JWTInvalidError` (HTTP 401), so
 * unauthenticated callers never reach a handler.
 *
 * `request.jwtPayload.sub` is the developer's `users.id`. Ownership is scoped
 * strictly by `oauth_clients.developer_id`, so a developer can only ever see
 * and manage their own clients. A client that exists but is owned by another
 * developer is reported as **404** (not 403) so the API never leaks the
 * existence of clients the caller does not own.
 *
 *   GET    /api/clients                       — list the developer's clients (#85)
 *   POST   /api/clients                       — create a client (#86)
 *   GET    /api/clients/:id                   — get one owned client (#87)
 *   PATCH  /api/clients/:id                   — update mutable fields (#88)
 *   DELETE /api/clients/:id                   — delete a client (#89)
 *   POST   /api/clients/:id/regenerate-secret — issue a new secret (#90)
 */

// The route manifest mounts this module under `/api/clients` regardless of
// the `clients/` directory name. Keep route paths resource-relative.
export const autoPrefix = '/api/clients';

// `oauth_clients.developer_id` is a UUID column. `request.jwtPayload.sub` is a
// developer's `users.id` (a UUID) for user tokens, but for the
// `client_credentials` grant `sub` equals the `client_id` — an opaque
// varchar, not a UUID. Querying Postgres with a non-UUID value would raise
// `22P02` (invalid input syntax for type uuid) and surface as a 500. Since a
// non-UUID subject can never own a UUID-keyed client row, treat it as
// "no clients" rather than letting it reach the database.
const uuidSubjectSchema = z.uuid();

/**
 * Project an `oauth_clients` row down to the safe fields exposed by the
 * management API. The client secret hash and any internal-only columns
 * (e.g. `dynamicRegisteredAt`, `metadata`, `realmId`) are intentionally
 * never serialized.
 *
 * `policy` is the EFFECTIVE environment policy (ADR-008 §7) resolved from the
 * client's `environment` and its realm's `max_environment_laxity` ceiling via
 * {@link resolveEnvironmentPolicy}. Its `environment` and `staticApiKeysAllowed`
 * are surfaced read-only so the developer portal can label the client and gate
 * the API-keys create form (#98) — they are NEVER read from the request body
 * (create/update schemas omit them), so a developer cannot self-relax posture.
 */
function toClientResponse(client: OAuthClientRow, policy: EnvironmentPolicy) {
  return {
    id: client.id,
    clientId: client.clientId,
    name: client.name,
    description: client.description,
    redirectUris: client.redirectUris,
    scopes: client.scopes,
    grantTypes: client.grantTypes,
    responseTypes: client.responseTypes,
    tokenEndpointAuthMethod: client.tokenEndpointAuthMethod,
    enabled: client.enabled,
    suspended: client.suspended,
    requirePkce: client.requirePkce,
    environment: policy.environment,
    staticApiKeysAllowed: policy.staticApiKeysAllowed,
    createdAt: client.createdAt,
    updatedAt: client.updatedAt,
    lastUsedAt: client.lastUsedAt,
  };
}

// Path param for the single-client routes. The `id` column is a UUID; a
// malformed id can never match a row, but validating here yields a clean 400
// instead of letting a non-UUID reach Postgres (22P02 → 500).
const clientIdParamsSchema = z.object({ id: z.uuid() });

/**
 * Pull the developer's `users.id` off the verified JWT. The guard populates
 * `jwtPayload`, but we guard `sub` explicitly so we never act with an
 * undefined owner (defense-in-depth, matching the list route).
 */
function requireDeveloperId(request: { jwtPayload?: { sub?: string } }): string {
  const sub = request.jwtPayload?.sub;
  if (!sub) {
    throw new JWTInvalidError('Missing JWT payload');
  }
  return sub;
}

/**
 * Resolve a client the caller is allowed to act on, or throw `NotFoundError`.
 *
 * Ownership is enforced here for every per-client route (#87/#88/#89/#90):
 *
 * - A non-UUID subject (e.g. a `client_credentials` token whose `sub` is a
 *   `client_id`) can never own a UUID-keyed row → 404 without a DB hit.
 * - A row owned by a different developer is reported as **404, not 403**, so
 *   the API never confirms the existence of clients the caller does not own
 *   (avoids enumeration; OWASP API1/A01 BOLA).
 * - A client of another realm than the request's is not found at all (#489),
 *   the same 404.
 */
async function resolveOwnedClient(
  fastify: FastifyInstance,
  request: FastifyRequest,
  developerId: string,
  id: string
): Promise<OAuthClientRow> {
  if (!uuidSubjectSchema.safeParse(developerId).success) {
    throw new NotFoundError('OAuthClient', id);
  }

  const client = await fastify.repositories.oauthClients.findById(requestRealm(request).id, id);
  if (!client || client.developerId !== developerId) {
    throw new NotFoundError('OAuthClient', id);
  }
  return client;
}

/**
 * Resolve a client's EFFECTIVE environment policy (ADR-008 §7) by pairing it
 * with its realm ceiling. Routes through {@link resolveEnvironmentPolicy} — the
 * single source of truth — so the response's `environment` / `staticApiKeysAllowed`
 * always agree with what the static-API-key gate (#97) enforces, including a
 * realm pinned to `production`. A missing realm fails safe to `production`.
 */
async function resolveClientPolicy(
  fastify: FastifyInstance,
  client: OAuthClientRow
): Promise<EnvironmentPolicy> {
  const realm = await fastify.repositories.realms.findById(client.realmId);
  return resolveEnvironmentPolicy(client, realm ?? null);
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
 * Resolve the realm's effective dynamic-registration scope allowlist, seeding
 * it from `DEFAULT_DYNAMIC_REGISTRATION_SCOPES` on first use exactly as
 * `/oauth/register` does. The REST create/update paths reuse this same policy
 * so a developer cannot self-grant a scope through the management API that the
 * realm would refuse at dynamic registration — keeping the two
 * client-creation paths consistent. Seeding is best-effort: a racing write
 * never blocks the request.
 *
 * The list is read from the database, not from the realm resolver's row
 * (`request.realm`), which can be up to its cache time old (#487): the seed
 * must see a list an operator set since then, or it would overwrite it. A
 * realm that no longer exists permits no scope.
 */
async function resolveRealmAllowedScopes(
  fastify: FastifyInstance,
  realmId: string
): Promise<string[]> {
  const realm = await fastify.repositories.realms.findById(realmId);
  if (!realm) return [];
  let allowedScopes = realm.dynamicRegistrationAllowedScopes ?? [];
  if (allowedScopes.length === 0 && env.DEFAULT_DYNAMIC_REGISTRATION_SCOPES.length > 0) {
    allowedScopes = [...env.DEFAULT_DYNAMIC_REGISTRATION_SCOPES];
    try {
      await fastify.repositories.realms.update(realm.id, {
        dynamicRegistrationAllowedScopes: allowedScopes,
      });
    } catch (err) {
      fastify.log.warn(
        { err, realmId: realm.id },
        'Failed to persist default dynamic_registration_allowed_scopes'
      );
    }
  }
  return allowedScopes;
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
 * here too, since the list may come from the environment when the realm's
 * seed write failed.
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

export default async function (fastify: FastifyInstance) {
  const requireManagementJwt = createRequireManagementJwt(fastify);

  fastify.withTypeProvider<ZodTypeProvider>().get(
    '/',
    {
      preHandler: requireManagementJwt,
      schema: {
        description:
          'List the OAuth clients owned by the authenticated developer. Scoped by oauth_clients.developer_id. Requires a developer Bearer access token. Never returns the client secret. (Phase 2.2, issue #85.)',
        tags: ['Clients'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [401],
        security: [{ bearerAuth: [] }],
        response: { 200: listClientsResponseSchema },
      },
      config: { surface: 'api' },
    },
    async (request, reply) => {
      const payload = request.jwtPayload;
      if (!payload || !payload.sub) {
        // Defense-in-depth: the guard populates jwtPayload, but guard the
        // sub explicitly so we never query with an undefined owner.
        throw new JWTInvalidError('Missing JWT payload');
      }

      const developerId = payload.sub;

      // A non-UUID subject (e.g. a client_credentials token whose `sub` is a
      // `client_id`) can never own a client row, so short-circuit to an empty
      // list instead of issuing a query that Postgres would reject with 22P02.
      if (!uuidSubjectSchema.safeParse(developerId).success) {
        return reply.send({ clients: [] });
      }

      // `developer_id IS NULL` — the deliberate answer (#374).
      //
      // A client registered anonymously through RFC 7591 DCR, or materialised
      // from a CIMD document, has no developer to attribute to, so its
      // `developer_id` is NULL and it matches no caller here. That is correct
      // and intentional: inventing an owner would hand an anonymous caller's
      // client to whoever the server guessed.
      //
      // What changed with #374 is that a developer who registers WITH their
      // access token is now attributed and does appear below — the case that
      // was simply unserved before. An anonymous registration is still
      // unmanageable from the portal, by design, and `docs/conformance` aside,
      // the developer-facing statement of that lives in the portal guide and
      // the API reference so a developer meets it before wondering where their
      // client went.
      //
      // Any future developer-scoped query MUST make the same choice explicitly
      // rather than inheriting it: a `WHERE developer_id = $1` that silently
      // drops NULL rows reads as "you have none" when it means "these cannot be
      // attributed to anyone". And it must NOT be widened to
      // `OR developer_id IS NULL` — that equality is the only tenant boundary
      // on this table, so widening it would hand every party's dynamically
      // registered clients to every developer.
      //
      // Full reasoning, including why a CIMD client is not merely unowned but
      // NOT OWNABLE: `docs/adr/012-dynamic-client-ownership.md`.
      const rows = await fastify.repositories.oauthClients.listByDeveloper(
        requestRealm(request).id,
        developerId
      );

      // Resolve each client's effective policy against its realm ceiling. Realms
      // are cached per id within the request so a developer's clients (which all
      // share the developer's realm) cost a single realm lookup, not one per client.
      const realmCache = new Map<
        string,
        Awaited<ReturnType<FastifyInstance['repositories']['realms']['findById']>>
      >();
      const clients = [];
      for (const row of rows) {
        if (!realmCache.has(row.realmId)) {
          realmCache.set(row.realmId, await fastify.repositories.realms.findById(row.realmId));
        }
        const policy = resolveEnvironmentPolicy(row, realmCache.get(row.realmId) ?? null);
        clients.push(toClientResponse(row, policy));
      }

      return reply.send({ clients });
    }
  );

  // ── POST /api/clients — create a client (#86) ───────────────────────────
  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/',
    {
      preHandler: requireManagementJwt,
      schema: {
        description:
          'Create an OAuth client owned by the authenticated developer. The server generates the client_id and (for confidential clients) a client_secret; the plaintext secret is returned in THIS response only and never again. Requires a developer Bearer access token. (Phase 2.2, issue #86.)',
        tags: ['Clients'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [400, 401, 403],
        security: [{ bearerAuth: [] }],
        body: createClientRequestSchema,
        response: { 201: createClientResponseSchema },
      },
      config: {
        surface: 'api',
        // Create runs an argon2id hash on every call (confidential clients hash
        // the real secret; public clients hash a sentinel), so an authenticated
        // caller could otherwise burn CPU at the global default rate. Cap it
        // per-IP at the same budget as /oauth/register, whose comment notes the
        // hash makes "a burst-proof cap mandatory".
        rateLimit: {
          max: env.REGISTER_CLIENT_RATE_LIMIT,
          timeWindow: env.REGISTER_CLIENT_RATE_WINDOW * 1000,
          keyGenerator: realmRateLimitKey,
        },
      },
    },
    async (request, reply) => {
      const developerId = requireDeveloperId(request);

      // `developer_id` is a UUID column; a non-UUID subject (client_credentials
      // token) cannot own a client and must not be allowed to create one.
      if (!uuidSubjectSchema.safeParse(developerId).success) {
        throw new JWTInvalidError('A user access token is required to create clients');
      }

      const body = request.body as CreateClientRequest;

      const grantTypes = body.grantTypes ?? ['authorization_code', 'refresh_token'];
      const responseTypes = body.responseTypes ?? ['code'];
      const tokenEndpointAuthMethod = body.tokenEndpointAuthMethod ?? 'none';
      // Zod applies `.default([])`, but default defensively so the handler is
      // also correct when invoked without the schema layer (unit tests).
      const redirectUris = body.redirectUris ?? [];
      // De-duplicated, as dynamic registration does: the allowlist check
      // accepts any number of repeats of an allowed scope, and the row would
      // store them all.
      const scopes = [...new Set(body.scopes ?? [])];

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

      // The per-developer ceiling, also before hashing. `GET /api/clients`
      // returns every owned client at once; this is what bounds it.
      await assertDeveloperClientLimit(fastify, realm.id, developerId);

      const clientId = randomUUID();

      // Confidential clients get a real secret; public clients
      // (auth method `none`) store a non-verifiable sentinel hash so the
      // NOT NULL column is satisfied without minting a usable secret — and so
      // the hash length never leaks the client type (matches /oauth/register).
      const isPublic = tokenEndpointAuthMethod === 'none';
      let plaintextSecret: string | undefined;
      let clientSecretHash: string;
      if (isPublic) {
        clientSecretHash = await fastify.passwordHasher.hashPassword(
          randomBytes(32).toString('hex')
        );
      } else {
        const secret = await generateClientSecret(fastify);
        plaintextSecret = secret.plaintext;
        clientSecretHash = secret.hash;
      }

      const created = await fastify.repositories.oauthClients.create({
        realmId: realm.id,
        clientId,
        clientSecretHash,
        name: body.name,
        description: body.description ?? null,
        redirectUris,
        scopes,
        grantTypes,
        responseTypes,
        tokenEndpointAuthMethod,
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
        // column, so `PATCH` cannot write it either.
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

      // Response carries the plaintext secret once — MUST NOT be cached.
      reply.header('Cache-Control', 'no-store').header('Pragma', 'no-cache');
      return reply.code(201).send({
        ...toClientResponse(created, policy),
        ...(plaintextSecret ? { clientSecret: plaintextSecret } : {}),
      });
    }
  );

  // ── GET /api/clients/:id — get one owned client (#87) ───────────────────
  fastify.withTypeProvider<ZodTypeProvider>().get(
    '/:id',
    {
      preHandler: requireManagementJwt,
      schema: {
        description:
          "Get one of the authenticated developer's OAuth clients by id. Returns 404 if the client does not exist or is owned by another developer (no existence enumeration). Never returns the client secret. (Phase 2.2, issue #87.)",
        tags: ['Clients'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [400, 401, 404],
        security: [{ bearerAuth: [] }],
        params: clientIdParamsSchema,
        response: { 200: clientSchema },
      },
      config: { surface: 'api' },
    },
    async (request, reply) => {
      const developerId = requireDeveloperId(request);
      const { id } = request.params as { id: string };

      const client = await resolveOwnedClient(fastify, request, developerId, id);
      const policy = await resolveClientPolicy(fastify, client);

      return reply.send(toClientResponse(client, policy));
    }
  );

  // ── PATCH /api/clients/:id — update mutable fields (#88) ─────────────────
  fastify.withTypeProvider<ZodTypeProvider>().patch(
    '/:id',
    {
      preHandler: requireManagementJwt,
      schema: {
        description:
          "Update mutable fields of one of the developer's OAuth clients (name, description, redirectUris, scopes, grantTypes, responseTypes, tokenEndpointAuthMethod, enabled). client_id and client_secret are immutable here. enabled is the owner's switch and may be set either way; it does not lift an operator's suspension (the read-only suspended field), which only the operator can. Returns 404 if the client does not exist or is owned by another developer. (Phase 2.2, issue #88.)",
        tags: ['Clients'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [400, 401, 404],
        security: [{ bearerAuth: [] }],
        params: clientIdParamsSchema,
        body: updateClientRequestSchema,
        response: { 200: clientSchema },
      },
      config: { surface: 'api' },
    },
    async (request, reply) => {
      const developerId = requireDeveloperId(request);
      const { id } = request.params as { id: string };
      const body = request.body as UpdateClientRequest;
      // De-duplicated before the allowlist check and the write, as on create.
      const scopes = body.scopes === undefined ? undefined : [...new Set(body.scopes)];

      const existing = await resolveOwnedClient(fastify, request, developerId, id);

      // Validate the *effective* configuration: take each field from the
      // request when present, else fall back to the persisted value. This
      // catches an update that would leave the client in an inconsistent
      // state (e.g. removing authorization_code while keeping response_types,
      // or dropping the last redirect_uri from an authorization_code client).
      const grantTypes = body.grantTypes ?? existing.grantTypes;
      const responseTypes = body.responseTypes ?? existing.responseTypes;
      const tokenEndpointAuthMethod =
        body.tokenEndpointAuthMethod ?? existing.tokenEndpointAuthMethod;
      const redirectUris = body.redirectUris ?? existing.redirectUris;

      if (body.redirectUris) {
        for (const uri of body.redirectUris) {
          validateRedirectUri(uri, env.REDIRECT_URI_CUSTOM_SCHEMES);
        }
      }
      assertGrantResponseConsistency({
        grantTypes,
        responseTypes,
        tokenEndpointAuthMethod,
        redirectUris,
      });

      // Cap the scopes this update ADDS against the client's realm policy, the
      // same allowlist dynamic registration enforces — a developer must not
      // widen scopes via PATCH beyond what the realm permits. A scope the
      // client already holds is not checked again, so a client keeps one the
      // realm no longer allows (or an operator gave it) while its owner
      // renames it or edits another field and sends its scopes back.
      if (scopes !== undefined) {
        const added = scopes.filter((scope) => !existing.scopes.includes(scope));
        if (added.length > 0) {
          const allowedScopes = await resolveRealmAllowedScopes(fastify, existing.realmId);
          assertScopesAllowed(added, allowedScopes);
        }
      }

      // An operator's `provisioned_by_operator` vouches for the redirect URIs
      // as the operator wrote them (ANT-2026-O8U3P920). An owner who changes
      // them voids that, so the client loses the automatic error redirects.
      const redirectUrisChanged =
        body.redirectUris !== undefined &&
        JSON.stringify(body.redirectUris) !== JSON.stringify(existing.redirectUris);

      const changes = {
        ...(body.name !== undefined ? { name: body.name } : {}),
        ...(body.description !== undefined ? { description: body.description } : {}),
        ...(body.redirectUris !== undefined ? { redirectUris: body.redirectUris } : {}),
        ...(redirectUrisChanged ? { provisionedByOperator: false } : {}),
        ...(scopes !== undefined ? { scopes } : {}),
        ...(body.grantTypes !== undefined ? { grantTypes: body.grantTypes } : {}),
        ...(body.responseTypes !== undefined ? { responseTypes: body.responseTypes } : {}),
        ...(body.tokenEndpointAuthMethod !== undefined
          ? { tokenEndpointAuthMethod: body.tokenEndpointAuthMethod }
          : {}),
        // `enabled` is the owner's switch, both ways. An operator who must keep
        // a client off suspends it (`oauth_clients.suspended`), which no route
        // writes and this one never reads from the body (ANT-2026-DR5XI3LV).
        ...(body.enabled !== undefined ? { enabled: body.enabled } : {}),
      };
      const updated = await fastify.repositories.oauthClients.update(existing.realmId, id, changes);

      // The names of the settings written, never their values.
      await emitClientEventBestEffort(
        fastify,
        request,
        'urn:qauth:event:client.updated:v1-rc.0',
        { fields: Object.keys(changes) },
        { developerId, client: updated }
      );

      const policy = await resolveClientPolicy(fastify, updated);
      return reply.send(toClientResponse(updated, policy));
    }
  );

  // ── DELETE /api/clients/:id — delete a client (#89) ─────────────────────
  fastify.withTypeProvider<ZodTypeProvider>().delete(
    '/:id',
    {
      preHandler: requireManagementJwt,
      schema: {
        description:
          "Delete one of the developer's OAuth clients. Returns 404 if the client does not exist or is owned by another developer. After deletion the client can no longer authenticate. (Phase 2.2, issue #89.)",
        tags: ['Clients'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [400, 401, 404],
        security: [{ bearerAuth: [] }],
        params: clientIdParamsSchema,
        response: { 204: z.null() },
      },
      config: { surface: 'api' },
    },
    async (request, reply) => {
      const developerId = requireDeveloperId(request);
      const { id } = request.params as { id: string };

      // Ownership-check before deleting: delete-by-id alone cannot enforce it.
      const existing = await resolveOwnedClient(fastify, request, developerId, id);

      await fastify.repositories.oauthClients.delete(existing.realmId, id);

      await emitClientEventBestEffort(
        fastify,
        request,
        'urn:qauth:event:client.deleted:v1-rc.0',
        {},
        { developerId, client: existing }
      );

      reply.code(204);
      return reply.send(null);
    }
  );

  // ── POST /api/clients/:id/regenerate-secret — issue a new secret (#90) ──
  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/:id/regenerate-secret',
    {
      preHandler: requireManagementJwt,
      schema: {
        description:
          "Issue a new client_secret for one of the developer's OAuth clients. The previous secret is invalidated immediately and the new plaintext secret is returned in THIS response only. Returns 404 if the client does not exist or is owned by another developer; 400 for a public client that has no secret. (Phase 2.2, issue #90.)",
        tags: ['Clients'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [400, 401, 404],
        security: [{ bearerAuth: [] }],
        params: clientIdParamsSchema,
        response: { 200: regenerateSecretResponseSchema },
      },
      config: {
        surface: 'api',
        // Regeneration always runs an argon2id hash, so it carries the same
        // CPU-DoS profile as create — cap it per-IP at the same budget.
        rateLimit: {
          max: env.REGISTER_CLIENT_RATE_LIMIT,
          timeWindow: env.REGISTER_CLIENT_RATE_WINDOW * 1000,
          keyGenerator: realmRateLimitKey,
        },
      },
    },
    async (request, reply) => {
      const developerId = requireDeveloperId(request);
      const { id } = request.params as { id: string };

      const existing = await resolveOwnedClient(fastify, request, developerId, id);

      // A public client (auth method `none`) holds no usable secret, so
      // regeneration is meaningless and would mint a credential the client
      // cannot present. Reject rather than silently confidential-ising it.
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
      // invalidated, so a failing event write must not 500 and lose the
      // one-time plaintext (the client would be locked out of its own secret).
      await emitClientEventBestEffort(
        fastify,
        request,
        'urn:qauth:event:client.secret_rotated:v1-rc.0',
        {},
        { developerId, client: updated }
      );

      const policy = await resolveClientPolicy(fastify, updated);

      // Response carries the plaintext secret once — MUST NOT be cached.
      reply.header('Cache-Control', 'no-store').header('Pragma', 'no-cache');
      return reply.send({ ...toClientResponse(updated, policy), clientSecret: plaintext });
    }
  );

  // ── Static developer API keys (ADR-008 §6, issue #97) ───────────────────
  // Registered here so they share this module's `/api/clients` autoPrefix,
  // auth model (management token + developer-id ownership), and error shapes.
  await registerApiKeyRoutes(fastify);
}
