import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { env } from '../../../config/env';
import { sendDeprecationHeaders } from '../../api-conventions/deprecation';
import {
  applyClientChange,
  createDeveloperClient,
  deleteDeveloperClient,
  isDeveloperSubject,
  type OAuthClientRow,
  recordClientUpdated,
  regenerateDeveloperClientSecret,
  requireDeveloperId,
  resolveClientPolicy,
  resolveOwnedClient,
  withClientPolicies,
} from '../../helpers/developer-clients';
import { type EnvironmentPolicy } from '../../helpers/environment-policy';
import { createRequireManagementJwt } from '../../helpers/management-token';
import { realmRateLimitKey } from '../../helpers/realm-rate-limit';
import { requestRealm } from '../../helpers/request-realm';
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
 * Client-management JSON API (Phase 2.2, task 2.2.1 — issue #85).
 *
 * DEPRECATED since #524: the developer API serves the same clients at
 * `/developer/v1-rc.0/clients` (`routes/developer`), in the API conventions'
 * representation. These paths keep their own response shape until the
 * release-candidate cleanup removes them; every response carries the
 * `Deprecation` header, and each operation is `deprecated: true` in the
 * OpenAPI document. The domain logic both share is in
 * `helpers/developer-clients.ts`.
 *
 * Mounted at `/api/clients` via the `autoPrefix` export below — the route
 * manifest registers it under `autoPrefix` rather than the directory-derived
 * prefix, so sibling routes added here register against the resource root
 * (`/`, `/:id`, `/:id/secret`, …) and land under `/api/clients`.
 *
 * Auth model
 * ----------
 * Every endpoint requires the developer-portal management token via
 * `createRequireManagementJwt` (Bearer JWT): the access token `/auth/login`
 * mints for the system client. The guard runs `fastify.requireJwt`
 * (signature, issuer, revocation) and then `assertManagementToken`, which
 * rejects a token issued to any other client, bound to any other audience, or
 * carrying an `act` claim. Both throw `JWTInvalidError` (HTTP 401), so
 * unauthenticated callers never reach a handler.
 *
 * `request.jwtPayload.sub` is the developer's `users.id`. A client that exists
 * but is owned by another developer is reported as **404** (not 403) so the
 * API never leaks the existence of clients the caller does not own.
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

/**
 * Project an `oauth_clients` row down to the safe fields exposed by the
 * management API. The client secret hash and any internal-only columns
 * (e.g. `dynamicRegisteredAt`, `metadata`, `realmId`) are intentionally
 * never serialized.
 *
 * `policy` is the EFFECTIVE environment policy (ADR-008 §7) resolved from the
 * client's `environment` and its realm's `max_environment_laxity` ceiling via
 * `resolveEnvironmentPolicy`. Its `environment` and `staticApiKeysAllowed`
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

export default async function (fastify: FastifyInstance) {
  const requireManagementJwt = createRequireManagementJwt(fastify);
  // Deprecated since #524: every response says so (RFC 9745).
  sendDeprecationHeaders(fastify);

  fastify.withTypeProvider<ZodTypeProvider>().get(
    '/',
    {
      preHandler: requireManagementJwt,
      schema: {
        description:
          'List the OAuth clients owned by the authenticated developer. Scoped by oauth_clients.developer_id. Requires a developer Bearer access token. Never returns the client secret. (Phase 2.2, issue #85.)',
        tags: ['Clients'],
        'x-qauth-stability': 'stable',
        deprecated: true,
        'x-qauth-errors': [401],
        security: [{ bearerAuth: [] }],
        response: { 200: listClientsResponseSchema },
      },
      config: { surface: 'api' },
    },
    async (request, reply) => {
      const developerId = requireDeveloperId(request);

      // A non-UUID subject (e.g. a client_credentials token whose `sub` is a
      // `client_id`) can never own a client row, so short-circuit to an empty
      // list instead of issuing a query that Postgres would reject with 22P02.
      if (!isDeveloperSubject(developerId)) {
        return reply.send({ clients: [] });
      }

      // `developer_id IS NULL` — the deliberate answer (#374).
      //
      // A client registered anonymously through RFC 7591 DCR, or materialised
      // from a CIMD document, has no developer to attribute to, so its
      // `developer_id` is NULL and it matches no caller here. That is correct
      // and intentional: inventing an owner would hand an anonymous caller's
      // client to whoever the server guessed. It must NOT be widened to
      // `OR developer_id IS NULL`: that equality is the only tenant boundary
      // on this table. Full reasoning, including why a CIMD client is not
      // merely unowned but NOT OWNABLE:
      // `docs/adr/012-dynamic-client-ownership.md`.
      const rows = await fastify.repositories.oauthClients.listByDeveloper(
        requestRealm(request).id,
        developerId
      );
      const clients = (await withClientPolicies(fastify, rows)).map(({ client, policy }) =>
        toClientResponse(client, policy)
      );

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
        deprecated: true,
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
      const body = request.body as CreateClientRequest;

      const { client, policy, clientSecret } = await createDeveloperClient(
        fastify,
        request,
        developerId,
        body
      );

      // Response carries the plaintext secret once — MUST NOT be cached.
      reply.header('Cache-Control', 'no-store').header('Pragma', 'no-cache');
      return reply.code(201).send({
        ...toClientResponse(client, policy),
        ...(clientSecret ? { clientSecret } : {}),
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
        deprecated: true,
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
        deprecated: true,
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

      const existing = await resolveOwnedClient(fastify, request, developerId, id);
      const { client: updated, fields } = await applyClientChange(fastify, existing, body);
      await recordClientUpdated(fastify, request, developerId, updated, fields);

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
        deprecated: true,
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

      await deleteDeveloperClient(fastify, request, developerId, id);

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
        deprecated: true,
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

      const { client, policy, clientSecret } = await regenerateDeveloperClientSecret(
        fastify,
        request,
        developerId,
        id
      );

      // Response carries the plaintext secret once — MUST NOT be cached.
      reply.header('Cache-Control', 'no-store').header('Pragma', 'no-cache');
      return reply.send({ ...toClientResponse(client, policy), clientSecret });
    }
  );

  // ── Static developer API keys (ADR-008 §6, issue #97) ───────────────────
  // Registered here so they share this module's `/api/clients` autoPrefix,
  // auth model (management token + developer-id ownership), and error shapes.
  await registerApiKeyRoutes(fastify);
}
