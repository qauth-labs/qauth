import { NotFoundError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyRequest } from 'fastify';

import { assertStaticApiKeysAllowed, generateApiKey } from './api-key';
import { resolveOwnedClient } from './developer-clients';
import { emitUserEvent } from './user-events';

/**
 * Static developer API keys (ADR-008 §6, issue #97): the domain logic of the
 * legacy `/api/clients/:clientId/api-keys` routes and of the developer API's
 * `/developer/v1-rc.0/clients/{clientId}/api-keys` (#524), shared so the two
 * cannot drift. Each route keeps only its own representation.
 *
 * A key hangs off a client the caller owns: a client owned by another
 * developer (or a non-UUID subject) is reported as 404, never 403, so
 * existence is never leaked (OWASP API1/A01 BOLA).
 *
 * The environment GATE is the heart of #97: a key may be minted ONLY while the
 * client resolves to `staticApiKeysAllowed` via
 * `resolveEnvironmentPolicy(client, realm)` — fail-safe, so an unset /
 * `production` client is refused with 403 and steered to `client_credentials`.
 * The gate lives entirely in `helpers/api-key.ts`.
 */

/** The shape of a single `api_keys` row as returned by the repository. */
export type ApiKeyRow = Awaited<
  ReturnType<FastifyInstance['repositories']['apiKeys']['listByClient']>
>[number];

/**
 * Mint a key for a client the caller owns, and record `api_key.created`.
 *
 * The environment gate runs before the argon2id hash, so a forbidden request
 * never pays its cost or persists. The plaintext `key` is returned once.
 */
export async function mintDeveloperApiKey(
  fastify: FastifyInstance,
  request: FastifyRequest,
  developerId: string,
  clientId: string,
  name: string
): Promise<{ apiKey: ApiKeyRow; key: string }> {
  const client = await resolveOwnedClient(fastify, request, developerId, clientId);

  // ENVIRONMENT GATE (ADR-008 §6): resolve the client's effective policy and
  // refuse minting (403) unless static API keys are allowed.
  const realm = await fastify.repositories.realms.findById(client.realmId);
  assertStaticApiKeysAllowed(client, realm ?? null);

  const generated = await generateApiKey(fastify);

  const created = await fastify.repositories.apiKeys.create({
    realmId: client.realmId,
    clientId: client.id,
    developerId,
    name,
    keyHash: generated.keyHash,
    prefix: generated.prefix,
    last4: generated.last4,
  });

  // Best-effort event: the key (and its hash) is already committed, so a
  // failing event write must not 500 and lose the one-time plaintext. The
  // developer acts; the key is the subject, never its prefix.
  try {
    await emitUserEvent(
      request,
      'urn:qauth:event:api_key.created:v1-rc.0',
      {},
      {
        realmId: client.realmId,
        userId: developerId,
        subject: { type: 'api_key', id: created.id },
        clientId: client.clientId,
        actor: 'user',
      }
    );
  } catch (err) {
    fastify.log.warn({ err, apiKeyId: created.id }, 'Failed to record the api_key.created event');
  }

  return { apiKey: created, key: generated.key };
}

/**
 * Revoke one key of a client the caller owns (idempotent soft-delete), and
 * record `api_key.revoked`. A key of another client is 404, so a key id is
 * never confirmed across ownership boundaries.
 */
export async function revokeDeveloperApiKey(
  fastify: FastifyInstance,
  request: FastifyRequest,
  developerId: string,
  clientId: string,
  keyId: string
): Promise<ApiKeyRow> {
  const client = await resolveOwnedClient(fastify, request, developerId, clientId);

  const existing = await fastify.repositories.apiKeys.findById(client.realmId, keyId);
  if (!existing || existing.clientId !== client.id) {
    throw new NotFoundError('ApiKey', keyId);
  }

  const revoked = await fastify.repositories.apiKeys.revoke(client.realmId, keyId);
  if (!revoked) {
    // Concurrent hard-delete or vanished row — treat as not found.
    throw new NotFoundError('ApiKey', keyId);
  }

  try {
    await emitUserEvent(
      request,
      'urn:qauth:event:api_key.revoked:v1-rc.0',
      {},
      {
        realmId: client.realmId,
        userId: developerId,
        subject: { type: 'api_key', id: revoked.id },
        clientId: client.clientId,
        actor: 'user',
      }
    );
  } catch (err) {
    fastify.log.warn({ err, apiKeyId: revoked.id }, 'Failed to record the api_key.revoked event');
  }

  return revoked;
}
