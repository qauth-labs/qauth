import { randomBytes } from 'node:crypto';

import type { FastifyInstance } from 'fastify';

import { env } from '../../config/env';
import { API_FAMILY_AUDIENCES } from '../api-conventions/families';

/**
 * The `audience` of the system client: the developer API's (#509, ADR-019
 * Decision 7). `/auth/login` mints the developer portal's token for this
 * client, so the token carries exactly the developer audience, which the
 * developer family's guard requires. The legacy `/api/*` routes accept it
 * too (`assertManagementToken`).
 */
export const SYSTEM_CLIENT_AUDIENCE: readonly string[] = [API_FAMILY_AUDIENCES.developer];

/** The `client_id` of the system client, the same in every realm. */
export function systemClientId(): string {
  return env.SYSTEM_CLIENT_ID || 'system';
}

/** Whether a stored `audience` is exactly {@link SYSTEM_CLIENT_AUDIENCE}. */
function hasSystemClientAudience(audience: readonly string[] | null): boolean {
  return (
    audience !== null &&
    audience.length === SYSTEM_CLIENT_AUDIENCE.length &&
    SYSTEM_CLIENT_AUDIENCE.every((value, index) => audience[index] === value)
  );
}

/**
 * Get or create system OAuth client
 * Helper function to get the system OAuth client for direct login operations
 *
 * A system client created before #509 has no `audience`, so its tokens carried
 * its `client_id`. It is given {@link SYSTEM_CLIENT_AUDIENCE} the first time
 * it is read, once per realm; a token minted before that keeps working at the
 * legacy `/api/*` routes for its short life.
 */
export async function getOrCreateSystemClient(realmId: string, fastify: FastifyInstance) {
  const clientId = systemClientId();

  let client = await fastify.repositories.oauthClients.findByClientId(realmId, clientId);

  if (!client) {
    // Generate random client secret (32 bytes = 64 hex characters)
    const clientSecret = randomBytes(32).toString('hex');

    // Hash the secret using password hasher
    const clientSecretHash = await fastify.passwordHasher.hashPassword(clientSecret);

    // Create system client with required configuration
    client = await fastify.repositories.oauthClients.create({
      realmId,
      clientId,
      clientSecretHash,
      name: 'System Client',
      redirectUris: [],
      grantTypes: ['refresh_token'],
      requirePkce: false,
      developerId: null,
      audience: [...SYSTEM_CLIENT_AUDIENCE],
      // The server provisions this client itself, for its own first-party
      // login (ANT-2026-O8U3P920). It registers no redirect URI, so the marker
      // never sends an error response anywhere; it is set so that every
      // server-written client carries it consistently.
      provisionedByOperator: true,
    });
  } else if (!hasSystemClientAudience(client.audience)) {
    client = await fastify.repositories.oauthClients.update(client.id, {
      audience: [...SYSTEM_CLIENT_AUDIENCE],
    });
  }

  return client;
}
