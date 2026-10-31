import { randomBytes } from 'node:crypto';

import type { FastifyInstance } from 'fastify';

import { env } from '../../config/env';
import { API_FAMILY_AUDIENCES } from '../api-conventions/families';

/** The `client_id` of the system client, the same in every realm. */
export function systemClientId(): string {
  return env.SYSTEM_CLIENT_ID || 'system';
}

/**
 * The `audience` of the system client: the developer API's (ADR-019 Decision
 * 7, #524). `/auth/login` mints the developer portal's token for this client,
 * so the token carries exactly the developer audience, which the developer
 * API's guard (`requireFamilyToken('developer')`) requires and the
 * deprecated `/api/*` routes (`assertManagementToken`) accept.
 *
 * Expand, then contract (ADR-018 §5): the release of #509 (#869) made every
 * node ACCEPT this audience on a portal token; this one MINTS it, and no
 * longer accepts the system client's `client_id` as a portal token's
 * audience.
 */
export const SYSTEM_CLIENT_AUDIENCE: readonly string[] = [API_FAMILY_AUDIENCES.developer];

/** Whether a stored `audience` is exactly {@link SYSTEM_CLIENT_AUDIENCE}. */
export function hasSystemClientAudience(audience: readonly string[] | null | undefined): boolean {
  return (
    Array.isArray(audience) &&
    audience.length === SYSTEM_CLIENT_AUDIENCE.length &&
    SYSTEM_CLIENT_AUDIENCE.every((value, index) => audience[index] === value)
  );
}

/**
 * Get or create system OAuth client
 * Helper function to get the system OAuth client for direct login operations
 *
 * The client is created with {@link SYSTEM_CLIENT_AUDIENCE}. A row whose
 * audience differs (one created before #524 has none, so its tokens carried
 * its `client_id`) is given it here, the first time it is read, as the boot
 * step (`giveSystemClientsTheDeveloperAudience`, `system-client-boot.ts`)
 * gives it to every row that exists at boot. A row a node of the previous
 * release creates during a rolling upgrade, for a realm's first sign-in, gets
 * it the next time a node of this release reads it; the token that node of
 * the previous release minted from it is refused, and its developer signs in
 * again.
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
    client = await fastify.repositories.oauthClients.update(realmId, client.id, {
      audience: [...SYSTEM_CLIENT_AUDIENCE],
    });
  }

  return client;
}
