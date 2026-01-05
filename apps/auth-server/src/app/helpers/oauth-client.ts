import { randomBytes } from 'crypto';
import type { FastifyInstance } from 'fastify';

import { env } from '../../config/env';

/**
 * Get or create system OAuth client
 * Helper function to get the system OAuth client for direct login operations
 */
export async function getOrCreateSystemClient(realmId: string, fastify: FastifyInstance) {
  const systemClientId = env.SYSTEM_CLIENT_ID || 'system';

  let client = await fastify.repositories.oauthClients.findByClientId(realmId, systemClientId);

  if (!client) {
    // Generate random client secret (32 bytes = 64 hex characters)
    const clientSecret = randomBytes(32).toString('hex');

    // Hash the secret using password hasher
    const clientSecretHash = await fastify.passwordHasher.hashPassword(clientSecret);

    // Create system client with required configuration
    client = await fastify.repositories.oauthClients.create({
      realmId,
      clientId: systemClientId,
      clientSecretHash,
      name: 'System Client',
      redirectUris: [],
      grantTypes: ['refresh_token'],
      requirePkce: false,
      developerId: null,
    });
  }

  return client;
}
