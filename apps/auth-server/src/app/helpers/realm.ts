import type { FastifyInstance } from 'fastify';

import { env } from '../../config/env';

/**
 * Get or create default realm
 * Helper function to get the default realm for user operations
 */
export async function getOrCreateDefaultRealm(fastify: FastifyInstance) {
  const defaultRealmName = env.DEFAULT_REALM_NAME;
  let realm = await fastify.repositories.realms.findByName(defaultRealmName);

  if (!realm) {
    realm = await fastify.repositories.realms.create({
      name: defaultRealmName,
      enabled: true,
    });
  }

  return realm;
}
