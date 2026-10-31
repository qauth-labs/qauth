import type { FastifyInstance } from 'fastify';

import { hasSystemClientAudience, SYSTEM_CLIENT_AUDIENCE, systemClientId } from './oauth-client';

/**
 * The boot step of #524: give the system client of every realm that has one
 * the developer audience ({@link SYSTEM_CLIENT_AUDIENCE}), so every portal
 * token `/auth/login` mints from now on carries it. A realm without a system
 * client gets none here: `/auth/login` creates it, with the audience, on the
 * realm's first sign-in.
 *
 * An audience an operator set by hand is replaced too: the developer API
 * accepts no other, so a portal token with another would work nowhere.
 * Idempotent, so every node may run it as it boots.
 *
 * @returns how many rows it changed
 */
export async function giveSystemClientsTheDeveloperAudience(
  fastify: FastifyInstance
): Promise<number> {
  const clientId = systemClientId();
  let changed = 0;
  for (const realm of await fastify.repositories.realms.listPolicyRecords()) {
    const client = await fastify.repositories.oauthClients.findByClientId(realm.realmId, clientId);
    if (client === undefined || hasSystemClientAudience(client.audience)) continue;
    await fastify.repositories.oauthClients.update(realm.realmId, client.id, {
      audience: [...SYSTEM_CLIENT_AUDIENCE],
    });
    changed++;
  }
  return changed;
}
