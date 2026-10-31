import type { FastifyInstance } from 'fastify';

import { SYSTEM_CLIENT_AUDIENCE, systemClientId } from './oauth-client';

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
  // One statement, whatever the number of realms: the step runs in an
  // `onReady` hook, which Fastify bounds at 10 s.
  return fastify.repositories.oauthClients.setAudienceInEveryRealm(
    systemClientId(),
    SYSTEM_CLIENT_AUDIENCE
  );
}
