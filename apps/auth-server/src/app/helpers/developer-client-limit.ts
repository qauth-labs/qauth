import { ForbiddenError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';

import { env } from '../../config/env';

/**
 * Refuse a new client for a developer who already owns
 * `MAX_CLIENTS_PER_DEVELOPER` of them (HTTP 403).
 *
 * `GET /api/clients` returns every client of the caller in one response, and
 * registration is open, so without a ceiling one self-registered account could
 * store enough rows that a few concurrent list requests run the process out of
 * heap, again after every restart. The route rate limits are per address and
 * per window, not per account, so they do not bound it.
 *
 * Called by `POST /api/clients` and by a `POST /oauth/register` that carries
 * the developer's token, before the argon2id hash. An anonymous registration
 * belongs to no developer and is not counted. The count and the insert are not
 * one transaction, so creates in flight together can pass the ceiling by their
 * number; every create after that is refused.
 */
export async function assertDeveloperClientLimit(
  fastify: FastifyInstance,
  developerId: string
): Promise<void> {
  const owned = await fastify.repositories.oauthClients.countByDeveloper(developerId);
  if (owned >= env.MAX_CLIENTS_PER_DEVELOPER) {
    throw new ForbiddenError(
      `Client limit reached: a developer may own at most ${env.MAX_CLIENTS_PER_DEVELOPER} clients`
    );
  }
}
