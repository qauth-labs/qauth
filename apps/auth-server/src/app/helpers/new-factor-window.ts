import type { FastifyInstance } from 'fastify';

import { newFactorWindowOf } from './new-factors';

/**
 * How long a factor bound after a password-only sign-in stays new in the
 * realm `realmId` (#1064): {@link newFactorWindowOf}, read from its row at
 * the binding. A realm that does not exist binds nothing: the read throws.
 */
export async function newFactorWindowIn(
  fastify: Pick<FastifyInstance, 'policyStore' | 'repositories'>,
  realmId: string
): Promise<number> {
  const realm = await fastify.repositories.realms.findById(realmId);
  if (realm === undefined) throw new Error('a factor bound in a realm that does not exist');
  return newFactorWindowOf(fastify, realm);
}
