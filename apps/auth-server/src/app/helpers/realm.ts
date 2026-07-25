import type { FastifyInstance } from 'fastify';

import { env } from '../../config/env';

/**
 * A single `realms` row as returned by the repository. Derived from the
 * decorator type so we stay decoupled from `@qauth-labs/infra-db`
 * (auth-server depends on it only transitively via
 * `@qauth-labs/fastify-plugin-db`), matching the boundary that
 * `routes/clients/index.ts` keeps with its `OAuthClientRow` type.
 */
type RealmRow = NonNullable<
  Awaited<ReturnType<FastifyInstance['repositories']['realms']['findByName']>>
>;

/**
 * Get or create default realm
 * Helper function to get the default realm for user operations
 *
 * The return type is explicit rather than inferred: TypeScript 7 rejects the
 * inferred form with TS2883, because naming it would require a reference to
 * `PasswordPolicy` from a package auth-server does not depend on directly.
 */
export async function getOrCreateDefaultRealm(fastify: FastifyInstance): Promise<RealmRow> {
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
