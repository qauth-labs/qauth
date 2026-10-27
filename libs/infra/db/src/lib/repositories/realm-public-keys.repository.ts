import { asc, eq } from 'drizzle-orm';

import type { RealmPublicKey, RealmPublicKeysRepository } from '../../types';
import { DbClient } from '../db';
import { realmPublicKeys } from '../schema/keys';

/**
 * The published keys of each realm (`realm_public_keys`, ADR-019 Decision 9).
 *
 * Public material only: the table's CHECKs refuse a private JWK member. Every
 * service role reads it (#495): a process without the signer verifies a
 * realm's tokens with these keys and serves them as the realm's JWKS (#491),
 * while only the signer reads `realm_keys`.
 */
export function createRealmPublicKeysRepository(defaultDb: DbClient): RealmPublicKeysRepository {
  return {
    async listByRealm(realmId: string, tx?: DbClient): Promise<RealmPublicKey[]> {
      const invoker = tx ?? defaultDb;
      return invoker
        .select()
        .from(realmPublicKeys)
        .where(eq(realmPublicKeys.realmId, realmId))
        .orderBy(
          asc(realmPublicKeys.purpose),
          asc(realmPublicKeys.publishAt),
          asc(realmPublicKeys.kid)
        );
    },
  };
}
