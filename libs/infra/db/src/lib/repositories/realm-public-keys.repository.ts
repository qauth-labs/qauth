import { asc, eq, sql } from 'drizzle-orm';

import type { DeniedRealmKey, RealmPublicKey, RealmPublicKeysRepository } from '../../types';
import { DbClient } from '../db';
import { realmKeyDenylist, realmPublicKeys } from '../schema/keys';

/**
 * The published keys of each realm (`realm_public_keys`, ADR-019 Decision 9).
 *
 * Public material only: the table's CHECKs refuse a private JWK member. Every
 * service role reads it (#495): a process without the signer verifies a
 * realm's tokens with these keys and serves them as the realm's JWKS (#491),
 * while only the signer reads `realm_keys`. The `kid` denylist of emergency
 * retirement (#551) is read here too, by every role.
 */

/**
 * How long a read of the denylist waits for a lock, and runs at most, in ms.
 * Each node reads it every few seconds and gives up waiting after 5 s: a read
 * stuck behind a lock must fail and free its pooled connection before the
 * next one starts, or the reads would take the pool.
 */
export const KEY_DENYLIST_READ_LOCK_TIMEOUT_MS = 2_000;
export const KEY_DENYLIST_READ_STATEMENT_TIMEOUT_MS = 4_000;

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

    async listDenied(tx?: DbClient): Promise<DeniedRealmKey[]> {
      const read = (invoker: DbClient) =>
        invoker
          .select()
          .from(realmKeyDenylist)
          .orderBy(asc(realmKeyDenylist.realmId), asc(realmKeyDenylist.kid));
      // In the caller's transaction, its own limits apply.
      if (tx !== undefined) return read(tx);
      return defaultDb.transaction(async (innerTx) => {
        // Transaction-local: the pooled connection keeps its own settings.
        await innerTx.execute(
          sql`select set_config('lock_timeout', ${`${KEY_DENYLIST_READ_LOCK_TIMEOUT_MS}ms`}, true),
                     set_config('statement_timeout', ${`${KEY_DENYLIST_READ_STATEMENT_TIMEOUT_MS}ms`}, true)`
        );
        return read(innerTx);
      });
    },
  };
}
