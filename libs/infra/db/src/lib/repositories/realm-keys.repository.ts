import {
  extractConstraintName,
  isUniqueConstraintError,
  UniqueConstraintError,
} from '@qauth-labs/shared-errors';
import { and, asc, eq, isNull, type SQL } from 'drizzle-orm';

import type {
  NewRealmKeyInput,
  RealmKey,
  RealmKeyFilter,
  RealmKeysRepository,
  RealmPublicKey,
  WrappedRealmKey,
} from '../../types';
import { DbClient } from '../db';
import { realmKeys, realmPublicKeys } from '../schema/keys';

/**
 * Every `realm_keys` column except the wrapped material (`ciphertext`, `iv`,
 * `wrapped_dek`): the projection of every method but `getWrappedForSigner`.
 *
 * An allowlist, not "all columns minus three", so a column added later is
 * never selected by accident. A metadata column missing from it fails the
 * build instead, because the result would no longer be a {@link RealmKey}.
 */
const REALM_KEY_COLUMNS = {
  id: realmKeys.id,
  realmId: realmKeys.realmId,
  purpose: realmKeys.purpose,
  scopeId: realmKeys.scopeId,
  algorithm: realmKeys.algorithm,
  kid: realmKeys.kid,
  status: realmKeys.status,
  pairId: realmKeys.pairId,
  kekRef: realmKeys.kekRef,
  aadVersion: realmKeys.aadVersion,
  createdAt: realmKeys.createdAt,
  publishAt: realmKeys.publishAt,
  activateAt: realmKeys.activateAt,
  retireAt: realmKeys.retireAt,
  unpublishAt: realmKeys.unpublishAt,
  compromisedAt: realmKeys.compromisedAt,
} as const;

/**
 * Factory for the realm keys repository (ADR-019 Decision 9, issue #461).
 *
 * Storage only. Generating, wrapping and unwrapping keys belongs to the keys
 * library (#462, #463); the repository never sees plaintext key material.
 *
 * @param defaultDb - Database client to use for queries
 * @returns Repository implementing {@link RealmKeysRepository}
 */
export function createRealmKeysRepository(defaultDb: DbClient): RealmKeysRepository {
  return {
    async create(input: NewRealmKeyInput, tx?: DbClient): Promise<RealmKey> {
      const invoker = tx ?? defaultDb;
      try {
        // A savepoint inside an outer transaction, so the two inserts stay
        // all-or-nothing even when the caller catches the error and goes on.
        return await invoker.transaction(async (innerTx) => {
          const [created] = await innerTx
            .insert(realmKeys)
            .values(input.key)
            .returning(REALM_KEY_COLUMNS);

          if (input.publicJwk !== undefined) {
            await innerTx.insert(realmPublicKeys).values({
              realmId: created.realmId,
              kid: created.kid,
              purpose: created.purpose,
              algorithm: created.algorithm,
              status: created.status,
              publicJwk: input.publicJwk,
              publishAt: input.key.publishAt,
              unpublishAt: created.unpublishAt,
            });
          }

          return created;
        });
      } catch (error) {
        if (isUniqueConstraintError(error)) {
          const constraint = extractConstraintName(error) || 'realm_keys_realm_id_kid_unique';
          throw new UniqueConstraintError(constraint, error);
        }
        throw error;
      }
    },

    async findByKid(realmId: string, kid: string, tx?: DbClient): Promise<RealmKey | undefined> {
      const invoker = tx ?? defaultDb;
      const [key] = await invoker
        .select(REALM_KEY_COLUMNS)
        .from(realmKeys)
        .where(and(eq(realmKeys.realmId, realmId), eq(realmKeys.kid, kid)))
        .limit(1);
      return key;
    },

    async listByRealm(
      realmId: string,
      filter: RealmKeyFilter = {},
      tx?: DbClient
    ): Promise<RealmKey[]> {
      const invoker = tx ?? defaultDb;
      const conditions: SQL[] = [eq(realmKeys.realmId, realmId)];
      if (filter.purpose !== undefined) {
        conditions.push(eq(realmKeys.purpose, filter.purpose));
      }
      if (filter.scopeId === null) {
        conditions.push(isNull(realmKeys.scopeId));
      } else if (filter.scopeId !== undefined) {
        conditions.push(eq(realmKeys.scopeId, filter.scopeId));
      }
      if (filter.status !== undefined) {
        conditions.push(eq(realmKeys.status, filter.status));
      }
      return invoker
        .select(REALM_KEY_COLUMNS)
        .from(realmKeys)
        .where(and(...conditions))
        .orderBy(asc(realmKeys.createdAt), asc(realmKeys.id));
    },

    async listPublicByRealm(realmId: string, tx?: DbClient): Promise<RealmPublicKey[]> {
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

    async getWrappedForSigner(
      realmId: string,
      kid: string,
      tx?: DbClient
    ): Promise<WrappedRealmKey | undefined> {
      const invoker = tx ?? defaultDb;
      const [key] = await invoker
        .select()
        .from(realmKeys)
        .where(and(eq(realmKeys.realmId, realmId), eq(realmKeys.kid, kid)))
        .limit(1);
      return key;
    },
  };
}
