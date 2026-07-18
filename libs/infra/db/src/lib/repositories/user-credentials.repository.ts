import {
  extractConstraintName,
  isUniqueConstraintError,
  NotFoundError,
  UniqueConstraintError,
} from '@qauth-labs/shared-errors';
import { and, eq, sql } from 'drizzle-orm';

import type { NewUserCredential, UserCredential, UserCredentialsRepository } from '../../types';
import { DbClient } from '../db';
import { userCredentials } from '../schema/identity';

/**
 * Factory for the `user_credentials` repository (ADR-002/ADR-003, #228).
 *
 * `credential_data` stays `Record<string, unknown>` at this layer — shape
 * interpretation belongs to the provider that owns the `provider_type` (for
 * `'password'`: `passwordCredentialDataSchema` in `@qauth-labs/server-federation`),
 * keeping the repository provider-agnostic.
 */
export function createUserCredentialsRepository(defaultDb: DbClient): UserCredentialsRepository {
  return {
    /**
     * Create a credential row.
     *
     * @throws UniqueConstraintError on a `(realm_id, provider_type,
     * external_sub)` conflict — same wire behavior (generic 409) as the users
     * repository's duplicate-email error, so even the pathological path where
     * the credential index fires before the users index maps identically.
     */
    async create(data: NewUserCredential, tx?: DbClient): Promise<UserCredential> {
      const invoker = tx ?? defaultDb;
      try {
        const [credential] = await invoker.insert(userCredentials).values(data).returning();
        return credential;
      } catch (error) {
        if (isUniqueConstraintError(error)) {
          const constraint =
            extractConstraintName(error) || 'idx_user_credentials_realm_provider_sub_unique';
          throw new UniqueConstraintError(constraint, error);
        }
        throw error;
      }
    },

    async findById(id: string, tx?: DbClient): Promise<UserCredential | undefined> {
      const invoker = tx ?? defaultDb;
      const [credential] = await invoker
        .select()
        .from(userCredentials)
        .where(eq(userCredentials.id, id))
        .limit(1);
      return credential;
    },

    /**
     * The login/resend hot path: unique-index lookup on
     * `(realm_id, provider_type, external_sub)` — same performance profile as
     * the legacy `(realm_id, email_normalized)` lookup it replaces.
     */
    async findByRealmProviderSub(
      realmId: string,
      providerType: string,
      externalSub: string,
      tx?: DbClient
    ): Promise<UserCredential | undefined> {
      const invoker = tx ?? defaultDb;
      const [credential] = await invoker
        .select()
        .from(userCredentials)
        .where(
          and(
            eq(userCredentials.realmId, realmId),
            eq(userCredentials.providerType, providerType),
            eq(userCredentials.externalSub, externalSub)
          )
        )
        .limit(1);
      return credential;
    },

    /**
     * Resolve a user's credential for one provider type. Rollback-window
     * fallback for verification tokens whose `credential_id` is NULL (#228);
     * exactly one `'password'` row per user is guaranteed by #226/#228 writes.
     */
    async findByUserIdAndType(
      userId: string,
      providerType: string,
      tx?: DbClient
    ): Promise<UserCredential | undefined> {
      const invoker = tx ?? defaultDb;
      const [credential] = await invoker
        .select()
        .from(userCredentials)
        .where(
          and(eq(userCredentials.userId, userId), eq(userCredentials.providerType, providerType))
        )
        .limit(1);
      return credential;
    },

    /**
     * Flip `credential_data.email_verified` to true in place.
     *
     * A single `jsonb_set` statement — no read-modify-write — so a concurrent
     * writer touching a sibling key can never be clobbered. The ONLY
     * `credential_data` mutation shipped in #228.
     *
     * @throws NotFoundError if the credential does not exist.
     */
    async setEmailVerified(id: string, tx?: DbClient): Promise<UserCredential> {
      const invoker = tx ?? defaultDb;
      const now = Date.now();

      const [credential] = await invoker
        .update(userCredentials)
        .set({
          credentialData: sql`jsonb_set(${userCredentials.credentialData}, '{email_verified}', 'true'::jsonb)`,
          updatedAt: now,
        })
        .where(eq(userCredentials.id, id))
        .returning();

      if (!credential) {
        throw new NotFoundError('UserCredential', id);
      }
      return credential;
    },
  };
}
