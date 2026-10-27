import { NotFoundError } from '@qauth-labs/shared-errors';
import {
  and,
  eq,
  getTableColumns,
  gt,
  gte,
  inArray,
  lt,
  notExists,
  type SQL,
  sql,
} from 'drizzle-orm';
import { alias } from 'drizzle-orm/pg-core';

import type {
  NewRefreshToken,
  RefreshFamilyRevocation,
  RefreshToken,
  RefreshTokensRepository,
} from '../../types';
import { DbClient } from '../db';
import { oauthClients } from '../schema/core';
import { refreshTokens } from '../schema/tokens';

/**
 * Serialise refresh-token rotation against bulk revocation for one user.
 *
 * A bulk revocation (`revokeFamily`, `revokeAllForUser`,
 * `revokeAllForUserAndClient`) is a single `UPDATE ... WHERE revoked = false`.
 * Under READ COMMITTED it blocks on the parent row of a rotation that is in
 * flight, re-checks that row once the rotation commits, finds it already
 * revoked, and never sees the child the rotation inserted — so the child
 * stays live after replay detection, consent revocation or logout.
 *
 * A transaction-scoped advisory lock keyed on the user closes that window:
 * rotation holds it shared for the length of its transaction, every bulk
 * revocation holds it exclusive, so the revoking UPDATE takes its snapshot
 * only after each in-flight rotation has committed, and a rotation that
 * starts afterwards loses its compare-and-set on the revoked parent. Both
 * sides take it before any row lock, so they cannot deadlock. A NULL key
 * (no such token) locks nothing. The id is hashed as a `uuid` rendered to
 * text, so a caller's id string and the id read from a row always give the
 * same key whatever their spelling.
 *
 * @param userId - Owner of the tokens: a user id, or a subquery resolving one
 */
async function lockUserTokens(
  invoker: DbClient,
  mode: 'rotate' | 'revoke',
  userId: string | SQL
): Promise<void> {
  const key = sql`hashtextextended((${userId})::uuid::text, 0)`;
  await invoker.execute(
    mode === 'rotate'
      ? sql`select pg_advisory_xact_lock_shared(${key})`
      : sql`select pg_advisory_xact_lock(${key})`
  );
}

/**
 * Read refresh-token rows of one realm's clients (#489). `refresh_tokens` has
 * no realm column: the client the token was issued to pins the realm, so the
 * read joins it and filters on its realm. A token of another realm is then no
 * row at all, from the same single query an unknown hash gets.
 */
function selectRealmTokens(invoker: DbClient, realmId: string, where: SQL | undefined) {
  return invoker
    .select(getTableColumns(refreshTokens))
    .from(refreshTokens)
    .innerJoin(oauthClients, eq(refreshTokens.oauthClientId, oauthClients.id))
    .where(and(eq(oauthClients.realmId, realmId), where));
}

/**
 * Factory function that creates a refresh tokens repository
 *
 * @param defaultDb - Database client to use for queries
 * @returns Repository object with token methods
 */
export function createRefreshTokensRepository(defaultDb: DbClient): RefreshTokensRepository {
  return {
    /**
     * Create a new refresh token
     *
     * @param data - Token data to create
     * @param tx - Optional transaction client
     * @returns Created token
     */
    async create(data: NewRefreshToken, tx?: DbClient): Promise<RefreshToken> {
      const invoker = tx ?? defaultDb;
      const [token] = await invoker.insert(refreshTokens).values(data).returning();
      return token;
    },

    /**
     * Find a token by its token hash
     * Only returns tokens that are not revoked and not expired
     *
     * @param realmId - Realm the request was resolved to; a token issued to a
     * client of another realm is not found
     * @param tokenHash - SHA-256 hash of the token
     * @param tx - Optional transaction client
     * @returns Token if found and valid, undefined otherwise
     */
    async findByTokenHash(
      realmId: string,
      tokenHash: string,
      tx?: DbClient
    ): Promise<RefreshToken | undefined> {
      const invoker = tx ?? defaultDb;
      const now = Date.now();

      const [result] = await selectRealmTokens(
        invoker,
        realmId,
        and(
          eq(refreshTokens.tokenHash, tokenHash),
          eq(refreshTokens.revoked, false),
          gt(refreshTokens.expiresAt, now)
        )
      ).limit(1);

      return result;
    },

    /**
     * Find a token by its token hash ignoring `revoked`/`expiresAt`.
     *
     * Used to detect replay of a revoked refresh token (OAuth 2.1 §4.3.1).
     * Callers MUST verify liveness/expiry before trusting the returned row.
     * Realm-scoped as {@link findByTokenHash} is, so a token of another realm
     * never reaches the replay logic that revokes its family.
     */
    async findByTokenHashIncludingRevoked(
      realmId: string,
      tokenHash: string,
      tx?: DbClient
    ): Promise<RefreshToken | undefined> {
      const invoker = tx ?? defaultDb;

      const [result] = await selectRealmTokens(
        invoker,
        realmId,
        eq(refreshTokens.tokenHash, tokenHash)
      ).limit(1);

      return result;
    },

    /**
     * Find all active tokens for a user
     * Returns tokens that are not revoked and not expired
     *
     * @param userId - User ID to find tokens for
     * @param tx - Optional transaction client
     * @returns Array of active tokens for the user
     */
    async findByUserId(userId: string, tx?: DbClient): Promise<RefreshToken[]> {
      const invoker = tx ?? defaultDb;
      const now = Date.now();

      return await invoker
        .select()
        .from(refreshTokens)
        .where(
          and(
            eq(refreshTokens.userId, userId),
            eq(refreshTokens.revoked, false),
            gt(refreshTokens.expiresAt, now)
          )
        );
    },

    /**
     * Revoke a token by ID
     * Sets revoked=true, revokedAt=now, and optional revocation reason
     *
     * @param id - Token ID to revoke
     * @param reason - Optional reason for revocation
     * @param tx - Optional transaction client
     * @returns Updated token
     * @throws NotFoundError if token is not found
     */
    async revoke(id: string, reason?: string, tx?: DbClient): Promise<RefreshToken> {
      const invoker = tx ?? defaultDb;
      const now = Date.now();

      const [token] = await invoker
        .update(refreshTokens)
        .set({
          revoked: true,
          revokedAt: now,
          revokedReason: reason ?? null,
        })
        .where(eq(refreshTokens.id, id))
        .returning();

      if (!token) {
        throw new NotFoundError('RefreshToken', id);
      }

      return token;
    },

    /**
     * Revoke a token only if it is still live (compare-and-set on
     * `revoked = false`), mirroring `authorizationCodes.markUsed`.
     *
     * This is the rotation step, so it takes the user's rotation lock (see
     * `lockUserTokens`) — meaningful only inside the caller's transaction,
     * which must also hold the child's insert.
     *
     * @returns The revoked row, or `undefined` when nothing was updated
     */
    async revokeIfActive(
      id: string,
      reason: string,
      tx?: DbClient
    ): Promise<RefreshToken | undefined> {
      const invoker = tx ?? defaultDb;

      await lockUserTokens(
        invoker,
        'rotate',
        sql`select ${refreshTokens.userId} from ${refreshTokens} where ${refreshTokens.id} = ${id}`
      );

      const [token] = await invoker
        .update(refreshTokens)
        .set({
          revoked: true,
          revokedAt: Date.now(),
          revokedReason: reason,
        })
        .where(and(eq(refreshTokens.id, id), eq(refreshTokens.revoked, false)))
        .returning();

      return token;
    },

    /**
     * Revoke every token in a refresh-token family in a single statement.
     *
     * When a revoked refresh token is replayed, OAuth 2.1 §4.3.1 /
     * RFC 9700 §2.2.2 require the whole family to be revoked — the
     * replay indicates either the legitimate client or an attacker is
     * using a stolen token. Only rows that are currently NOT revoked
     * are touched so the earliest `revokedReason` is preserved for audit.
     *
     * @param familyId - Family identifier shared by every rotation
     * @param reason - Optional reason string ('replay_detected' etc.)
     * @param tx - Optional transaction client
     * @returns Count of rows whose state was changed.
     */
    async revokeFamily(familyId: string, reason?: string, tx?: DbClient): Promise<number> {
      const now = Date.now();

      // The revocation lock must be held across the UPDATE, so a caller
      // that supplies no `tx` gets a transaction opened here.
      const run = async (invoker: DbClient): Promise<number> => {
        await lockUserTokens(
          invoker,
          'revoke',
          sql`select ${refreshTokens.userId} from ${refreshTokens} where ${refreshTokens.familyId} = ${familyId} limit 1`
        );

        const updated = await invoker
          .update(refreshTokens)
          .set({
            revoked: true,
            revokedAt: now,
            revokedReason: reason ?? null,
          })
          .where(and(eq(refreshTokens.familyId, familyId), eq(refreshTokens.revoked, false)))
          .returning({ id: refreshTokens.id });

        return updated.length;
      };

      return tx ? run(tx) : defaultDb.transaction((innerTx) => run(innerTx));
    },

    /**
     * Revoke the family an authorization code's redemption started.
     *
     * A second redemption of a code (OAuth 2.1 §4.1.3, ADR-017 Decision 10)
     * revokes every token the first one led to. The family is found through
     * its first token, the one that carries `authorization_code_id`; every
     * rotation shares its `family_id`. Takes the same revocation lock as
     * `revokeFamily`, so a rotation in flight either commits first and its
     * child is revoked here, or starts after and loses its compare-and-set.
     * Already-revoked rows keep their original reason.
     *
     * @param authorizationCodeId - The code row's id
     * @param reason - Recorded as `revokedReason`
     * @param tx - Optional transaction client
     * @returns The family the code started, `null` when it started none (no
     *   stored consent, a previous release redeemed it), and the count of rows
     *   revoked by this call: 0 also when the family is already revoked.
     */
    async revokeFamilyByAuthorizationCode(
      authorizationCodeId: string,
      reason: string,
      tx?: DbClient
    ): Promise<RefreshFamilyRevocation> {
      const now = Date.now();

      const run = async (invoker: DbClient): Promise<RefreshFamilyRevocation> => {
        await lockUserTokens(
          invoker,
          'revoke',
          sql`select ${refreshTokens.userId} from ${refreshTokens} where ${refreshTokens.authorizationCodeId} = ${authorizationCodeId}`
        );

        // Read under the lock, so a second replay still names the family it
        // finds already revoked.
        const [first] = await invoker
          .select({ familyId: refreshTokens.familyId })
          .from(refreshTokens)
          .where(eq(refreshTokens.authorizationCodeId, authorizationCodeId))
          .limit(1);

        const updated = await invoker
          .update(refreshTokens)
          .set({
            revoked: true,
            revokedAt: now,
            revokedReason: reason,
          })
          .where(
            and(
              inArray(
                refreshTokens.familyId,
                invoker
                  .select({ familyId: refreshTokens.familyId })
                  .from(refreshTokens)
                  .where(eq(refreshTokens.authorizationCodeId, authorizationCodeId))
              ),
              eq(refreshTokens.revoked, false)
            )
          )
          .returning({ id: refreshTokens.id });

        return { familyId: first?.familyId ?? null, revokedCount: updated.length };
      };

      return tx ? run(tx) : defaultDb.transaction((innerTx) => run(innerTx));
    },

    /**
     * Revoke all active tokens for a user
     * Useful for "logout all sessions" functionality
     *
     * @param userId - User ID whose tokens should be revoked
     * @param reason - Optional reason for revocation
     * @param tx - Optional transaction client
     */
    async revokeAllForUser(userId: string, reason?: string, tx?: DbClient): Promise<void> {
      const now = Date.now();

      const run = async (invoker: DbClient): Promise<void> => {
        await lockUserTokens(invoker, 'revoke', userId);

        await invoker
          .update(refreshTokens)
          .set({
            revoked: true,
            revokedAt: now,
            revokedReason: reason ?? null,
          })
          .where(
            and(
              eq(refreshTokens.userId, userId),
              eq(refreshTokens.revoked, false),
              gt(refreshTokens.expiresAt, now)
            )
          );
      };

      return tx ? run(tx) : defaultDb.transaction((innerTx) => run(innerTx));
    },

    /**
     * Revoke every active refresh token a user holds for one client
     * (consent revocation). Already-revoked rows keep their original reason.
     *
     * @returns Count of rows revoked by this call
     */
    async revokeAllForUserAndClient(
      userId: string,
      oauthClientId: string,
      reason: string,
      tx?: DbClient
    ): Promise<number> {
      const run = async (invoker: DbClient): Promise<number> => {
        await lockUserTokens(invoker, 'revoke', userId);

        const updated = await invoker
          .update(refreshTokens)
          .set({
            revoked: true,
            revokedAt: Date.now(),
            revokedReason: reason,
          })
          .where(
            and(
              eq(refreshTokens.userId, userId),
              eq(refreshTokens.oauthClientId, oauthClientId),
              eq(refreshTokens.revoked, false)
            )
          )
          .returning({ id: refreshTokens.id });

        return updated.length;
      };

      return tx ? run(tx) : defaultDb.transaction((innerTx) => run(innerTx));
    },

    /**
     * Delete the families whose every token has expired.
     *
     * A family is deleted whole, and only once its newest token has expired.
     * A rotated token stays in place while any token of its family is live,
     * so a replay of it is still found revoked and still revokes the family
     * (RFC 9700 §4.14.2): deleting it at its own expiry would turn that
     * replay into an unknown token and leave the family alive. Revoked
     * families follow the same rule.
     *
     * @param tx - Optional transaction client
     * @returns Count of deleted tokens
     */
    async deleteExpired(tx?: DbClient): Promise<number> {
      const invoker = tx ?? defaultDb;
      const now = Date.now();
      const live = alias(refreshTokens, 'live');

      const deleted = await invoker
        .delete(refreshTokens)
        .where(
          and(
            lt(refreshTokens.expiresAt, now),
            notExists(
              invoker
                .select({ one: sql`1` })
                .from(live)
                .where(and(eq(live.familyId, refreshTokens.familyId), gte(live.expiresAt, now)))
            )
          )
        )
        .returning({ id: refreshTokens.id });

      return deleted.length;
    },
  };
}
