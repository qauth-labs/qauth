import { and, eq, gt, isNull, lt } from 'drizzle-orm';

import type {
  NewOid4vpRequestState,
  Oid4vpRequestState,
  Oid4vpRequestStatesRepository,
} from '../../types';
import { DbClient } from '../db';
import { oid4vpRequestStates } from '../schema/oid4vp';

/**
 * Factory for the OID4VP request-state repository (ADR-004, issue #233).
 *
 * @param defaultDb - Database client to use for queries
 * @returns Repository object with request-state methods
 */
export function createOid4vpRequestStatesRepository(
  defaultDb: DbClient
): Oid4vpRequestStatesRepository {
  return {
    /**
     * Persist a presentation request about to be sent to a wallet.
     *
     * @param data - request-state row (`stateHash` pre-digested by the caller)
     * @param tx - Optional transaction client
     * @returns the created row
     */
    async create(data: NewOid4vpRequestState, tx?: DbClient): Promise<Oid4vpRequestState> {
      const invoker = tx ?? defaultDb;
      const [created] = await invoker.insert(oid4vpRequestStates).values(data).returning();
      return created;
    },

    /**
     * Atomically consume a request state — exactly once, under concurrency.
     *
     * This is ONE statement on purpose, and the shape matters more than it looks:
     *
     * ```sql
     * UPDATE oid4vp_request_states
     *    SET redeemed_at = $now
     *  WHERE state_hash = $hash AND redeemed_at IS NULL AND expires_at > $now
     * RETURNING *
     * ```
     *
     * Postgres evaluates the predicate while holding the row lock, so two
     * concurrent POSTs carrying the same `state` are serialized: the loser
     * re-reads the row after the winner commits, sees `redeemed_at` set, matches
     * nothing and returns zero rows. A `SELECT` followed by an `UPDATE` — even
     * inside a transaction at READ COMMITTED — leaves a window where both
     * readers see a pending row, which is exactly how a presentation gets
     * replayed. `authorization_codes.markUsed` uses the same single-statement
     * guard for the same reason.
     *
     * Expiry is folded into the SAME predicate rather than checked afterwards,
     * so an expired state is never "consumed then rejected" — it is simply not
     * matched, and stays available to nothing.
     *
     * @param stateHash - SHA-256 digest of the `state` the wallet posted
     * @param tx - Optional transaction client
     * @returns the redeemed row, or undefined when unknown / expired / already
     * consumed — three cases the caller must not be able to tell apart.
     */
    async redeem(stateHash: string, tx?: DbClient): Promise<Oid4vpRequestState | undefined> {
      const invoker = tx ?? defaultDb;
      const now = Date.now();

      const [redeemed] = await invoker
        .update(oid4vpRequestStates)
        .set({ redeemedAt: now })
        .where(
          and(
            eq(oid4vpRequestStates.stateHash, stateHash),
            isNull(oid4vpRequestStates.redeemedAt),
            gt(oid4vpRequestStates.expiresAt, now)
          )
        )
        .returning();

      return redeemed;
    },

    /**
     * Atomically consume a request state by its encryption `kid` (#377 Phase C).
     *
     * ```sql
     * UPDATE oid4vp_request_states
     *    SET redeemed_at = $now
     *  WHERE response_encryption_kid = $kid AND redeemed_at IS NULL AND expires_at > $now
     * RETURNING *
     * ```
     *
     * Byte-for-byte the shape of {@link redeem} above, on the other correlator,
     * and it is load-bearing that it stays so: the row lock serializes two
     * concurrent posts carrying the same `kid`, and folding expiry into the
     * predicate means an expired row is never "consumed then rejected". The
     * lookup is a probe on `idx_oid4vp_request_states_encryption_kid`, the
     * UNIQUE partial index over live rows — which is also what guarantees the
     * predicate can match at most one row, so `RETURNING *` never has to pick.
     *
     * The `kid` is bounded by the caller before it reaches here
     * (`MAX_ENCRYPTION_KID_LENGTH`), and NULL kids — every plain `direct_post`
     * row — can never match, because `= $kid` is never true of NULL.
     *
     * @param kid - the `kid` read out of the JWE protected header, untrusted
     * @param tx - Optional transaction client
     * @returns the redeemed row, or undefined when unknown / expired / already
     * consumed — three cases the caller must not be able to tell apart.
     */
    async redeemByEncryptionKid(
      kid: string,
      tx?: DbClient
    ): Promise<Oid4vpRequestState | undefined> {
      const invoker = tx ?? defaultDb;
      const now = Date.now();

      const [redeemed] = await invoker
        .update(oid4vpRequestStates)
        .set({ redeemedAt: now })
        .where(
          and(
            eq(oid4vpRequestStates.responseEncryptionKid, kid),
            isNull(oid4vpRequestStates.redeemedAt),
            gt(oid4vpRequestStates.expiresAt, now)
          )
        )
        .returning();

      return redeemed;
    },

    /**
     * Delete expired rows (housekeeping).
     *
     * @param tx - Optional transaction client
     * @returns count of deleted rows
     */
    async deleteExpired(tx?: DbClient): Promise<number> {
      const invoker = tx ?? defaultDb;
      const now = Date.now();

      const deleted = await invoker
        .delete(oid4vpRequestStates)
        .where(lt(oid4vpRequestStates.expiresAt, now))
        .returning({ id: oid4vpRequestStates.id });

      return deleted.length;
    },
  };
}
