import { aliasedTable, and, eq, getTableColumns, gt, isNull, lt, sql } from 'drizzle-orm';

import type {
  NewOid4vpRequestState,
  Oid4vpRequestState,
  Oid4vpRequestStatesRepository,
} from '../../types';
import { DbClient } from '../db';
import { oid4vpRequestStates } from '../schema/oid4vp';

/**
 * The SET fragment every redemption carries besides `redeemed_at`: the three
 * encrypted-response columns (#377 Phase C) cleared in the SAME statement that
 * consumes the row.
 *
 * The ephemeral private key has exactly one job — open the one response its
 * `kid` names — and that job ends the instant the row is consumed. A key that
 * outlives its response is pure exposure: a later database dump, combined with
 * the encrypted POST bodies an access log or WAF in front of the endpoint may
 * have retained, would decrypt every historical presentation retroactively.
 * Clearing it here, rather than in a later housekeeping pass, means there is
 * no window in which a consumed row still carries a usable key — the row lock
 * that serializes redemption also serializes the erasure.
 *
 * All three are cleared together because the schema's
 * `..._response_encryption_complete` CHECK allows only all-set or all-null:
 * after consumption none of them has a purpose (the `kid` can match nothing —
 * the redemption predicates require `redeemed_at IS NULL` — and the marker
 * describes a value that is gone), so all-null is the honest state.
 *
 * Literal `null` rather than a bound parameter so the statement SAYS what it
 * does: a reader of the SQL, or of the unit test that pins it, sees the
 * erasure rather than a placeholder.
 */
const CLEAR_RESPONSE_ENCRYPTION = {
  responseEncryptionKid: sql`null`,
  responseEncryptionPrivateJwk: sql`null`,
  responseEncryptionKeyProtection: sql`null`,
} as const;

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
     *    SET redeemed_at = $now,
     *        response_encryption_kid = NULL,
     *        response_encryption_private_jwk = NULL,
     *        response_encryption_key_protection = NULL
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
     * The encrypted-response columns are cleared in the same statement (see
     * {@link CLEAR_RESPONSE_ENCRYPTION}). A cleartext redemption should never
     * find a row that carries them — such a row asked for `direct_post.jwt`,
     * and the caller refuses the mode mismatch — but the row IS consumed either
     * way, and a consumed row must not keep a key. The cleartext path has no
     * use for the key, so nothing hands it back: the returned row is the row as
     * it now stands, with the three columns NULL.
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
        .set({ redeemedAt: now, ...CLEAR_RESPONSE_ENCRYPTION })
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
     * Atomically consume a request state by its encryption `kid` (#377 Phase C),
     * handing its private key to the caller EXACTLY ONCE and erasing it from
     * the table in the same statement.
     *
     * ```sql
     * UPDATE oid4vp_request_states
     *    SET redeemed_at = $now,
     *        response_encryption_kid = NULL,
     *        response_encryption_private_jwk = NULL,
     *        response_encryption_key_protection = NULL
     *   FROM oid4vp_request_states AS before
     *  WHERE before.id = oid4vp_request_states.id
     *    AND oid4vp_request_states.response_encryption_kid = $kid
     *    AND oid4vp_request_states.redeemed_at IS NULL
     *    AND oid4vp_request_states.expires_at > $now
     * RETURNING oid4vp_request_states.*  -- minus the three, which come from:
     *           before.response_encryption_kid,
     *           before.response_encryption_private_jwk,
     *           before.response_encryption_key_protection
     * ```
     *
     * The guard is byte-for-byte the shape of {@link redeem} above, on the
     * other correlator, and it is load-bearing that it stays so: the row lock
     * serializes two concurrent posts carrying the same `kid`, and folding
     * expiry into the predicate means an expired row is never "consumed then
     * rejected". The lookup is a probe on
     * `idx_oid4vp_request_states_encryption_kid`, the UNIQUE partial index over
     * live rows — which is also what guarantees the predicate can match at most
     * one row.
     *
     * ## Why the self-join
     *
     * `RETURNING` sees the row AFTER the update, so a plain `RETURNING *` would
     * hand back the NULLs just written and the caller could not decrypt the
     * response it is holding. Joining the table to itself by primary key gives
     * the statement a second image of the same row — `before` — taken from the
     * statement's snapshot, i.e. BEFORE its own write, and the three key columns
     * are projected from that image. One statement, so the hand-off and the
     * erasure cannot be separated by a crash or a lost connection: either the
     * caller has the key and the table does not, or neither happened.
     *
     * The self-join does not weaken the guard. Under READ COMMITTED the loser of
     * a concurrent redemption blocks on the row lock, then re-evaluates the
     * predicate against the winner's committed version of the TARGET row — where
     * `redeemed_at` is now set — so it matches nothing, whatever image `before`
     * holds. The container-backed suite proves this with twelve simultaneous
     * posts.
     *
     * The returned row is therefore the row AS CONSUMED: `redeemed_at` set, and
     * the three encrypted-response columns carrying the values the row held at
     * the moment of consumption. Nothing else will ever return them — the table
     * no longer has them.
     *
     * The `kid` is bounded and character-checked by the caller before it
     * reaches here (`readEncryptedResponseKid`), and NULL kids — every plain
     * `direct_post` row — can never match, because `= $kid` is never true of
     * NULL.
     *
     * @param kid - the `kid` read out of the JWE protected header, untrusted
     * @param tx - Optional transaction client
     * @returns the redeemed row as consumed, or undefined when unknown /
     * expired / already consumed — three cases the caller must not be able to
     * tell apart.
     */
    async redeemByEncryptionKid(
      kid: string,
      tx?: DbClient
    ): Promise<Oid4vpRequestState | undefined> {
      const invoker = tx ?? defaultDb;
      const now = Date.now();
      const before = aliasedTable(oid4vpRequestStates, 'before');

      const [redeemed] = await invoker
        .update(oid4vpRequestStates)
        .set({ redeemedAt: now, ...CLEAR_RESPONSE_ENCRYPTION })
        .from(before)
        .where(
          and(
            eq(before.id, oid4vpRequestStates.id),
            eq(oid4vpRequestStates.responseEncryptionKid, kid),
            isNull(oid4vpRequestStates.redeemedAt),
            gt(oid4vpRequestStates.expiresAt, now)
          )
        )
        .returning({
          ...getTableColumns(oid4vpRequestStates),
          responseEncryptionKid: before.responseEncryptionKid,
          responseEncryptionPrivateJwk: before.responseEncryptionPrivateJwk,
          responseEncryptionKeyProtection: before.responseEncryptionKeyProtection,
        });

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
