import {
  aliasedTable,
  and,
  eq,
  getTableColumns,
  gt,
  isNotNull,
  isNull,
  lt,
  or,
  sql,
} from 'drizzle-orm';

import type {
  NewOid4vpRequestState,
  NewOid4vpResponseCode,
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
 * The SET fragment that writes the Response Code (#405) into the redemption —
 * the other half of what every redemption carries besides `redeemed_at`.
 *
 * Minted by the caller BEFORE the row is touched, and written by the ONE
 * statement that consumes the row, so the digest exists exactly when a
 * redemption happened: there is no second `UPDATE` that could fail after the
 * first committed, leaving a consumed row with no code for its return leg —
 * and no code on a row that was never consumed, because the guard predicates
 * that decide consumption decide this write too. Every redeemed row gets the
 * pair, same-device or not; the repository has one shape, and whether the
 * code is then emitted is read off the returned row's `sameDevice` by the
 * caller. The schema's `..._response_code_complete` CHECK is what makes the
 * two columns move together.
 */
function issueResponseCode(responseCode: NewOid4vpResponseCode) {
  return {
    responseCodeHash: responseCode.codeHash,
    responseCodeExpiresAt: responseCode.codeExpiresAt,
  } as const;
}

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
     *        response_encryption_key_protection = NULL,
     *        response_code_hash = $codeHash,
     *        response_code_expires_at = $codeExpiresAt
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
     * The Response Code's digest and deadline are written in the same
     * statement too (see {@link issueResponseCode}), so the returned row
     * carries them — and carries `sameDevice`, which is what the caller reads
     * to decide whether the code it minted goes back to the wallet.
     *
     * @param stateHash - SHA-256 digest of the `state` the wallet posted
     * @param responseCode - digest and deadline of the Response Code the
     * caller minted for this redemption; never the code itself
     * @param tx - Optional transaction client
     * @returns the redeemed row, or undefined when unknown / expired / already
     * consumed — three cases the caller must not be able to tell apart.
     */
    async redeem(
      stateHash: string,
      responseCode: NewOid4vpResponseCode,
      tx?: DbClient
    ): Promise<Oid4vpRequestState | undefined> {
      const invoker = tx ?? defaultDb;
      const now = Date.now();

      const [redeemed] = await invoker
        .update(oid4vpRequestStates)
        .set({ redeemedAt: now, ...CLEAR_RESPONSE_ENCRYPTION, ...issueResponseCode(responseCode) })
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
     *        response_encryption_key_protection = NULL,
     *        response_code_hash = $codeHash,
     *        response_code_expires_at = $codeExpiresAt
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
     * The Response Code's digest and deadline ride in the same SET as the
     * erasure (see {@link issueResponseCode}); they are new values, not
     * pre-update ones, so they are read from the target row like everything
     * else and need nothing from `before`.
     *
     * @param kid - the `kid` read out of the JWE protected header, untrusted
     * @param responseCode - digest and deadline of the Response Code the
     * caller minted for this redemption; never the code itself
     * @param tx - Optional transaction client
     * @returns the redeemed row as consumed, or undefined when unknown /
     * expired / already consumed — three cases the caller must not be able to
     * tell apart.
     */
    async redeemByEncryptionKid(
      kid: string,
      responseCode: NewOid4vpResponseCode,
      tx?: DbClient
    ): Promise<Oid4vpRequestState | undefined> {
      const invoker = tx ?? defaultDb;
      const now = Date.now();
      const before = aliasedTable(oid4vpRequestStates, 'before');

      const [redeemed] = await invoker
        .update(oid4vpRequestStates)
        .set({ redeemedAt: now, ...CLEAR_RESPONSE_ENCRYPTION, ...issueResponseCode(responseCode) })
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
     * Atomically consume a Response Code (#405) presented back by the browser
     * on the same-device return leg, and learn which request it named.
     *
     * ```sql
     * UPDATE oid4vp_request_states
     *    SET response_code_redeemed_at = $now
     *  WHERE response_code_hash = $codeHash
     *    AND response_code_redeemed_at IS NULL
     *    AND response_code_expires_at > $now
     *    AND redeemed_at IS NOT NULL
     *    AND same_device = true
     * RETURNING state_hash
     * ```
     *
     * The shape is {@link redeem}'s on the third correlator, and every reason
     * given there holds here: the predicate is evaluated under the row lock,
     * so two browsers landing with the same code are serialized and exactly
     * one sees a row; expiry is in the predicate, so an expired code is never
     * "consumed then rejected". The lookup is a probe on
     * `idx_oid4vp_request_states_response_code`, the UNIQUE partial index over
     * codes not yet redeemed, which is what guarantees at most one match.
     *
     * Two predicates have no counterpart in {@link redeem}. `redeemed_at IS
     * NOT NULL` closes a gap the DDL leaves open on purpose: the schema ties
     * the code's hash and deadline to EACH OTHER, but not to `redeemed_at` —
     * through this repository the only thing that writes a code is a
     * redemption, and a CHECK across the two would make the INSERT shape
     * depend on the redemption shape for no gain. This predicate is what
     * makes "a code is only good on a row a wallet actually answered" true of
     * a hand-written row as well.
     *
     * `same_device = true` is load-bearing: the digest is written for every
     * redeemed row, and for a cross-device row the code it names never left
     * the server. Guessing 256 bits is not a threat; a future caller that
     * emits the code somewhere it should not is, and this predicate makes
     * such a code worthless at the one place it could be spent.
     *
     * `RETURNING state_hash` and nothing else, on purpose. The return route
     * needs exactly the value that joins the code to the browser's flow
     * record; projecting the row would put the encrypted-response columns —
     * NULL by now, but the shape matters — on a path the BROWSER drives, and
     * would hand the return leg the `nonce` and DCQL query it has no use for.
     *
     * A refusal is one `undefined` for unknown, expired, replayed, cross-device
     * and never-answered alike; the caller renders one page for all of them.
     *
     * @param codeHash - SHA-256 digest of the Response Code the browser
     * presented, pre-digested by the caller; the code itself never reaches here
     * @param tx - Optional transaction client
     * @returns the `stateHash` of the request the code named, or undefined.
     * Either way, a code that was live is now spent.
     */
    async redeemResponseCode(
      codeHash: string,
      tx?: DbClient
    ): Promise<{ stateHash: string } | undefined> {
      const invoker = tx ?? defaultDb;
      const now = Date.now();

      const [redeemed] = await invoker
        .update(oid4vpRequestStates)
        .set({ responseCodeRedeemedAt: now })
        .where(
          and(
            eq(oid4vpRequestStates.responseCodeHash, codeHash),
            isNull(oid4vpRequestStates.responseCodeRedeemedAt),
            gt(oid4vpRequestStates.responseCodeExpiresAt, now),
            isNotNull(oid4vpRequestStates.redeemedAt),
            eq(oid4vpRequestStates.sameDevice, true)
          )
        )
        .returning({ stateHash: oid4vpRequestStates.stateHash });

      return redeemed;
    },

    /**
     * Delete expired rows (housekeeping).
     *
     * A row is expired only when BOTH its deadlines have passed:
     *
     * ```sql
     * DELETE FROM oid4vp_request_states
     *  WHERE expires_at < $now
     *    AND (response_code_expires_at IS NULL OR response_code_expires_at < $now)
     * ```
     *
     * The Response Code's deadline (#405) is set at redemption and is
     * independent of the request's, so a request answered at its last second
     * carries a code that outlives `expires_at`. Sweeping on `expires_at`
     * alone would turn that on-time answer into a return leg that finds no
     * row — the browser lands, the code is unknown, and the user is refused
     * for having been slow to tap "Done". A row with no code (never answered,
     * or answered before the column existed) is swept on `expires_at` as
     * before.
     *
     * @param tx - Optional transaction client
     * @returns count of deleted rows
     */
    async deleteExpired(tx?: DbClient): Promise<number> {
      const invoker = tx ?? defaultDb;
      const now = Date.now();

      const deleted = await invoker
        .delete(oid4vpRequestStates)
        .where(
          and(
            lt(oid4vpRequestStates.expiresAt, now),
            or(
              isNull(oid4vpRequestStates.responseCodeExpiresAt),
              lt(oid4vpRequestStates.responseCodeExpiresAt, now)
            )
          )
        )
        .returning({ id: oid4vpRequestStates.id });

      return deleted.length;
    },
  };
}
