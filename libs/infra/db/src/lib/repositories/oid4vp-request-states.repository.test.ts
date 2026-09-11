import { drizzle } from 'drizzle-orm/node-postgres';
import type { Pool } from 'pg';
import { describe, expect, it } from 'vitest';

import type { DbClient } from '../db';
import { createOid4vpRequestStatesRepository } from './oid4vp-request-states.repository';

/**
 * SQL-shape tests for the OID4VP request-state repository (issue #233).
 *
 * These assert the property the whole `direct_post` intake rests on — that
 * redemption is ONE guarded statement — WITHOUT needing Docker. The
 * container-backed suite
 * (`oid4vp-request-states.integration.test.ts`) proves the behaviour against a
 * real Postgres, including genuine concurrency; this one proves the statement
 * the repository emits, so a refactor that reintroduces a read-then-write is
 * caught even on a machine with no daemon.
 */

interface CapturedQuery {
  readonly text: string;
  readonly values: readonly unknown[];
}

/**
 * A `pg` client that records queries instead of running them.
 *
 * Drizzle only needs `query()` to build and dispatch; returning an empty row set
 * is enough for every statement under test, because the repository's behaviour
 * on "no row matched" is exactly what several of these assert. A test that
 * wants a match hands in rows in the mode drizzle will read them: an object
 * for `returning()` (every column), an ARRAY for a projected
 * `returning({ ... })`, which drizzle issues with `rowMode: 'array'`.
 */
function createRecordingDb(rows: (Record<string, unknown> | readonly unknown[])[] = []): {
  db: DbClient;
  queries: CapturedQuery[];
} {
  const queries: CapturedQuery[] = [];

  const client = {
    query: (config: { text?: string; values?: unknown[] } | string, values?: unknown[]) => {
      const text = typeof config === 'string' ? config : (config.text ?? '');
      const params = typeof config === 'string' ? (values ?? []) : (config.values ?? values ?? []);
      queries.push({ text, values: params });
      return Promise.resolve({ rows, rowCount: rows.length, fields: [], command: '', oid: 0 });
    },
  };

  return { db: drizzle(client as unknown as Pool) as unknown as DbClient, queries };
}

const STATE_HASH = 'a'.repeat(64);
const CODE_HASH = 'c'.repeat(64);
const CODE_EXPIRES_AT = 1_800_000_180_000;
/** The Response Code as the repository receives it (#405): digest + deadline, never the code. */
const RESPONSE_CODE = { codeHash: CODE_HASH, codeExpiresAt: CODE_EXPIRES_AT } as const;

describe('createOid4vpRequestStatesRepository.redeem', () => {
  it('issues exactly ONE statement — never a select followed by an update', async () => {
    const { db, queries } = createRecordingDb();

    await createOid4vpRequestStatesRepository(db).redeem(STATE_HASH, RESPONSE_CODE);

    expect(queries).toHaveLength(1);
    expect(queries[0].text.toLowerCase()).not.toContain('select');
  });

  it('(OID4VP 1.0 §14.3.2) guards the update on unredeemed AND unexpired, and returns the row', async () => {
    const { db, queries } = createRecordingDb();

    await createOid4vpRequestStatesRepository(db).redeem(STATE_HASH, RESPONSE_CODE);

    const sql = queries[0].text.toLowerCase();

    expect(sql).toContain('update "oid4vp_request_states"');
    expect(sql).toContain('set "redeemed_at"');
    expect(sql).toContain('"state_hash" =');
    // The two halves of the guard. Without either one, a replayed or expired
    // state would be consumable.
    expect(sql).toContain('"redeemed_at" is null');
    expect(sql).toContain('"expires_at" >');
    expect(sql).toContain('returning');
  });

  it('returns undefined when nothing matched (unknown / expired / already consumed)', async () => {
    const { db } = createRecordingDb([]);

    await expect(
      createOid4vpRequestStatesRepository(db).redeem(STATE_HASH, RESPONSE_CODE)
    ).resolves.toBeUndefined();
  });

  it('returns the row when the guarded update matched', async () => {
    const { db } = createRecordingDb([{ id: 'row-1', state_hash: STATE_HASH }]);

    await expect(
      createOid4vpRequestStatesRepository(db).redeem(STATE_HASH, RESPONSE_CODE)
    ).resolves.toBeDefined();
  });

  it('erases the encrypted-response columns in the SAME statement that consumes the row', async () => {
    // A cleartext redemption should never find a row carrying a key — such a
    // row asked for `direct_post.jwt` — but it consumes the row either way, and
    // a consumed row must not keep a key (#377 Phase C review, F1).
    const { db, queries } = createRecordingDb();

    await createOid4vpRequestStatesRepository(db).redeem(STATE_HASH, RESPONSE_CODE);

    const sql = queries[0].text.toLowerCase();
    const setClause = sql.slice(sql.indexOf(' set '), sql.indexOf(' where '));

    expect(setClause).toContain('"response_encryption_kid" = null');
    expect(setClause).toContain('"response_encryption_private_jwk" = null');
    expect(setClause).toContain('"response_encryption_key_protection" = null');
  });

  /**
   * The Response Code (#405) lands in the ONE statement that consumes the row.
   * A second `UPDATE` after redemption could fail after the first committed,
   * leaving a consumed row with no code for its return leg; and the erasure
   * must not have been displaced to make room — both are pinned on one SET.
   */
  it('writes the Response Code digest and deadline in the SAME statement, alongside the erasure', async () => {
    const { db, queries } = createRecordingDb();

    await createOid4vpRequestStatesRepository(db).redeem(STATE_HASH, RESPONSE_CODE);

    expect(queries).toHaveLength(1);
    const sql = queries[0].text.toLowerCase();
    const setClause = sql.slice(sql.indexOf(' set '), sql.indexOf(' where '));

    expect(setClause).toContain('"response_code_hash" =');
    expect(setClause).toContain('"response_code_expires_at" =');
    expect(setClause).toContain('"response_encryption_kid" = null');
    // Bound, never interpolated — and it is the DIGEST that is bound.
    expect(queries[0].values).toContain(CODE_HASH);
    expect(queries[0].values).toContain(CODE_EXPIRES_AT);
    expect(queries[0].text).not.toContain(CODE_HASH);
    // The guard is untouched by the new columns.
    const whereClause = sql.slice(sql.indexOf(' where '), sql.indexOf('returning'));
    expect(whereClause).not.toContain('"response_code');
    expect(whereClause).not.toContain('"same_device"');
  });

  it('exposes no way to read a row without consuming it', () => {
    const { db } = createRecordingDb();
    const repository = createOid4vpRequestStatesRepository(db);

    expect(Object.keys(repository).sort()).toEqual([
      'create',
      'deleteExpired',
      'redeem',
      'redeemByEncryptionKid',
      'redeemResponseCode',
    ]);
    expect(repository).not.toHaveProperty('findByStateHash');
    expect(repository).not.toHaveProperty('findByEncryptionKid');
    expect(repository).not.toHaveProperty('findByResponseCode');
  });
});

/**
 * The second correlator (#377 Phase C): a `direct_post.jwt` response carries no
 * cleartext `state`, so the row is consumed by the JWE `kid` instead. Every
 * property asserted of `redeem` above has to hold of this statement too — it is
 * the SAME guard on a different column, and a divergence between the two would
 * be a retry oracle on the encrypted path only.
 */
describe('createOid4vpRequestStatesRepository.redeemByEncryptionKid', () => {
  const KID = 'GtuHqs4XZKFV2wzsobBVRw';

  it('issues exactly ONE statement — never a select followed by an update', async () => {
    const { db, queries } = createRecordingDb();

    await createOid4vpRequestStatesRepository(db).redeemByEncryptionKid(KID, RESPONSE_CODE);

    expect(queries).toHaveLength(1);
    expect(queries[0].text.toLowerCase()).not.toContain('select');
  });

  it('guards on the kid, unredeemed AND unexpired, and returns the row', async () => {
    const { db, queries } = createRecordingDb();

    await createOid4vpRequestStatesRepository(db).redeemByEncryptionKid(KID, RESPONSE_CODE);

    const sql = queries[0].text.toLowerCase();

    expect(sql).toContain('update "oid4vp_request_states"');
    expect(sql).toContain('set "redeemed_at"');
    expect(sql).toContain('"response_encryption_kid" =');
    // NOT the state digest: the encrypted path has no cleartext state to hash.
    // (`returning *` lists the column; the WHERE clause must not read it.)
    expect(sql.slice(sql.indexOf('where'), sql.indexOf('returning'))).not.toContain('"state_hash"');
    expect(sql).toContain('"redeemed_at" is null');
    expect(sql).toContain('"expires_at" >');
    expect(sql).toContain('returning');
  });

  it('binds the kid as a parameter, never interpolated', async () => {
    const { db, queries } = createRecordingDb();

    await createOid4vpRequestStatesRepository(db).redeemByEncryptionKid(KID, RESPONSE_CODE);

    expect(queries[0].values).toContain(KID);
    expect(queries[0].text).not.toContain(KID);
  });

  it('returns undefined when nothing matched (unknown / expired / already consumed)', async () => {
    const { db } = createRecordingDb([]);

    await expect(
      createOid4vpRequestStatesRepository(db).redeemByEncryptionKid(KID, RESPONSE_CODE)
    ).resolves.toBeUndefined();
  });

  it('returns the row when the guarded update matched', async () => {
    const { db } = createRecordingDb([{ id: 'row-1', response_encryption_kid: KID }]);

    await expect(
      createOid4vpRequestStatesRepository(db).redeemByEncryptionKid(KID, RESPONSE_CODE)
    ).resolves.toBeDefined();
  });

  /**
   * The key is handed over EXACTLY ONCE and erased in the same statement (#377
   * Phase C review, F1). Two halves, both pinned here because a refactor could
   * break either one silently: forget the erasure and every login leaves a
   * private key in the table forever; forget the pre-update projection and the
   * caller is handed the NULL it just wrote and cannot decrypt anything.
   */
  it('erases the encrypted-response columns in the SAME statement that consumes the row', async () => {
    const { db, queries } = createRecordingDb();

    await createOid4vpRequestStatesRepository(db).redeemByEncryptionKid(KID, RESPONSE_CODE);

    expect(queries).toHaveLength(1);
    const sql = queries[0].text.toLowerCase();
    const setClause = sql.slice(sql.indexOf(' set '), sql.indexOf(' from '));

    expect(setClause).toContain('"redeemed_at" =');
    expect(setClause).toContain('"response_encryption_kid" = null');
    expect(setClause).toContain('"response_encryption_private_jwk" = null');
    expect(setClause).toContain('"response_encryption_key_protection" = null');
  });

  it('projects the PRE-update key columns into RETURNING via a primary-key self-join', async () => {
    const { db, queries } = createRecordingDb();

    await createOid4vpRequestStatesRepository(db).redeemByEncryptionKid(KID, RESPONSE_CODE);

    const sql = queries[0].text.toLowerCase();
    const returning = sql.slice(sql.indexOf('returning'));

    // The second image of the row, joined by primary key — and the guard still
    // reads the TARGET's columns, which is what keeps it a guard under EPQ.
    expect(sql).toContain('from "oid4vp_request_states" "before"');
    expect(sql).toContain('"before"."id" = "oid4vp_request_states"."id"');
    expect(sql).toContain('"oid4vp_request_states"."redeemed_at" is null');
    // The three key columns come from the snapshot image, never from the row
    // as just written.
    expect(returning).toContain('"before"."response_encryption_kid"');
    expect(returning).toContain('"before"."response_encryption_private_jwk"');
    expect(returning).toContain('"before"."response_encryption_key_protection"');
    expect(returning).not.toContain('"oid4vp_request_states"."response_encryption_private_jwk"');
    // Everything else is the row as it now stands, `redeemed_at` included.
    expect(returning).toContain('"oid4vp_request_states"."redeemed_at"');
    expect(returning).toContain('"oid4vp_request_states"."state_hash"');
  });

  it('writes the Response Code digest and deadline in the SAME statement, alongside the erasure', async () => {
    // The encrypted path consumes the row BEFORE decrypting, so the code is
    // written on a row whose submission may yet be refused — that is fine
    // (the code never leaves the server on refusal) and it is the same shape
    // as `redeem`, which is the point: one statement, whichever correlator.
    const { db, queries } = createRecordingDb();

    await createOid4vpRequestStatesRepository(db).redeemByEncryptionKid(KID, RESPONSE_CODE);

    expect(queries).toHaveLength(1);
    const sql = queries[0].text.toLowerCase();
    const setClause = sql.slice(sql.indexOf(' set '), sql.indexOf(' from '));

    expect(setClause).toContain('"response_code_hash" =');
    expect(setClause).toContain('"response_code_expires_at" =');
    expect(setClause).toContain('"response_encryption_kid" = null');
    expect(queries[0].values).toContain(CODE_HASH);
    expect(queries[0].values).toContain(CODE_EXPIRES_AT);
    expect(queries[0].text).not.toContain(CODE_HASH);
    // New values, not pre-update ones: nothing about the code is projected
    // from the `before` image, and the guard does not read the new columns.
    const returning = sql.slice(sql.indexOf('returning'));
    expect(returning).not.toContain('"before"."response_code');
    const whereClause = sql.slice(sql.indexOf(' where '), sql.indexOf('returning'));
    expect(whereClause).not.toContain('"response_code');
    expect(whereClause).not.toContain('"same_device"');
  });
});

/**
 * The third correlator (#405): the Response Code, presented back by the
 * BROWSER on the same-device return leg. Every property `redeem` has, this
 * statement has to have too — and two more predicates that make a code
 * worthless anywhere but on a same-device row a wallet actually answered.
 */
describe('createOid4vpRequestStatesRepository.redeemResponseCode', () => {
  it('issues exactly ONE statement — never a select followed by an update', async () => {
    const { db, queries } = createRecordingDb();

    await createOid4vpRequestStatesRepository(db).redeemResponseCode(CODE_HASH);

    expect(queries).toHaveLength(1);
    expect(queries[0].text.toLowerCase()).not.toContain('select');
  });

  it('guards on all five predicates: digest, code unredeemed, code unexpired, row redeemed, same-device', async () => {
    const { db, queries } = createRecordingDb();

    await createOid4vpRequestStatesRepository(db).redeemResponseCode(CODE_HASH);

    const sql = queries[0].text.toLowerCase();
    const whereClause = sql.slice(sql.indexOf(' where '), sql.indexOf('returning'));

    expect(sql).toContain('update "oid4vp_request_states"');
    expect(sql).toContain('set "response_code_redeemed_at" =');
    // 1. The digest finds the row.
    expect(whereClause).toContain('"response_code_hash" =');
    // 2. The code's own single-use marker — what makes the return leg consume
    //    exactly once under concurrency.
    expect(whereClause).toContain('"response_code_redeemed_at" is null');
    // 3. The code's OWN deadline, never the request's.
    expect(whereClause).toContain('"response_code_expires_at" >');
    expect(whereClause).not.toContain('"expires_at" >');
    // 4. Only on a row a wallet actually answered.
    expect(whereClause).toContain('"redeemed_at" is not null');
    expect(whereClause).not.toContain('"redeemed_at" is null');
    // 5. Only on a row whose code was ever emitted.
    expect(whereClause).toContain('"same_device" =');
    expect(queries[0].values).toContain(true);
  });

  it('binds the digest as a parameter, never interpolated', async () => {
    const { db, queries } = createRecordingDb();

    await createOid4vpRequestStatesRepository(db).redeemResponseCode(CODE_HASH);

    expect(queries[0].values).toContain(CODE_HASH);
    expect(queries[0].text).not.toContain(CODE_HASH);
  });

  it('returns ONLY state_hash — never the row, never a key column', async () => {
    // The return route needs the one value that joins the code to a browser
    // flow. The encrypted-response columns must never be projected on a path
    // the browser drives, and the return leg has no use for the nonce or the
    // DCQL query.
    const { db, queries } = createRecordingDb();

    await createOid4vpRequestStatesRepository(db).redeemResponseCode(CODE_HASH);

    const sql = queries[0].text.toLowerCase();
    const returning = sql.slice(sql.indexOf('returning'));

    expect(returning).toContain('"state_hash"');
    expect(returning).not.toContain('*');
    expect(returning).not.toContain('"response_encryption_kid"');
    expect(returning).not.toContain('"response_encryption_private_jwk"');
    expect(returning).not.toContain('"response_encryption_key_protection"');
    expect(returning).not.toContain('"nonce"');
    expect(returning).not.toContain('"dcql_query"');
    expect(returning).not.toContain('"response_code_hash"');
  });

  it('returns undefined when nothing matched (unknown / expired / replayed / cross-device / never answered)', async () => {
    const { db } = createRecordingDb([]);

    await expect(
      createOid4vpRequestStatesRepository(db).redeemResponseCode(CODE_HASH)
    ).resolves.toBeUndefined();
  });

  it('returns the state hash when the guarded update matched', async () => {
    const { db } = createRecordingDb([[STATE_HASH]]);

    await expect(
      createOid4vpRequestStatesRepository(db).redeemResponseCode(CODE_HASH)
    ).resolves.toEqual({ stateHash: STATE_HASH });
  });
});

describe('createOid4vpRequestStatesRepository.deleteExpired', () => {
  it('deletes only rows whose expiry has passed', async () => {
    const { db, queries } = createRecordingDb();

    await createOid4vpRequestStatesRepository(db).deleteExpired();

    const sql = queries[0].text.toLowerCase();

    expect(sql).toContain('delete from "oid4vp_request_states"');
    expect(sql).toContain('"expires_at" <');
  });

  it('spares a row whose Response Code is still live, whatever its request expiry', async () => {
    // A request answered at its last second carries a code that outlives
    // `expires_at`; sweeping on `expires_at` alone would turn that on-time
    // answer into a return leg that finds no row (#405).
    const { db, queries } = createRecordingDb();

    await createOid4vpRequestStatesRepository(db).deleteExpired();

    const sql = queries[0].text.toLowerCase();
    const whereClause = sql.slice(sql.indexOf(' where '));

    expect(whereClause).toContain('"expires_at" <');
    expect(whereClause).toContain('"response_code_expires_at" is null');
    expect(whereClause).toContain('"response_code_expires_at" <');
    // The two halves of the code clause are joined by OR, and the whole is
    // ANDed with the request's expiry — not the other way round.
    expect(whereClause).toMatch(
      /"expires_at" < \$\d+ and \("oid4vp_request_states"\."response_code_expires_at" is null or "oid4vp_request_states"\."response_code_expires_at" < \$\d+\)/
    );
  });
});
