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
 * on "no row matched" is exactly what several of these assert.
 */
function createRecordingDb(rows: Record<string, unknown>[] = []): {
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

describe('createOid4vpRequestStatesRepository.redeem', () => {
  it('issues exactly ONE statement — never a select followed by an update', async () => {
    const { db, queries } = createRecordingDb();

    await createOid4vpRequestStatesRepository(db).redeem(STATE_HASH);

    expect(queries).toHaveLength(1);
    expect(queries[0].text.toLowerCase()).not.toContain('select');
  });

  it('guards the update on unredeemed AND unexpired, and returns the row', async () => {
    const { db, queries } = createRecordingDb();

    await createOid4vpRequestStatesRepository(db).redeem(STATE_HASH);

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
      createOid4vpRequestStatesRepository(db).redeem(STATE_HASH)
    ).resolves.toBeUndefined();
  });

  it('returns the row when the guarded update matched', async () => {
    const { db } = createRecordingDb([{ id: 'row-1', state_hash: STATE_HASH }]);

    await expect(createOid4vpRequestStatesRepository(db).redeem(STATE_HASH)).resolves.toBeDefined();
  });

  it('exposes no way to read a row without consuming it', () => {
    const { db } = createRecordingDb();
    const repository = createOid4vpRequestStatesRepository(db);

    expect(Object.keys(repository).sort()).toEqual([
      'create',
      'deleteExpired',
      'redeem',
      'redeemByEncryptionKid',
    ]);
    expect(repository).not.toHaveProperty('findByStateHash');
    expect(repository).not.toHaveProperty('findByEncryptionKid');
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

    await createOid4vpRequestStatesRepository(db).redeemByEncryptionKid(KID);

    expect(queries).toHaveLength(1);
    expect(queries[0].text.toLowerCase()).not.toContain('select');
  });

  it('guards on the kid, unredeemed AND unexpired, and returns the row', async () => {
    const { db, queries } = createRecordingDb();

    await createOid4vpRequestStatesRepository(db).redeemByEncryptionKid(KID);

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

    await createOid4vpRequestStatesRepository(db).redeemByEncryptionKid(KID);

    expect(queries[0].values).toContain(KID);
    expect(queries[0].text).not.toContain(KID);
  });

  it('returns undefined when nothing matched (unknown / expired / already consumed)', async () => {
    const { db } = createRecordingDb([]);

    await expect(
      createOid4vpRequestStatesRepository(db).redeemByEncryptionKid(KID)
    ).resolves.toBeUndefined();
  });

  it('returns the row when the guarded update matched', async () => {
    const { db } = createRecordingDb([{ id: 'row-1', response_encryption_kid: KID }]);

    await expect(
      createOid4vpRequestStatesRepository(db).redeemByEncryptionKid(KID)
    ).resolves.toBeDefined();
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
});
