/**
 * Seed-then-migrate test for migration 0054: an approval keeps no request
 * body and no hash of the request without its nonce (#901).
 *
 * An approval filed before it holds the body in `canonical_request` and the
 * unsalted hash in `request_hash`. The migration moves the method, path
 * parameters and query to their own columns and, in that same row version,
 * empties the stored request and overwrites `request_hash` and the nonce, so
 * the columns it then drops (which DROP COLUMN only hides) hold neither. An
 * approval still open has no display, which only the operation's renderer
 * can make, so it is retired as `expired`.
 *
 * Requires Docker; self-skips without it. The schema is rebuilt from scratch
 * and upgraded through 0053, then 0054, so a later migration cannot change
 * what this test sees.
 */
import { createHash, randomBytes } from 'node:crypto';
import { rmSync } from 'node:fs';

import {
  applyQauthMigrations,
  qauthMigrationsFolderWithFirst,
  requireDockerOrSkip,
  type StartedPostgres,
  startPostgresContainer,
} from '@qauth-labs/shared-testing';
import { Pool } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

const MIGRATION_IDX = 54;
const SECRET = 'an SMTP password the operation sets';
const NOW = Date.now();

describe('migration 0054 — admin_approvals keep no request body (seed-then-migrate)', () => {
  let container: StartedPostgres | undefined;
  let pool: Pool | undefined;
  let dockerUp = false;
  const before = qauthMigrationsFolderWithFirst(MIGRATION_IDX);
  const through = qauthMigrationsFolderWithFirst(MIGRATION_IDX + 1);

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    container = await startPostgresContainer();
    pool = new Pool({ connectionString: container.connectionString, max: 2 });
  }, 180_000);

  afterAll(async () => {
    await pool?.end();
    await container?.stop();
    rmSync(before, { recursive: true, force: true });
    rmSync(through, { recursive: true, force: true });
  });

  beforeEach(async (testCtx) => {
    if (!dockerUp || !pool || !container) {
      testCtx.skip();
      return;
    }
    await pool.query(
      'DROP SCHEMA public CASCADE; CREATE SCHEMA public; DROP SCHEMA IF EXISTS drizzle CASCADE;'
    );
    await applyQauthMigrations(container.connectionString, before);
  });

  /** The pool; only called from a test that was not skipped. */
  function db(): Pool {
    if (!pool) throw new Error('no pool');
    return pool;
  }

  /** Apply every migration through 0054. */
  async function migrate(): Promise<void> {
    if (!container) throw new Error('no container');
    await applyQauthMigrations(container.connectionString, through);
  }

  /** An approval as #512 filed it, in `status`, with its body and both hashes. */
  async function fileAsBefore(status: 'pending' | 'approved' | 'consumed' | 'denied') {
    const {
      rows: [realm],
    } = await db().query<{ id: string }>(`INSERT INTO realms (name) VALUES ('r') RETURNING id`);
    const {
      rows: [user],
    } = await db().query<{ id: string }>(`INSERT INTO users (realm_id) VALUES ($1) RETURNING id`, [
      realm.id,
    ]);
    const canonical = {
      operationId: 'keys.rotate',
      method: 'POST',
      params: { realmId: realm.id, keyId: 'signing-1' },
      query: { dryRun: 'false' },
      body: { smtpPassword: SECRET },
      realmId: realm.id,
      requester: { kind: 'human', realmId: realm.id, accountId: user.id },
    };
    const requestHash = createHash('sha256').update(JSON.stringify(canonical)).digest();
    const nonce = randomBytes(32);
    const given = status === 'pending' ? [] : [{ approverId: user.id }];
    const {
      rows: [approval],
    } = await db().query<{ id: string }>(
      `INSERT INTO admin_approvals (realm_id, requester_kind, requester_realm_id, requester_id,
              operation_id, canonical_request, request_hash, op_hash, nonce, classification,
              approvals_required, approvals, status, created_at, expires_at, used_at)
       VALUES ($1, 'human', $1, $2, 'keys.rotate', $3, $4, $5, $6,
               '{"class": "security", "effects": [], "permissions": []}', 1, $7, $8, $9, $10, $11)
       RETURNING id`,
      [
        realm.id,
        user.id,
        JSON.stringify(canonical),
        requestHash,
        randomBytes(32),
        nonce,
        JSON.stringify(given),
        status,
        NOW,
        NOW + 5 * 60_000,
        status === 'consumed' ? NOW + 1_000 : null,
      ]
    );
    return { id: approval.id, realmId: realm.id, requestHash, nonce };
  }

  interface Row {
    status: string;
    method: string;
    params: unknown;
    query: unknown;
    display: unknown;
    nonce: Buffer;
    row: string;
  }

  async function rowOf(id: string): Promise<Row> {
    const {
      rows: [row],
    } = await db().query<Row>(
      `SELECT status, method, params, query, display, nonce, admin_approvals::text AS row
         FROM admin_approvals WHERE id = $1`,
      [id]
    );
    return row;
  }

  it('moves the method, path parameters and query to their columns, and keeps no body or hash', async () => {
    const consumed = await fileAsBefore('consumed');
    await migrate();

    const row = await rowOf(consumed.id);
    expect(row).toMatchObject({
      status: 'consumed',
      method: 'POST',
      params: { realmId: consumed.realmId, keyId: 'signing-1' },
      query: { dryRun: 'false' },
      display: null,
    });
    expect(row.row).not.toContain(SECRET);
    expect(row.row).not.toContain(consumed.requestHash.toString('hex'));
    // A closed approval's nonce is overwritten too.
    expect(row.nonce).toHaveLength(32);
    expect(row.nonce.equals(consumed.nonce)).toBe(false);

    const {
      rows: [dropped],
    } = await db().query<{ count: string }>(
      `SELECT count(*) FROM information_schema.columns
        WHERE table_name = 'admin_approvals' AND column_name IN ('canonical_request', 'request_hash')`
    );
    expect(Number(dropped.count)).toBe(0);
  });

  it('retires an approval still open as expired: it has no display to show', async () => {
    const pending = await fileAsBefore('pending');
    const approved = await fileAsBefore('approved');
    const denied = await fileAsBefore('denied');
    await migrate();

    expect((await rowOf(pending.id)).status).toBe('expired');
    expect((await rowOf(approved.id)).status).toBe('expired');
    expect((await rowOf(denied.id)).status).toBe('denied');
    for (const { id, nonce } of [pending, approved, denied]) {
      expect((await rowOf(id)).nonce.equals(nonce)).toBe(false);
    }
  });

  it('refuses an open approval without a display from then on', async () => {
    const consumed = await fileAsBefore('consumed');
    await migrate();
    await expect(
      db().query(
        `UPDATE admin_approvals SET status = 'pending', used_at = NULL, approvals = '[]' WHERE id = $1`,
        [consumed.id]
      )
    ).rejects.toMatchObject({ constraint: 'admin_approvals_open_has_display' });
  });
});
