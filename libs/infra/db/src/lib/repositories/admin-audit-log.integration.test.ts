/**
 * Real-Postgres integration tests for the admin audit log (issue #448).
 *
 * What only a database can prove: the row commits and rolls back with the
 * caller's transaction, the advisory lock keeps concurrent appends to one
 * linear chain, the triggers refuse UPDATE, DELETE and TRUNCATE to every role,
 * the writer grants refuse them earlier, verification finds a row changed or
 * removed behind the application's back, and the guarded prune leaves a chain
 * that still verifies from its checkpoint.
 *
 * The log cannot be truncated, so `reset()` leaves it alone and every test
 * works in a realm id of its own.
 *
 * Requires Docker; self-skips without it, same as the sibling suites.
 */
import { randomUUID } from 'node:crypto';

import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { and, eq } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool, type PoolClient } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import type { AdminAuditEntry, AdminAuditLogRepository, Database } from '../../types';
import { adminAuditLogWriterGrantStatements } from '../admin-audit/grants';
import { ADMIN_AUDIT_SECRET_MARKER } from '../admin-audit/mask-secrets';
import { computeAdminAuditRowHash } from '../admin-audit/row-hash';
import { adminAuditLog, realms } from '../schema';
import { createAdminAuditLogRepository } from './admin-audit-log.repository';
import { type IntegrationDb, setupIntegrationDb } from './integration-setup';

const DAY_MS = 86_400_000;
const OPERATOR_REALM_ID = '0192f1c4-3333-7000-8000-000000000003';

describe('admin_audit_log integration (real Postgres)', () => {
  let ctx: IntegrationDb | undefined;
  let dockerUp = false;
  let auditLog: AdminAuditLogRepository;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    // A container of its own: a case below creates roles, which are
    // cluster-wide and outlive the database, so on a shared server their
    // fixed names would meet the next suite's.
    ctx = await setupIntegrationDb({ privateContainer: true });
    auditLog = createAdminAuditLogRepository(ctx.database.db);
  }, 180_000);

  afterAll(async () => {
    await ctx?.teardown();
  });

  beforeEach(async (testCtx) => {
    if (!dockerUp || !ctx) {
      testCtx.skip();
      return;
    }
    await ctx.reset();
  });

  function db(): Database {
    if (!ctx) throw new Error('no ctx');
    return ctx.database.db;
  }

  function pool(): Pool {
    if (!ctx) throw new Error('no ctx');
    return ctx.database.pool;
  }

  function entry(realmId: string, overrides: Partial<AdminAuditEntry> = {}): AdminAuditEntry {
    return {
      realmId,
      actorKind: 'human_admin',
      actorId: randomUUID(),
      actorRealmId: OPERATOR_REALM_ID,
      operationId: 'realms.policies.write',
      operationClass: 'write',
      outcome: 'succeeded',
      diff: {
        change: { before: { passwordMinScore: 2 }, after: { passwordMinScore: 3 } },
        annotations: {},
      },
      traceId: randomUUID(),
      ...overrides,
    };
  }

  /** Append `count` rows to a realm, one transaction each, in order. */
  async function appendRows(
    realmId: string,
    count: number,
    log: AdminAuditLogRepository = auditLog
  ): Promise<void> {
    for (let i = 0; i < count; i += 1) {
      await db().transaction((tx) => log.appendAdminAudit(tx, entry(realmId)));
    }
  }

  async function chainRows(
    realmId: string
  ): Promise<{ seq: number; prev_hash: Buffer; row_hash: Buffer }[]> {
    const { rows } = await pool().query(
      `SELECT seq::int AS seq, prev_hash, row_hash FROM admin_audit_log WHERE realm_id = $1 ORDER BY seq`,
      [realmId]
    );
    return rows;
  }

  /**
   * Run statements as the superuser with every trigger off, the way an
   * attacker with superuser access, or an operator editing by hand, would.
   */
  async function tamper(statements: [string, unknown[]][]): Promise<void> {
    const client: PoolClient = await pool().connect();
    try {
      await client.query('BEGIN');
      await client.query('SET LOCAL session_replication_role = replica');
      for (const [text, values] of statements) await client.query(text, values);
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  /** The Postgres error behind a rejected promise: `code` and `constraint`. */
  async function pgError(
    promise: Promise<unknown>
  ): Promise<{ code?: string; constraint?: string }> {
    try {
      await promise;
    } catch (error) {
      let current: unknown = error;
      while (current && typeof current === 'object') {
        const candidate = current as { code?: unknown; constraint?: unknown; cause?: unknown };
        if (typeof candidate.code === 'string' && /^[0-9A-Z]{5}$/.test(candidate.code)) {
          return { code: candidate.code, constraint: candidate.constraint as string | undefined };
        }
        current = candidate.cause;
      }
      throw error;
    }
    throw new Error('expected the statement to fail');
  }

  describe('transactions', () => {
    it('leaves no row when the transaction that appended it rolls back', async () => {
      const realmId = randomUUID();

      await expect(
        db().transaction(async (tx) => {
          // The change the row records, and the row, in one transaction.
          await tx.insert(realms).values({ id: realmId, name: `realm-${realmId}` });
          await auditLog.appendAdminAudit(tx, entry(realmId));
          throw new Error('the operation failed after the append');
        })
      ).rejects.toThrow('the operation failed after the append');

      expect(await chainRows(realmId)).toEqual([]);
      const { rows } = await pool().query(`SELECT 1 FROM realms WHERE id = $1`, [realmId]);
      expect(rows).toEqual([]);

      // The rolled-back row used no seq.
      await appendRows(realmId, 1);
      expect((await chainRows(realmId)).map((row) => row.seq)).toEqual([1]);
    });

    it('rolls the row back when the outbox hook fails, and runs the hook inside the transaction', async () => {
      const realmId = randomUUID();
      const seen: number[] = [];
      const withHook = createAdminAuditLogRepository(db(), {
        afterAppend: async (tx, record) => {
          // The row is visible inside the transaction that wrote it.
          const rows = await tx
            .select({ seq: adminAuditLog.seq })
            .from(adminAuditLog)
            .where(eq(adminAuditLog.realmId, record.realmId));
          seen.push(...rows.map((row) => row.seq));
          throw new Error('outbox write failed');
        },
      });

      await expect(
        db().transaction((tx) => withHook.appendAdminAudit(tx, entry(realmId)))
      ).rejects.toThrow('outbox write failed');

      expect(seen).toEqual([1]);
      expect(await chainRows(realmId)).toEqual([]);
    });
  });

  describe('concurrency', () => {
    it('gives parallel appends to one realm one linear chain with no gap', async () => {
      const realmId = randomUUID();
      const otherRealmId = randomUUID();
      const appends = Array.from({ length: 40 }, (_, i) =>
        db().transaction((tx) =>
          auditLog.appendAdminAudit(tx, entry(i % 4 === 0 ? otherRealmId : realmId))
        )
      );

      await Promise.all(appends);

      const rows = await chainRows(realmId);
      expect(rows.map((row) => row.seq)).toEqual(Array.from({ length: 30 }, (_, i) => i + 1));
      for (let i = 1; i < rows.length; i += 1) {
        expect(rows[i].prev_hash.equals(rows[i - 1].row_hash)).toBe(true);
      }
      expect((await chainRows(otherRealmId)).map((row) => row.seq)).toEqual(
        Array.from({ length: 10 }, (_, i) => i + 1)
      );

      await expect(auditLog.verifyAdminAuditChain(realmId)).resolves.toMatchObject({
        ok: true,
        rowsChecked: 30,
        checkpoint: null,
        head: { seq: 30, rowHash: rows[29].row_hash.toString('hex') },
      });
      // Paging through the chain a few rows at a time finds the same.
      await expect(
        createAdminAuditLogRepository(db(), { verifyBatchSize: 7 }).verifyAdminAuditChain(realmId)
      ).resolves.toMatchObject({ ok: true, rowsChecked: 30 });
      await expect(auditLog.verifyAdminAuditChain(otherRealmId)).resolves.toMatchObject({
        ok: true,
        rowsChecked: 10,
      });
    });
  });

  describe('what a row stores', () => {
    it('stores the diff with the secret masked and the act chain in full', async () => {
      const realmId = randomUUID();
      const userId = randomUUID();
      const actChain = {
        sub: userId,
        act: { sub: 'admin-1', iss: 'https://operator.example.test', act: { sub: 'console' } },
      };

      await db().transaction((tx) =>
        auditLog.appendAdminAudit(
          tx,
          entry(realmId, {
            operationId: 'users.setup_link.copy',
            operationClass: 'security',
            effects: ['credentials'],
            actChain,
            diff: {
              change: {
                before: null,
                after: { userId, setupLink: 'https://auth.example.test/setup?code=s3cr3t-code' },
              },
              annotations: { setupLink: 'secret' },
            },
          })
        )
      );

      const { rows } = await pool().query(
        `SELECT masked_diff, act_chain, row_to_json(l)::text AS whole
           FROM admin_audit_log l WHERE realm_id = $1`,
        [realmId]
      );
      expect(rows[0].masked_diff).toEqual({
        before: null,
        after: { userId, setupLink: ADMIN_AUDIT_SECRET_MARKER },
      });
      expect(rows[0].act_chain).toEqual(actChain);
      expect(rows[0].whole).not.toContain('s3cr3t-code');
    });
  });

  describe('entries the chain could not verify later', () => {
    it('are refused and leave no row: a hole in a diff array, a trace id past its column', async () => {
      const realmId = randomUUID();
      // eslint-disable-next-line no-sparse-arrays
      const sparse = [1, , 3] as unknown as number[];

      for (const overrides of [
        { diff: { change: { before: null, after: { list: sparse } }, annotations: {} } },
        { traceId: `${'a'.repeat(128)}   ` },
      ] as Partial<AdminAuditEntry>[]) {
        await expect(
          db().transaction((tx) => auditLog.appendAdminAudit(tx, entry(realmId, overrides)))
        ).rejects.toThrow(TypeError);
      }
      expect(await chainRows(realmId)).toEqual([]);
    });
  });

  describe('append-only triggers', () => {
    it('refuse UPDATE, DELETE and TRUNCATE on the log, the table owner included', async () => {
      const realmId = randomUUID();
      await appendRows(realmId, 2);

      for (const statement of [
        `UPDATE admin_audit_log SET outcome = 'denied' WHERE realm_id = '${realmId}'`,
        `DELETE FROM admin_audit_log WHERE realm_id = '${realmId}'`,
        `TRUNCATE admin_audit_log`,
      ]) {
        await expect(pgError(pool().query(statement))).resolves.toEqual({
          code: '23514',
          constraint: 'admin_audit_log_append_only',
        });
      }
      expect(await chainRows(realmId)).toHaveLength(2);
    });

    it('refuse an inserted row that does not follow the chain head', async () => {
      const realmId = randomUUID();
      await appendRows(realmId, 2);
      const [head] = (await chainRows(realmId)).slice(-1);
      const insert = (seq: number, prevHash: Buffer) =>
        pool().query(
          `INSERT INTO admin_audit_log
             (realm_id, seq, prev_hash, row_hash, actor_kind, actor_id, operation_id,
              operation_class, effects, outcome, approvals, created_at)
           VALUES ($1, $2, $3, $4, 'host_operator', 'root', 'realms.read', 'read', '[]',
                   'succeeded', '[]', 0)`,
          [realmId, seq, prevHash, Buffer.alloc(32, 7)]
        );

      // A gap in seq, a repeated link, and the right seq on the wrong hash.
      for (const [seq, prevHash] of [
        [5, head.row_hash],
        [2, head.prev_hash],
        [3, Buffer.alloc(32, 1)],
      ] as [number, Buffer][]) {
        await expect(pgError(insert(seq, prevHash))).resolves.toEqual({
          code: '23514',
          constraint: 'admin_audit_log_follows_head',
        });
      }
      expect(await chainRows(realmId)).toHaveLength(2);
    });

    it('pin the search_path of every function they run', async () => {
      const { rows } = await pool().query(
        `SELECT proname, proconfig FROM pg_proc
          WHERE proname IN ('admin_audit_log_follows_head', 'admin_audit_log_append_only',
                            'admin_audit_log_checkpoint_valid', 'admin_audit_log_prune')
          ORDER BY proname`
      );
      expect(rows).toEqual(
        [
          'admin_audit_log_append_only',
          'admin_audit_log_checkpoint_valid',
          'admin_audit_log_follows_head',
          'admin_audit_log_prune',
        ].map((proname) => ({ proname, proconfig: ['search_path=pg_catalog, pg_temp'] }))
      );
    });

    it('refuse UPDATE, DELETE and TRUNCATE on the checkpoints', async () => {
      const realmId = randomUUID();
      await appendRows(
        realmId,
        2,
        createAdminAuditLogRepository(db(), { now: () => Date.now() - 100 * DAY_MS })
      );
      await pool().query(`SELECT admin_audit_log_prune($1, 1)`, [realmId]);

      for (const statement of [
        `UPDATE admin_audit_log_checkpoints SET seq = 2 WHERE realm_id = '${realmId}'`,
        `DELETE FROM admin_audit_log_checkpoints WHERE realm_id = '${realmId}'`,
        `TRUNCATE admin_audit_log_checkpoints`,
      ]) {
        await expect(pgError(pool().query(statement))).resolves.toEqual({
          code: '23514',
          constraint: 'admin_audit_log_checkpoints_append_only',
        });
      }
    });
  });

  describe('a role holding the writer grants', () => {
    const ROLE = 'qauth_admin_audit_writer';
    let writer: Pool | undefined;
    let writerLog: AdminAuditLogRepository;

    beforeAll(async () => {
      if (!dockerUp || !ctx) return;
      // Login roles are cluster-wide and outlive `reset()`; the container is
      // per file, so creating it once here is enough.
      await pool().query(`CREATE ROLE ${ROLE} LOGIN PASSWORD '${ROLE}'`);
      await pool().query(`GRANT USAGE ON SCHEMA public TO ${ROLE}`);
      // Twice: the statements are idempotent.
      for (let i = 0; i < 2; i += 1) {
        for (const statement of adminAuditLogWriterGrantStatements(ROLE)) {
          await pool().query(statement);
        }
      }
      const url = new URL(ctx.connectionString);
      url.username = ROLE;
      url.password = ROLE;
      writer = new Pool({ connectionString: url.toString(), max: 2 });
      writerLog = createAdminAuditLogRepository(drizzle(writer));
    });

    afterAll(async () => {
      await writer?.end();
    });

    function writerPool(): Pool {
      if (!writer) throw new Error('no writer pool');
      return writer;
    }

    it('holds INSERT and SELECT on the log and SELECT on the checkpoints, nothing else', async () => {
      const { rows } = await pool().query(
        `SELECT table_name, privilege_type FROM information_schema.role_table_grants
          WHERE grantee = $1 ORDER BY table_name, privilege_type`,
        [ROLE]
      );
      expect(rows).toEqual([
        { table_name: 'admin_audit_log', privilege_type: 'INSERT' },
        { table_name: 'admin_audit_log', privilege_type: 'SELECT' },
        { table_name: 'admin_audit_log_checkpoints', privilege_type: 'SELECT' },
      ]);
    });

    it('can append and verify through the repository', async () => {
      const realmId = randomUUID();
      const writerDb = drizzle(writerPool());

      for (let i = 0; i < 3; i += 1) {
        await writerDb.transaction((tx) => writerLog.appendAdminAudit(tx, entry(realmId)));
      }

      await expect(writerLog.verifyAdminAuditChain(realmId)).resolves.toMatchObject({
        ok: true,
        rowsChecked: 3,
      });
    });

    it('cannot UPDATE, DELETE or TRUNCATE the log, write a checkpoint, or call the prune', async () => {
      const realmId = randomUUID();
      await appendRows(realmId, 1);

      for (const [statement, values] of [
        [`UPDATE admin_audit_log SET outcome = 'denied' WHERE realm_id = $1`, [realmId]],
        [`DELETE FROM admin_audit_log WHERE realm_id = $1`, [realmId]],
        [`TRUNCATE admin_audit_log`, []],
        [
          `INSERT INTO admin_audit_log_checkpoints (realm_id, seq, row_hash) VALUES ($1, 1, decode(repeat('00', 32), 'hex'))`,
          [realmId],
        ],
        [`SELECT admin_audit_log_prune($1, 1)`, [realmId]],
      ] as [string, unknown[]][]) {
        // 42501 = insufficient_privilege: the grants stop it before any trigger runs.
        await expect(pgError(writerPool().query(statement, values))).resolves.toMatchObject({
          code: '42501',
        });
      }
      expect(await chainRows(realmId)).toHaveLength(1);
    });
  });

  describe('a role granted DML on both tables, beyond the writer grants', () => {
    const ROLE = 'qauth_admin_audit_dml';
    let dml: Pool | undefined;

    beforeAll(async () => {
      if (!dockerUp || !ctx) return;
      await pool().query(`CREATE ROLE ${ROLE} LOGIN PASSWORD '${ROLE}'`);
      await pool().query(`GRANT USAGE ON SCHEMA public TO ${ROLE}`);
      await pool().query(
        `GRANT SELECT, INSERT, DELETE ON admin_audit_log, admin_audit_log_checkpoints TO ${ROLE}`
      );
      const url = new URL(ctx.connectionString);
      url.username = ROLE;
      url.password = ROLE;
      dml = new Pool({ connectionString: url.toString(), max: 1 });
    });

    afterAll(async () => {
      await dml?.end();
    });

    /** Run statements as that role in one transaction, rolled back on error. */
    async function asDml(statements: [string, unknown[]][]): Promise<void> {
      if (!dml) throw new Error('no dml pool');
      const client = await dml.connect();
      try {
        await client.query('BEGIN');
        for (const [text, values] of statements) await client.query(text, values);
        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }
    }

    /** A checkpoint copied from a real row, the way a prune would write it. */
    const COPY_CHECKPOINT = `INSERT INTO admin_audit_log_checkpoints (realm_id, seq, row_hash)
      SELECT realm_id, seq, row_hash FROM admin_audit_log WHERE realm_id = $1 AND seq = $2`;

    it('cannot delete a row that no checkpoint covers', async () => {
      const realmId = randomUUID();
      await appendRows(realmId, 2);

      await expect(
        pgError(asDml([[`DELETE FROM admin_audit_log WHERE realm_id = $1`, [realmId]]]))
      ).resolves.toEqual({ code: '23514', constraint: 'admin_audit_log_append_only' });
      expect(await chainRows(realmId)).toHaveLength(2);
    });

    it('cannot write its own checkpoint over rows younger than 90 days, and so cannot delete them', async () => {
      const realmId = randomUUID();
      await appendRows(realmId, 5);
      await expect(
        pgError(
          asDml([
            [COPY_CHECKPOINT, [realmId, 3]],
            [`DELETE FROM admin_audit_log WHERE realm_id = $1 AND seq <= 3`, [realmId]],
          ])
        )
      ).resolves.toEqual({ code: '23514', constraint: 'admin_audit_log_retention_floor' });
      expect(await chainRows(realmId)).toHaveLength(5);
      await expect(auditLog.verifyAdminAuditChain(realmId)).resolves.toMatchObject({
        ok: true,
        rowsChecked: 5,
      });
    });

    it('cannot write a checkpoint with another hash, or one behind the newest', async () => {
      const realmId = randomUUID();
      await appendRows(
        realmId,
        4,
        createAdminAuditLogRepository(db(), { now: () => Date.now() - 100 * DAY_MS })
      );
      await pool().query(`SELECT admin_audit_log_prune($1, 2)`, [realmId]);

      await expect(
        pgError(
          asDml([
            [
              `INSERT INTO admin_audit_log_checkpoints (realm_id, seq, row_hash) VALUES ($1, 3, $2)`,
              [realmId, Buffer.alloc(32, 9)],
            ],
          ])
        )
      ).resolves.toEqual({ code: '23514', constraint: 'admin_audit_log_checkpoints_match' });
      await expect(
        pgError(
          asDml([
            [
              `INSERT INTO admin_audit_log_checkpoints (realm_id, seq, row_hash) VALUES ($1, 1, $2)`,
              [realmId, Buffer.alloc(32, 9)],
            ],
          ])
        )
      ).resolves.toEqual({ code: '23514', constraint: 'admin_audit_log_checkpoints_forward' });
    });
  });

  describe('verifyAdminAuditChain', () => {
    it('passes on an untouched chain and on a realm with no rows', async () => {
      const realmId = randomUUID();
      await appendRows(realmId, 3);

      await expect(auditLog.verifyAdminAuditChain(realmId)).resolves.toMatchObject({
        ok: true,
        rowsChecked: 3,
        head: { seq: 3 },
      });
      await expect(auditLog.verifyAdminAuditChain(randomUUID())).resolves.toEqual({
        ok: true,
        realmId: expect.any(String),
        rowsChecked: 0,
        checkpoint: null,
        head: null,
      });
    });

    it('reports the row a superuser changed', async () => {
      const realmId = randomUUID();
      await appendRows(realmId, 5);

      await tamper([
        [
          `UPDATE admin_audit_log SET masked_diff = '{"before":null,"after":{"passwordMinScore":0}}'
            WHERE realm_id = $1 AND seq = 3`,
          [realmId],
        ],
      ]);

      await expect(auditLog.verifyAdminAuditChain(realmId)).resolves.toMatchObject({
        ok: false,
        rowsChecked: 2,
        break: { seq: 3, reason: 'row_hash_mismatch' },
      });
    });

    it('reports the next row when a changed row was given a correct new hash', async () => {
      const realmId = randomUUID();
      await appendRows(realmId, 4);
      const [row] = await db()
        .select()
        .from(adminAuditLog)
        .where(and(eq(adminAuditLog.realmId, realmId), eq(adminAuditLog.seq, 2)));
      const forged = computeAdminAuditRowHash(row.prevHash, { ...row, outcome: 'denied' });

      await tamper([
        [
          `UPDATE admin_audit_log SET outcome = 'denied', row_hash = $2 WHERE realm_id = $1 AND seq = 2`,
          [realmId, forged],
        ],
      ]);

      // Row 2 now hashes right; row 3 still carries the hash it was chained to.
      await expect(auditLog.verifyAdminAuditChain(realmId)).resolves.toMatchObject({
        ok: false,
        rowsChecked: 2,
        break: { seq: 3, reason: 'prev_hash_mismatch' },
      });
    });

    it('reports the row after one a superuser deleted from the middle', async () => {
      const realmId = randomUUID();
      await appendRows(realmId, 5);

      await tamper([[`DELETE FROM admin_audit_log WHERE realm_id = $1 AND seq = 3`, [realmId]]]);

      await expect(auditLog.verifyAdminAuditChain(realmId)).resolves.toMatchObject({
        ok: false,
        rowsChecked: 2,
        break: { seq: 4, reason: 'sequence_mismatch', expectedSeq: 3 },
      });
    });

    it('reports the oldest retained row when the oldest rows were deleted without a prune', async () => {
      const realmId = randomUUID();
      await appendRows(realmId, 4);

      await tamper([[`DELETE FROM admin_audit_log WHERE realm_id = $1 AND seq <= 2`, [realmId]]]);

      await expect(auditLog.verifyAdminAuditChain(realmId)).resolves.toMatchObject({
        ok: false,
        rowsChecked: 0,
        break: { seq: 3, reason: 'sequence_mismatch', expectedSeq: 1 },
      });
    });
  });

  describe('admin_audit_log_prune', () => {
    const oldLog = (): AdminAuditLogRepository =>
      createAdminAuditLogRepository(db(), { now: () => Date.now() - 100 * DAY_MS });

    it('removes the oldest rows, records a checkpoint, and the chain still verifies', async () => {
      const realmId = randomUUID();
      await appendRows(realmId, 5, oldLog());
      await appendRows(realmId, 2);
      const before = await chainRows(realmId);

      const { rows } = await pool().query(`SELECT admin_audit_log_prune($1, 3)::int AS deleted`, [
        realmId,
      ]);
      expect(rows[0].deleted).toBe(3);

      expect((await chainRows(realmId)).map((row) => row.seq)).toEqual([4, 5, 6, 7]);
      await expect(auditLog.verifyAdminAuditChain(realmId)).resolves.toEqual({
        ok: true,
        realmId,
        rowsChecked: 4,
        checkpoint: { seq: 3, rowHash: before[2].row_hash.toString('hex') },
        head: { seq: 7, rowHash: before[6].row_hash.toString('hex') },
      });

      // The chain goes on after the prune.
      await appendRows(realmId, 1);
      await expect(auditLog.verifyAdminAuditChain(realmId)).resolves.toMatchObject({
        ok: true,
        rowsChecked: 5,
        head: { seq: 8 },
      });
    });

    it('resumes the chain from the checkpoint when every row was pruned', async () => {
      const realmId = randomUUID();
      await appendRows(realmId, 3, oldLog());

      await pool().query(`SELECT admin_audit_log_prune($1, 3)`, [realmId]);
      await expect(auditLog.verifyAdminAuditChain(realmId)).resolves.toMatchObject({
        ok: true,
        rowsChecked: 0,
        checkpoint: { seq: 3 },
        head: null,
      });

      await appendRows(realmId, 2);
      expect((await chainRows(realmId)).map((row) => row.seq)).toEqual([4, 5]);
      await expect(auditLog.verifyAdminAuditChain(realmId)).resolves.toMatchObject({
        ok: true,
        rowsChecked: 2,
      });
    });

    it('refuses to remove a row younger than 90 days', async () => {
      const realmId = randomUUID();
      await appendRows(realmId, 2, oldLog());
      await appendRows(
        realmId,
        1,
        createAdminAuditLogRepository(db(), { now: () => Date.now() - 89 * DAY_MS })
      );

      await expect(
        pgError(pool().query(`SELECT admin_audit_log_prune($1, 3)`, [realmId]))
      ).resolves.toEqual({ code: '23514', constraint: 'admin_audit_log_retention_floor' });
      expect(await chainRows(realmId)).toHaveLength(3);
    });

    it('refuses a seq that is not in the log', async () => {
      const realmId = randomUUID();
      await appendRows(realmId, 3, oldLog());
      await pool().query(`SELECT admin_audit_log_prune($1, 2)`, [realmId]);

      // P0002 = no_data_found: already pruned, or never written.
      for (const seq of [1, 2, 9]) {
        await expect(
          pgError(pool().query(`SELECT admin_audit_log_prune($1, $2)`, [realmId, seq]))
        ).resolves.toMatchObject({ code: 'P0002' });
      }
    });

    it('refuses to prune over a row removed or relinked outside the rules', async () => {
      const removed = randomUUID();
      await appendRows(removed, 5, oldLog());
      await tamper([[`DELETE FROM admin_audit_log WHERE realm_id = $1 AND seq = 2`, [removed]]]);

      const relinked = randomUUID();
      await appendRows(relinked, 5, oldLog());
      await tamper([
        [
          `UPDATE admin_audit_log SET prev_hash = sha256(prev_hash) WHERE realm_id = $1 AND seq = 3`,
          [relinked],
        ],
      ]);

      for (const realmId of [removed, relinked]) {
        await expect(
          pgError(pool().query(`SELECT admin_audit_log_prune($1, 3)`, [realmId]))
        ).resolves.toEqual({ code: '23514', constraint: 'admin_audit_log_checkpoints_unbroken' });
        // The prune left the evidence where verification finds it.
        await expect(auditLog.verifyAdminAuditChain(realmId)).resolves.toMatchObject({
          ok: false,
        });
      }
    });

    it('fails verification when a superuser changes the checkpoint', async () => {
      const realmId = randomUUID();
      await appendRows(realmId, 4, oldLog());
      await pool().query(`SELECT admin_audit_log_prune($1, 2)`, [realmId]);

      await tamper([
        [
          `UPDATE admin_audit_log_checkpoints SET row_hash = sha256(row_hash) WHERE realm_id = $1`,
          [realmId],
        ],
      ]);

      await expect(auditLog.verifyAdminAuditChain(realmId)).resolves.toMatchObject({
        ok: false,
        rowsChecked: 0,
        break: { seq: 3, reason: 'prev_hash_mismatch' },
      });
    });
  });
});
