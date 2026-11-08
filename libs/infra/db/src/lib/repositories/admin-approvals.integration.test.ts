/**
 * Real-Postgres integration tests for approval requests (issue #512, ADR-019
 * Decision 7).
 *
 * Every move of an approval takes its row lock, then is one conditional
 * `UPDATE … RETURNING`: these tests hold that each move happens only from the
 * state it names, only before the expiry, at most once under concurrent
 * writers, and not at all when the transaction that made it rolls back; and
 * that a move that closes an approval, and the expiry sweep, overwrite its
 * nonce (#901). The table's CHECKs are exercised with raw SQL. Who may make
 * each move is the auth server's approval engine, tested there.
 *
 * Requires Docker; self-skips without it, same as the sibling suites.
 */
import { createHash, randomBytes } from 'node:crypto';

import { requireDockerOrSkip, testPrimaryCredential } from '@qauth-labs/shared-testing';
import { sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import type { AdminApprovalEntry } from '../schema/admin-approvals';
import {
  type AdminApprovalsRepository,
  createAdminApprovalsRepository,
  type NewAdminApproval,
} from './admin-approvals.repository';
import { type IntegrationDb, setupIntegrationDb } from './integration-setup';
import { createRealmsRepository, type RealmsRepository } from './realms.repository';
import { createUsersRepository, type UsersRepository } from './users.repository';

/**
 * When most approvals here are filed: far ahead of the database's clock, which
 * a write checks the expiry against too, so only the `now` a test hands over
 * expires one. 2100-01-01.
 */
const NOW = 4_102_444_800_000;
const LIFETIME = 5 * 60_000;

const sha256 = (text: string) => createHash('sha256').update(text).digest();

/** What an approver of the approvals here is shown. */
const DISPLAY = {
  operation: 'keys.rotate',
  title: 'Rotate the signing key signing-1',
  fields: [{ label: 'Retire the old key after', value: '7 days' }],
  reason: null,
};

describe('approval requests (real Postgres)', () => {
  let ctx: IntegrationDb | undefined;
  let dockerUp = false;
  let approvals: AdminApprovalsRepository;
  let realms: RealmsRepository;
  let users: UsersRepository;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    ctx = await setupIntegrationDb();
    approvals = createAdminApprovalsRepository(ctx.database.db);
    realms = createRealmsRepository(ctx.database.db);
    users = createUsersRepository(ctx.database.db);
  }, 180_000);

  afterAll(async () => {
    await ctx?.teardown();
  });

  beforeEach(async (test) => {
    if (!dockerUp || !ctx) {
      test.skip();
      return;
    }
    await ctx.reset();
  });

  function db(): IntegrationDb {
    if (!ctx) throw new Error('no database');
    return ctx;
  }

  /** A realm, its requester and a filed approval needing `required` approvals. */
  async function filed(required = 1, overrides: Partial<NewAdminApproval> = {}) {
    const realm = await realms.create({ name: `realm-${randomBytes(4).toString('hex')}` });
    const requester = await users.create({ realmId: realm.id }, testPrimaryCredential());
    const approval = await approvals.create({
      realmId: realm.id,
      requesterKind: 'human',
      requesterRealmId: realm.id,
      requesterId: requester.id,
      operationId: 'keys.rotate',
      method: 'POST',
      params: { realmId: realm.id, keyId: 'signing-1' },
      query: {},
      display: DISPLAY,
      opHash: sha256('operation'),
      nonce: randomBytes(32),
      reason: null,
      classification: { class: 'security', effects: ['key-custody'], permissions: ['keys.rotate'] },
      approvalsRequired: required,
      createdAt: NOW,
      expiresAt: NOW + LIFETIME,
      ...overrides,
    });
    return { realm, requester, approval };
  }

  const entry = (approverId: string, approverRealmId: string): AdminApprovalEntry => ({
    approverRealmId,
    approverId,
    credentialId: `credential-${approverId}`,
    factor: 'test',
    approvedAt: NOW + 1_000,
  });

  it('files a pending approval with no approval yet, readable in its realm only', async () => {
    const { realm, approval } = await filed();
    expect(approval).toMatchObject({ status: 'pending', approvals: [], usedAt: null });
    expect(approval.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-/);
    expect(await approvals.findById(realm.id, approval.id)).toMatchObject({
      opHash: sha256('operation'),
      method: 'POST',
      params: { realmId: realm.id, keyId: 'signing-1' },
      query: {},
      display: DISPLAY,
    });
    const other = await realms.create({ name: 'other' });
    expect(await approvals.findById(other.id, approval.id)).toBeUndefined();
    expect(await approvals.findById(realm.id, 'not-a-uuid')).toBeUndefined();
  });

  it('becomes approved with its last approval, and takes each approver once', async () => {
    const { realm, requester, approval } = await filed(2);
    const second = await users.create({ realmId: realm.id }, testPrimaryCredential());

    const first = await approvals.addApproval(realm.id, approval.id, {
      expectedCount: 0,
      entry: entry(requester.id, realm.id),
      now: NOW + 1_000,
    });
    expect(first).toMatchObject({ status: 'pending' });
    // The same approver again, or a writer that read an older count.
    expect(
      await approvals.addApproval(realm.id, approval.id, {
        expectedCount: 1,
        entry: entry(requester.id, realm.id),
        now: NOW + 1_000,
      })
    ).toBeUndefined();
    expect(
      await approvals.addApproval(realm.id, approval.id, {
        expectedCount: 0,
        entry: entry(second.id, realm.id),
        now: NOW + 1_000,
      })
    ).toBeUndefined();

    const done = await approvals.addApproval(realm.id, approval.id, {
      expectedCount: 1,
      entry: entry(second.id, realm.id),
      now: NOW + 1_000,
    });
    expect(done?.status).toBe('approved');
    expect(done?.approvals.map((given) => given.approverId)).toEqual([requester.id, second.id]);
  });

  it('takes no approval, denial or cancellation once expired', async () => {
    const { realm, requester, approval } = await filed();
    const expired = NOW + LIFETIME;
    expect(
      await approvals.addApproval(realm.id, approval.id, {
        expectedCount: 0,
        entry: entry(requester.id, realm.id),
        now: expired,
      })
    ).toBeUndefined();
    expect(
      await approvals.deny(realm.id, approval.id, { expectedCount: 0, now: expired })
    ).toBeUndefined();
    expect(
      await approvals.cancel(realm.id, approval.id, {
        requesterRealmId: realm.id,
        requesterId: requester.id,
        expected: { status: 'pending', approvalCount: 0 },
        now: expired,
      })
    ).toBeUndefined();
  });

  it('is cancelled only by its requester, from the state the caller saw', async () => {
    const { realm, requester, approval } = await filed();
    const stranger = await users.create({ realmId: realm.id }, testPrimaryCredential());
    const cancel = (requesterId: string, status: 'pending' | 'approved') =>
      approvals.cancel(realm.id, approval.id, {
        requesterRealmId: realm.id,
        requesterId,
        expected: { status, approvalCount: 0 },
        now: NOW + 1_000,
      });

    expect(await cancel(stranger.id, 'pending')).toBeUndefined();
    expect(await cancel(requester.id, 'approved')).toBeUndefined();
    expect((await cancel(requester.id, 'pending'))?.status).toBe('cancelled');
    expect(await cancel(requester.id, 'pending')).toBeUndefined();
  });

  it('denies a pending approval once, and nothing approves it after', async () => {
    const { realm, requester, approval } = await filed();
    expect(
      (await approvals.deny(realm.id, approval.id, { expectedCount: 0, now: NOW + 1_000 }))?.status
    ).toBe('denied');
    expect(
      await approvals.addApproval(realm.id, approval.id, {
        expectedCount: 0,
        entry: entry(requester.id, realm.id),
        now: NOW + 1_000,
      })
    ).toBeUndefined();
  });

  /** A filed approval with its one approval in. */
  async function approved() {
    const filedApproval = await filed();
    const { realm, requester, approval } = filedApproval;
    await approvals.addApproval(realm.id, approval.id, {
      expectedCount: 0,
      entry: entry(requester.id, realm.id),
      now: NOW + 1_000,
    });
    return filedApproval;
  }

  it('is consumed once, for its own request and before it expires', async () => {
    const { realm, approval } = await approved();
    const consume = (opHash: Buffer, now: number) =>
      db().database.db.transaction((tx) =>
        approvals.consume(realm.id, approval.id, { opHash, now }, tx)
      );

    expect(await consume(sha256('another operation'), NOW + 2_000)).toBeUndefined();
    expect(await consume(sha256('operation'), NOW + LIFETIME)).toBeUndefined();
    const used = await consume(sha256('operation'), NOW + 2_000);
    expect(used).toMatchObject({ status: 'consumed', usedAt: NOW + 2_000 });
    expect(await consume(sha256('operation'), NOW + 2_000)).toBeUndefined();
  });

  it('is consumed by exactly one of two concurrent transactions', async () => {
    const { realm, approval } = await approved();
    let release: () => void = () => undefined;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });

    // The first transaction consumes and stays open; the second blocks on the
    // row until the first commits, then finds it consumed.
    const first = db().database.db.transaction(async (tx) => {
      const used = await approvals.consume(
        realm.id,
        approval.id,
        { opHash: sha256('operation'), now: NOW + 2_000 },
        tx
      );
      await held;
      return used;
    });
    await waitFor(async () => (await openTransactionsOnApprovals()) >= 1);
    const second = db().database.db.transaction((tx) =>
      approvals.consume(
        realm.id,
        approval.id,
        { opHash: sha256('operation'), now: NOW + 2_000 },
        tx
      )
    );
    await waitFor(async () => (await lockWaiters()) >= 1);
    release();

    const results = await Promise.all([first, second]);
    expect(results.map((result) => result?.status)).toEqual(['consumed', undefined]);
  });

  it('is not consumed once it expired while another transaction held it', async () => {
    // A transaction that consumed it holds its row past the expiry, then
    // rolls back. The consumer that waited on the row sampled its `now`
    // before the wait: the expiry is checked again once it holds the row.
    const filedAt = Date.now();
    const { realm, requester, approval } = await filed(1, {
      createdAt: filedAt - 1_000,
      expiresAt: filedAt + 1_000,
    });
    await approvals.addApproval(realm.id, approval.id, {
      expectedCount: 0,
      entry: entry(requester.id, realm.id),
      now: filedAt,
    });
    let rollBack: () => void = () => undefined;
    const held = new Promise<void>((resolve) => {
      rollBack = resolve;
    });
    const consume = (tx: Parameters<AdminApprovalsRepository['consume']>[3]) =>
      approvals.consume(realm.id, approval.id, { opHash: sha256('operation'), now: filedAt }, tx);

    const first = db().database.db.transaction(async (tx) => {
      expect(await consume(tx)).toMatchObject({ status: 'consumed' });
      await held;
      throw new Error('the operation failed after the approval expired');
    });
    await waitFor(async () => (await openTransactionsOnApprovals()) >= 1);
    const second = db().database.db.transaction((tx) => consume(tx));
    await waitFor(async () => (await lockWaiters()) >= 1);
    await new Promise((resolve) => setTimeout(resolve, approval.expiresAt - Date.now() + 200));
    rollBack();

    await expect(first).rejects.toThrow('the operation failed');
    expect(await second).toBeUndefined();
    expect((await approvals.findById(realm.id, approval.id))?.status).toBe('approved');
  });

  it('stays approved when the transaction that consumed it rolls back', async () => {
    const { realm, approval } = await approved();
    await expect(
      db().database.db.transaction(async (tx) => {
        await approvals.consume(
          realm.id,
          approval.id,
          { opHash: sha256('operation'), now: NOW + 2_000 },
          tx
        );
        throw new Error('the operation failed after its change');
      })
    ).rejects.toThrow('the operation failed');
    expect((await approvals.findById(realm.id, approval.id))?.status).toBe('approved');
  });

  it('keeps its status consistent with the approvals it holds', async () => {
    const { approval } = await filed();
    const update = (assignment: string) =>
      db().database.pool.query(`UPDATE admin_approvals SET ${assignment} WHERE id = $1`, [
        approval.id,
      ]);
    await expect(update(`status = 'approved'`)).rejects.toMatchObject({
      constraint: 'admin_approvals_status_matches_approvals',
    });
    await expect(update(`status = 'consumed', used_at = 1`)).rejects.toMatchObject({
      constraint: 'admin_approvals_status_matches_approvals',
    });
    await expect(update(`status = 'cancelled', used_at = 1`)).rejects.toMatchObject({
      constraint: 'admin_approvals_used_exactly_when_consumed',
    });
    await expect(update(`status = 'expired_unused'`)).rejects.toMatchObject({
      constraint: 'admin_approvals_status',
    });
    // An open approval has what its approver is shown; a closed one may not.
    await expect(update(`display = NULL`)).rejects.toMatchObject({
      constraint: 'admin_approvals_open_has_display',
    });
    await expect(update(`display = '[]'`)).rejects.toMatchObject({
      constraint: 'admin_approvals_display_object',
    });
    await expect(update(`params = '[]'`)).rejects.toMatchObject({
      constraint: 'admin_approvals_params_object',
    });
    await expect(update(`query = '"q"'`)).rejects.toMatchObject({
      constraint: 'admin_approvals_query_object',
    });
    await expect(update(`method = ''`)).rejects.toMatchObject({
      constraint: 'admin_approvals_method_not_empty',
    });
    await update(`status = 'expired', display = NULL`);
    await expect(update(`approvals_required = 3`)).rejects.toMatchObject({
      constraint: 'admin_approvals_required_range',
    });
    await expect(update(`expires_at = created_at`)).rejects.toMatchObject({
      constraint: 'admin_approvals_expires_after_created',
    });
    await expect(update(`op_hash = '\\x00'`)).rejects.toMatchObject({
      constraint: 'admin_approvals_op_hash_sha256',
    });
  });

  /** The stored nonce of `id`. */
  async function nonceOf(id: string): Promise<Buffer> {
    const { rows } = await db().database.pool.query<{ nonce: Buffer }>(
      'SELECT nonce FROM admin_approvals WHERE id = $1',
      [id]
    );
    return rows[0].nonce;
  }

  // Acceptance criterion (#901): a closed approval's nonce is no longer the
  // one its op_hash was computed with.
  it('overwrites the nonce once consumed, cancelled or denied, and keeps it while open', async () => {
    const used = await approved();
    expect(await nonceOf(used.approval.id)).toEqual(used.approval.nonce);
    const consumed = await db().database.db.transaction((tx) =>
      approvals.consume(
        used.realm.id,
        used.approval.id,
        { opHash: sha256('operation'), now: NOW + 2_000 },
        tx
      )
    );
    expect(consumed?.nonce).toHaveLength(32);
    expect(consumed?.nonce.equals(used.approval.nonce)).toBe(false);
    expect(await nonceOf(used.approval.id)).toEqual(consumed?.nonce);
    // The op_hash stays: the audit log binds to it.
    expect(consumed?.opHash).toEqual(sha256('operation'));

    const cancelled = await filed();
    const withdrawn = await approvals.cancel(cancelled.realm.id, cancelled.approval.id, {
      requesterRealmId: cancelled.realm.id,
      requesterId: cancelled.requester.id,
      expected: { status: 'pending', approvalCount: 0 },
      now: NOW + 1_000,
    });
    expect(withdrawn?.nonce.equals(cancelled.approval.nonce)).toBe(false);

    const denied = await filed();
    const declined = await approvals.deny(denied.realm.id, denied.approval.id, {
      expectedCount: 0,
      now: NOW + 1_000,
    });
    expect(declined?.nonce.equals(denied.approval.nonce)).toBe(false);

    // Each overwrite draws its own bytes.
    const nonces = [consumed?.nonce, withdrawn?.nonce, declined?.nonce].map((nonce) =>
      nonce?.toString('hex')
    );
    expect(new Set(nonces).size).toBe(3);
  });

  it('keeps no column that holds a body or a hash of the request without its nonce', async () => {
    const { rows } = await db().database.pool.query<{ column_name: string }>(
      `SELECT column_name FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'admin_approvals' ORDER BY column_name`
    );
    expect(rows.map((row) => row.column_name)).toEqual([
      'approvals',
      'approvals_required',
      'classification',
      'created_at',
      'display',
      'expires_at',
      'id',
      'method',
      'nonce',
      'op_hash',
      'operation_id',
      'params',
      'query',
      'realm_id',
      'reason',
      'requester_id',
      'requester_kind',
      'requester_realm_id',
      'status',
      'used_at',
    ]);
  });

  it('marks the approvals that expired unused, with a new nonce, and nothing else', async () => {
    const lapsedPending = await filed();
    const lapsedApproved = await approved();
    const live = await filed(1, { createdAt: NOW + LIFETIME, expiresAt: NOW + 2 * LIFETIME });
    const closed = await filed();
    await approvals.deny(closed.realm.id, closed.approval.id, {
      expectedCount: 0,
      now: NOW + 1_000,
    });
    const closedNonce = await nonceOf(closed.approval.id);

    // Before their expiry, nothing.
    expect(await approvals.expireLapsed(NOW + LIFETIME - 1, 100)).toBe(0);
    // At it, the two open ones that expired, across realms.
    expect(await approvals.expireLapsed(NOW + LIFETIME, 100)).toBe(2);
    for (const { realm, approval } of [lapsedPending, lapsedApproved]) {
      const stored = await approvals.findById(realm.id, approval.id);
      expect(stored?.status).toBe('expired');
      expect(stored?.nonce.equals(approval.nonce)).toBe(false);
      expect(stored?.opHash).toEqual(approval.opHash);
    }
    expect(await approvals.findById(live.realm.id, live.approval.id)).toMatchObject({
      status: 'pending',
      nonce: live.approval.nonce,
    });
    expect(await approvals.findById(closed.realm.id, closed.approval.id)).toMatchObject({
      status: 'denied',
      nonce: closedNonce,
    });
    // Repeated, it marks nothing twice; an expired approval takes no move.
    expect(await approvals.expireLapsed(NOW + LIFETIME, 100)).toBe(0);
    expect(
      await approvals.cancel(lapsedPending.realm.id, lapsedPending.approval.id, {
        requesterRealmId: lapsedPending.realm.id,
        requesterId: lapsedPending.requester.id,
        expected: { status: 'pending', approvalCount: 0 },
        now: NOW + 1_000,
      })
    ).toBeUndefined();
  });

  it('marks at most its limit, the earliest expired first', async () => {
    const first = await filed(1, { createdAt: NOW - 2_000, expiresAt: NOW - 1_000 });
    const second = await filed(1, { createdAt: NOW - 2_000, expiresAt: NOW });
    expect(await approvals.expireLapsed(NOW + LIFETIME, 1)).toBe(1);
    expect((await approvals.findById(first.realm.id, first.approval.id))?.status).toBe('expired');
    expect((await approvals.findById(second.realm.id, second.approval.id))?.status).toBe('pending');
    expect(await approvals.expireLapsed(NOW + LIFETIME, 1)).toBe(1);
    expect(await approvals.expireLapsed(NOW + LIFETIME, 1)).toBe(0);
  });

  it('skips an approval another transaction holds, and marks it once it is free', async () => {
    const { realm, approval } = await approved();
    let release: () => void = () => undefined;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    const holder = db().database.db.transaction(async (tx) => {
      await tx.execute(sql`SELECT id FROM admin_approvals WHERE id = ${approval.id} FOR UPDATE`);
      await held;
    });
    await waitFor(async () => (await rowLocksOnApprovals()) >= 1);

    expect(await approvals.expireLapsed(NOW + LIFETIME, 100)).toBe(0);
    release();
    await holder;
    expect(await approvals.expireLapsed(NOW + LIFETIME, 100)).toBe(1);
    expect((await approvals.findById(realm.id, approval.id))?.status).toBe('expired');
  });

  it('files an approval pending and empty, whatever else its caller hands over', async () => {
    const { realm, approval } = await approved();
    const stored = await approvals.findById(realm.id, approval.id);
    expect(stored).toMatchObject({ status: 'approved' });
    const again = await approvals.create({
      ...(stored as NonNullable<typeof stored>),
      display: DISPLAY,
      createdAt: NOW + 1_000,
    });
    expect(again.id).not.toBe(approval.id);
    expect(again).toMatchObject({ status: 'pending', approvals: [], usedAt: null });
  });

  it('goes with its realm', async () => {
    const { realm, approval } = await filed();
    await db().database.pool.query('DELETE FROM realms WHERE id = $1', [realm.id]);
    expect(await approvals.findById(realm.id, approval.id)).toBeUndefined();
  });

  /**
   * Backends of this database inside a transaction that touched
   * admin_approvals. `l.database` keeps out the server's other databases:
   * copied from one template, their tables have the same OIDs.
   */
  async function openTransactionsOnApprovals(): Promise<number> {
    const { rows } = await db().database.pool.query<{ count: string }>(
      `SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid = l.relation
        WHERE c.relname = 'admin_approvals' AND l.mode = 'RowExclusiveLock' AND l.granted
          AND l.database = (SELECT oid FROM pg_database WHERE datname = current_database())`
    );
    return Number(rows[0].count);
  }

  /** Backends of this database holding a row lock (`FOR UPDATE`) on admin_approvals. */
  async function rowLocksOnApprovals(): Promise<number> {
    const { rows } = await db().database.pool.query<{ count: string }>(
      `SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid = l.relation
        WHERE c.relname = 'admin_approvals' AND l.mode = 'RowShareLock' AND l.granted
          AND l.database = (SELECT oid FROM pg_database WHERE datname = current_database())`
    );
    return Number(rows[0].count);
  }

  /** Backends of this database waiting on a lock. */
  async function lockWaiters(): Promise<number> {
    const { rows } = await db().database.pool.query<{ count: string }>(
      `SELECT count(*) FROM pg_stat_activity
        WHERE datname = current_database() AND wait_event_type = 'Lock'`
    );
    return Number(rows[0].count);
  }
});

/** Poll `condition` until it holds, for up to 10 s. */
async function waitFor(condition: () => Promise<boolean>): Promise<void> {
  const deadline = Date.now() + 10_000;
  while (!(await condition())) {
    if (Date.now() > deadline) throw new Error('the condition never held');
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}
