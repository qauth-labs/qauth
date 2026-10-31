/**
 * Real-Postgres integration tests for approval requests (issue #512, ADR-019
 * Decision 7).
 *
 * Every move of an approval takes its row lock, then is one conditional
 * `UPDATE … RETURNING`: these tests hold that each move happens only from the
 * state it names, only before the expiry, at most once under concurrent
 * writers, and not at all when the transaction that made it rolls back. The
 * table's CHECKs are exercised with raw SQL. Who may make each move is the
 * auth server's approval engine, tested there.
 *
 * Requires Docker; self-skips without it, same as the sibling suites.
 */
import { createHash, randomBytes } from 'node:crypto';

import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
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
    const requester = await users.create({ realmId: realm.id });
    const canonical = {
      operationId: 'keys.rotate',
      method: 'POST',
      realmId: realm.id,
      body: { smtpPassword: 'a secret the operation sets' },
    };
    const approval = await approvals.create({
      realmId: realm.id,
      requesterKind: 'human',
      requesterRealmId: realm.id,
      requesterId: requester.id,
      operationId: 'keys.rotate',
      canonicalRequest: canonical,
      requestHash: sha256('request'),
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
    expect((await approvals.findById(realm.id, approval.id))?.requestHash).toEqual(
      sha256('request')
    );
    const other = await realms.create({ name: 'other' });
    expect(await approvals.findById(other.id, approval.id)).toBeUndefined();
    expect(await approvals.findById(realm.id, 'not-a-uuid')).toBeUndefined();
  });

  it('becomes approved with its last approval, and takes each approver once', async () => {
    const { realm, requester, approval } = await filed(2);
    const second = await users.create({ realmId: realm.id });

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
    const stranger = await users.create({ realmId: realm.id });
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
    const consume = (requestHash: Buffer, now: number) =>
      db().database.db.transaction((tx) =>
        approvals.consume(realm.id, approval.id, { requestHash, now }, tx)
      );

    expect(await consume(sha256('another request'), NOW + 2_000)).toBeUndefined();
    expect(await consume(sha256('request'), NOW + LIFETIME)).toBeUndefined();
    const used = await consume(sha256('request'), NOW + 2_000);
    expect(used).toMatchObject({ status: 'consumed', usedAt: NOW + 2_000 });
    expect(await consume(sha256('request'), NOW + 2_000)).toBeUndefined();
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
        { requestHash: sha256('request'), now: NOW + 2_000 },
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
        { requestHash: sha256('request'), now: NOW + 2_000 },
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
      approvals.consume(
        realm.id,
        approval.id,
        { requestHash: sha256('request'), now: filedAt },
        tx
      );

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
          { requestHash: sha256('request'), now: NOW + 2_000 },
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
    await expect(update(`status = 'expired'`)).rejects.toMatchObject({
      constraint: 'admin_approvals_status',
    });
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

  it('drops the body once consumed, cancelled or denied, and keeps it while open', async () => {
    const bodyOf = async (id: string) =>
      (
        await db().database.pool.query<{ body: unknown }>(
          `SELECT canonical_request -> 'body' AS body FROM admin_approvals WHERE id = $1`,
          [id]
        )
      ).rows[0].body;

    const used = await approved();
    expect(await bodyOf(used.approval.id)).toEqual({ smtpPassword: 'a secret the operation sets' });
    await db().database.db.transaction((tx) =>
      approvals.consume(
        used.realm.id,
        used.approval.id,
        { requestHash: sha256('request'), now: NOW + 2_000 },
        tx
      )
    );
    expect(await bodyOf(used.approval.id)).toBeNull();

    const cancelled = await filed();
    await approvals.cancel(cancelled.realm.id, cancelled.approval.id, {
      requesterRealmId: cancelled.realm.id,
      requesterId: cancelled.requester.id,
      expected: { status: 'pending', approvalCount: 0 },
      now: NOW + 1_000,
    });
    expect(await bodyOf(cancelled.approval.id)).toBeNull();

    const denied = await filed();
    await approvals.deny(denied.realm.id, denied.approval.id, {
      expectedCount: 0,
      now: NOW + 1_000,
    });
    expect(await bodyOf(denied.approval.id)).toBeNull();
    // The rest of the stored request stays.
    expect(
      (await approvals.findById(denied.realm.id, denied.approval.id))?.canonicalRequest
    ).toEqual({ operationId: 'keys.rotate', method: 'POST', realmId: denied.realm.id });
  });

  it('files an approval pending and empty, whatever else its caller hands over', async () => {
    const { realm, approval } = await approved();
    const stored = await approvals.findById(realm.id, approval.id);
    expect(stored).toMatchObject({ status: 'approved' });
    const again = await approvals.create({
      ...(stored as NonNullable<typeof stored>),
      createdAt: NOW + 1_000,
    });
    expect(again.id).not.toBe(approval.id);
    expect(again).toMatchObject({ status: 'pending', approvals: [], usedAt: null });
  });

  it('drops the body of an approval that expired unused when the next one of its realm is filed', async () => {
    const bodyOf = async (id: string) =>
      (
        await db().database.pool.query<{ body: unknown }>(
          `SELECT canonical_request -> 'body' AS body FROM admin_approvals WHERE id = $1`,
          [id]
        )
      ).rows[0].body;
    const first = await filed();
    const elsewhere = await filed();
    // Filed in the first one's realm before it expires: it keeps its body.
    const live = await approvals.create({
      ...first.approval,
      reason: null,
      createdAt: NOW + 1_000,
      expiresAt: NOW + 1_000 + LIFETIME,
    });
    expect(await bodyOf(first.approval.id)).not.toBeNull();
    // Filed once it has expired: its body goes, the open one's and another
    // realm's stay.
    await approvals.create({
      ...first.approval,
      reason: null,
      createdAt: NOW + LIFETIME,
      expiresAt: NOW + 2 * LIFETIME,
    });
    expect(await bodyOf(first.approval.id)).toBeNull();
    expect(await bodyOf(live.id)).not.toBeNull();
    expect(await bodyOf(elsewhere.approval.id)).not.toBeNull();
  });

  it('goes with its realm', async () => {
    const { realm, approval } = await filed();
    await db().database.pool.query('DELETE FROM realms WHERE id = $1', [realm.id]);
    expect(await approvals.findById(realm.id, approval.id)).toBeUndefined();
  });

  /** Backends of this database inside a transaction that touched admin_approvals. */
  async function openTransactionsOnApprovals(): Promise<number> {
    const { rows } = await db().database.pool.query<{ count: string }>(
      `SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid = l.relation
        WHERE c.relname = 'admin_approvals' AND l.mode = 'RowExclusiveLock' AND l.granted`
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
