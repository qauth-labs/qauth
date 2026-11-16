/**
 * Real-Postgres integration tests for the act-chain tokens issued to admins
 * (issue #523, migration 0082).
 *
 * Exercises what a unit test cannot: the live read that refuses an expired
 * token and one whose approval is not consumed, the realm scoping of every
 * read, the newest-first list of a user's rows, the table's CHECKs and the
 * cascades from the user and the realm.
 *
 * Requires Docker; self-skips without it, same as the sibling suites.
 */
import { createHash, randomBytes, randomUUID } from 'node:crypto';

import { requireDockerOrSkip, testPrimaryCredential } from '@qauth-labs/shared-testing';
import { sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  type AdminActSessionsRepository,
  createAdminActSessionsRepository,
  type NewAdminActSession,
} from './admin-act-sessions.repository';
import {
  type AdminApprovalsRepository,
  createAdminApprovalsRepository,
} from './admin-approvals.repository';
import { type IntegrationDb, setupIntegrationDb } from './integration-setup';
import { createRealmsRepository, type RealmsRepository } from './realms.repository';
import { createUsersRepository, type UsersRepository } from './users.repository';

/** Far ahead of the database's clock, which no read here checks. 2100-01-01. */
const NOW = 4_102_444_800_000;
const TEN_MINUTES = 10 * 60_000;

const sha256 = (text: string) => createHash('sha256').update(text).digest();

describe('act-chain tokens issued to admins (real Postgres, #523)', () => {
  let ctx: IntegrationDb | undefined;
  let dockerUp = false;
  let sessions: AdminActSessionsRepository;
  let approvals: AdminApprovalsRepository;
  let realms: RealmsRepository;
  let users: UsersRepository;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    ctx = await setupIntegrationDb();
    sessions = createAdminActSessionsRepository(ctx.database.db);
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

  function db() {
    if (!ctx) throw new Error('no database');
    return ctx.database.db;
  }

  /** A realm, a user of it, its admin, and an approval of `status` in it. */
  async function fixture(status: 'approved' | 'consumed' = 'consumed') {
    const realm = await realms.create({ name: `realm-${randomBytes(4).toString('hex')}` });
    const user = await users.create({ realmId: realm.id }, testPrimaryCredential());
    const admin = await users.create({ realmId: realm.id }, testPrimaryCredential());
    const opHash = sha256('operation');
    const approval = await approvals.create({
      realmId: realm.id,
      requesterKind: 'human',
      requesterRealmId: realm.id,
      requesterId: admin.id,
      operationId: 'users.actChainTokens.create',
      method: 'POST',
      params: { realmId: realm.id, userId: user.id },
      query: {},
      display: {
        operation: 'users.actChainTokens.create',
        title: 'Act for',
        fields: [],
        reason: null,
      },
      opHash,
      nonce: randomBytes(32),
      reason: null,
      classification: {
        class: 'security',
        effects: ['issue-for-other'],
        permissions: ['users.security'],
      },
      approvalsRequired: 1,
      createdAt: NOW,
      expiresAt: NOW + 5 * 60_000,
    });
    await approvals.addApproval(realm.id, approval.id, {
      expectedCount: 0,
      entry: {
        approverRealmId: realm.id,
        approverId: admin.id,
        credentialId: 'credential',
        factor: 'test',
        approvedAt: NOW + 1_000,
      },
      now: NOW + 1_000,
    });
    if (status === 'consumed') {
      await db().transaction((tx) =>
        approvals.consume(realm.id, approval.id, { opHash, now: NOW + 2_000 }, tx)
      );
    }
    return { realmId: realm.id, userId: user.id, adminId: admin.id, approvalId: approval.id };
  }

  function session(
    at: Awaited<ReturnType<typeof fixture>>,
    overrides: Partial<NewAdminActSession> = {}
  ): NewAdminActSession {
    return {
      realmId: at.realmId,
      userId: at.userId,
      adminRealmId: at.realmId,
      adminUserId: at.adminId,
      adminClientId: 'admin-console',
      approvalId: at.approvalId,
      operationId: 'users.actChainTokens.create',
      permissionIds: ['users.security'],
      tokenJti: randomUUID(),
      scopes: ['qauth:account:read'],
      createdAt: NOW + 2_000,
      expiresAt: NOW + 2_000 + TEN_MINUTES,
      ...overrides,
    };
  }

  it('writes a row and reads it live while unexpired and its approval consumed, in its realm only', async () => {
    const at = await fixture();
    const written = await db().transaction((tx) => sessions.create(tx, session(at)));
    expect(written).toMatchObject({
      realmId: at.realmId,
      userId: at.userId,
      adminUserId: at.adminId,
      approvalId: at.approvalId,
      scopes: ['qauth:account:read'],
      permissionIds: ['users.security'],
    });

    expect(await sessions.findLive(at.realmId, written.tokenJti, NOW + 3_000)).toEqual(written);
    // Expired: refused from its `exp` on.
    expect(
      await sessions.findLive(at.realmId, written.tokenJti, written.expiresAt)
    ).toBeUndefined();
    // Another realm's token id names nothing here.
    const other = await fixture();
    expect(await sessions.findLive(other.realmId, written.tokenJti, NOW + 3_000)).toBeUndefined();
    expect(await sessions.findLive('not-a-uuid', written.tokenJti, NOW)).toBeUndefined();
  });

  it('refuses a token whose approval is not consumed, or names no approval of its realm', async () => {
    const pending = await fixture('approved');
    const unconsumed = await db().transaction((tx) => sessions.create(tx, session(pending)));
    expect(
      await sessions.findLive(pending.realmId, unconsumed.tokenJti, NOW + 3_000)
    ).toBeUndefined();

    const at = await fixture();
    const other = await fixture();
    // The approval of another realm does not stand behind a token of this one.
    const foreign = await db().transaction((tx) =>
      sessions.create(tx, session(at, { approvalId: other.approvalId }))
    );
    expect(await sessions.findLive(at.realmId, foreign.tokenJti, NOW + 3_000)).toBeUndefined();
  });

  it('lists a user rows newest first, in the realm only, and never another user', async () => {
    const at = await fixture();
    const first = await db().transaction((tx) => sessions.create(tx, session(at)));
    const second = await db().transaction((tx) =>
      sessions.create(tx, session(at, { createdAt: NOW + 5_000, expiresAt: NOW + 6_000 }))
    );
    const stranger = await users.create({ realmId: at.realmId }, testPrimaryCredential());
    await db().transaction((tx) => sessions.create(tx, session(at, { userId: stranger.id })));

    expect((await sessions.listForUser(at.realmId, at.userId)).map((row) => row.id)).toEqual([
      second.id,
      first.id,
    ]);
    expect(await sessions.listForUser(at.realmId, at.userId, { limit: 1 })).toHaveLength(1);
    const other = await fixture();
    expect(await sessions.listForUser(other.realmId, at.userId)).toEqual([]);
  });

  it('refuses a lifetime over ten minutes, empty scopes and a user of another realm', async () => {
    const at = await fixture();
    await expect(
      db().transaction((tx) =>
        sessions.create(tx, session(at, { expiresAt: NOW + 2_000 + TEN_MINUTES + 1 }))
      )
    ).rejects.toThrow(RangeError);
    await expect(
      db().transaction((tx) => sessions.create(tx, session(at, { scopes: [] })))
    ).rejects.toThrow(RangeError);
    // The CHECK holds the lifetime for every writer.
    await expect(
      db().execute(sql`
        INSERT INTO admin_act_sessions (realm_id, user_id, admin_realm_id, admin_user_id,
          admin_client_id, approval_id, operation_id, permission_ids, token_jti, scopes,
          created_at, expires_at)
        VALUES (${at.realmId}, ${at.userId}, ${at.realmId}, ${at.adminId}, 'admin-console',
          ${at.approvalId}, 'users.actChainTokens.create', '["users.security"]'::jsonb,
          ${randomUUID()}, '["qauth:account:read"]'::jsonb, ${NOW}, ${NOW + TEN_MINUTES + 1})
      `)
    ).rejects.toMatchObject({ cause: { constraint: 'admin_act_sessions_lifetime' } });
    // A user of another realm is no user of the row's realm.
    const other = await fixture();
    await expect(
      db().transaction((tx) => sessions.create(tx, session(at, { userId: other.userId })))
    ).rejects.toMatchObject({ cause: { constraint: 'admin_act_sessions_user_realm_fk' } });
  });

  it('goes with the user, and stays when the admin account is deleted', async () => {
    const at = await fixture();
    const written = await db().transaction((tx) => sessions.create(tx, session(at)));
    const neighbour = await users.create({ realmId: at.realmId }, testPrimaryCredential());
    const kept = await db().transaction((tx) =>
      sessions.create(tx, session(at, { userId: neighbour.id }))
    );
    await db().execute(sql`DELETE FROM users WHERE id = ${at.adminId}`);
    expect(await sessions.listForUser(at.realmId, kept.userId)).toHaveLength(1);
    await db().execute(sql`DELETE FROM users WHERE id = ${at.userId}`);
    expect(await sessions.findLive(at.realmId, written.tokenJti, NOW + 3_000)).toBeUndefined();
    expect(await sessions.listForUser(at.realmId, at.userId)).toEqual([]);
  });
});
