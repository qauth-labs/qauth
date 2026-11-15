/**
 * The two functions an admin's deletion of an account runs through as the
 * admin role (migration 0079, `users.delete`, #681), against real Postgres:
 * the lock that holds the account until the deletion commits, and the
 * deletion, whose cascade removes what hangs off the account and whose guard
 * refuses a service account's account and one that holds an admin grant.
 *
 * Requires Docker; skips locally without it, fails on CI (requireDockerOrSkip).
 */
import { randomUUID } from 'node:crypto';

import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import type { DbClient } from '../db';
import { realms } from '../schema/core';
import { createAdminGrantsRepository } from './admin-grants.repository';
import type { AdminRoleCatalog } from './admin-roles.repository';
import { type IntegrationDb, setupIntegrationDb } from './integration-setup';
import { createRealmsRepository } from './realms.repository';
import { createServiceAccountsRepository } from './service-accounts.repository';
import { createUsersRepository } from './users.repository';

/** The tables whose rows of an account the deletion's cascade removes. */
const ACCOUNT_TABLES = [
  'user_credentials',
  'oauth_consents',
  'sessions',
  'refresh_tokens',
] as const;

const BUILT_IN = ['viewer', 'editor', 'security-admin'];

/**
 * A stand-in for the auth server's role catalog, which the grants repository
 * needs to write a grant: the built-in roles alone, as the grant below names.
 */
const catalog: AdminRoleCatalog = {
  builtInRoleNames: BUILT_IN,
  isBuiltInRoleName: (name) => BUILT_IN.includes(name),
  validatePermissionIds: (ids) => ({ valid: true, permissionIds: [...ids] }),
};

describe("users.delete's functions (real Postgres, #681)", () => {
  let ctx: IntegrationDb | undefined;
  let dockerUp = false;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    ctx = await setupIntegrationDb();
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

  function context(): IntegrationDb {
    if (!ctx) throw new Error('integration db not initialised');
    return ctx;
  }

  const db = () => context().database.db;
  const pool = () => context().database.pool;

  async function realm(name: string, isOperator = false): Promise<string> {
    const [row] = await db()
      .insert(realms)
      .values({ name, isOperator })
      .returning({ id: realms.id });
    return row.id;
  }

  async function account(realmId: string) {
    return createUsersRepository(db()).create(
      { realmId },
      {
        providerType: 'password',
        externalSub: `${randomUUID()}@example.com`,
        credentialData: { password_hash: '$argon2id$hash', email_verified: true },
      }
    );
  }

  /** What the account holds: a consent, a session, a refresh token and a code of one client. */
  async function holdings(realmId: string, userId: string): Promise<void> {
    const { rows } = await pool().query<{ id: string }>(
      `INSERT INTO oauth_clients (realm_id, client_id, client_secret_hash, name, redirect_uris)
       VALUES ($1, $2, 'h', 'App', '["https://app.example/cb"]') RETURNING id::text AS id`,
      [realmId, `app-${randomUUID()}`]
    );
    const client = rows[0].id;
    await pool().query(
      `INSERT INTO oauth_consents (user_id, oauth_client_id, realm_id, scopes)
       VALUES ($1, $2, $3, '["openid"]')`,
      [userId, client, realmId]
    );
    const session = await pool().query<{ id: string }>(
      `INSERT INTO sessions (realm_id, user_id, auth_time, expires_at)
       VALUES ($1, $2, $3, $4) RETURNING id::text AS id`,
      [realmId, userId, Date.now(), Date.now() + 3_600_000]
    );
    await pool().query(
      'INSERT INTO session_clients (session_id, oauth_client_id) VALUES ($1, $2)',
      [session.rows[0].id, client]
    );
    // The family's start is filled by migration 0038's trigger.
    await pool().query(
      `INSERT INTO refresh_tokens (token_hash, user_id, oauth_client_id, expires_at)
       VALUES (md5(random()::text) || md5(random()::text), $1, $2, $3)`,
      [userId, client, Date.now() + 3_600_000]
    );
  }

  async function countOf(table: (typeof ACCOUNT_TABLES)[number], userId: string): Promise<number> {
    const { rows } = await pool().query<{ count: number }>(
      `SELECT count(*)::int AS count FROM ${table} WHERE user_id = $1`,
      [userId]
    );
    return rows[0]?.count ?? 0;
  }

  /** Run `work` in one transaction, as the admin pipeline runs a handler. */
  async function inTransaction<T>(work: (tx: DbClient) => Promise<T>): Promise<T> {
    return db().transaction(async (tx) => work(tx));
  }

  it("deletes the realm's account with what hangs off it, and nothing of another account", async () => {
    const realmId = await realm('delete-1');
    const doomed = await account(realmId);
    const kept = await account(realmId);
    await holdings(realmId, doomed.id);
    await holdings(realmId, kept.id);
    const users = createUsersRepository(db());

    const deleted = await inTransaction(async (tx) => {
      expect(await users.lockForDeletion(realmId, doomed.id, tx)).toBe(true);
      return users.deleteAccount(realmId, doomed.id, tx);
    });
    expect(deleted).toBe(true);

    expect(await users.findById(realmId, doomed.id)).toBeUndefined();
    for (const table of ACCOUNT_TABLES) {
      expect(await countOf(table, doomed.id), table).toBe(0);
    }
    expect(await users.findById(realmId, kept.id)).toBeDefined();
    expect(await countOf('user_credentials', kept.id)).toBe(1);
    expect(await countOf('sessions', kept.id)).toBe(1);
    expect(await countOf('oauth_consents', kept.id)).toBe(1);
  });

  it('finds and deletes nothing for an unknown id, a deleted account or another realm’s', async () => {
    const realmId = await realm('delete-2');
    const otherRealm = await realm('delete-2-other');
    const elsewhere = await account(otherRealm);
    const users = createUsersRepository(db());

    await inTransaction(async (tx) => {
      expect(await users.lockForDeletion(realmId, randomUUID(), tx)).toBe(false);
      expect(await users.deleteAccount(realmId, randomUUID(), tx)).toBe(false);
      expect(await users.lockForDeletion(realmId, elsewhere.id, tx)).toBe(false);
      expect(await users.deleteAccount(realmId, elsewhere.id, tx)).toBe(false);
    });
    expect(await users.findById(otherRealm, elsewhere.id)).toBeDefined();

    // Deleted once: the second call finds nothing.
    const once = await account(realmId);
    await inTransaction(async (tx) => users.deleteAccount(realmId, once.id, tx));
    await inTransaction(async (tx) => {
      expect(await users.lockForDeletion(realmId, once.id, tx)).toBe(false);
      expect(await users.deleteAccount(realmId, once.id, tx)).toBe(false);
    });
  });

  it("refuses a service account's account, whoever calls it", async () => {
    const operator = await realm('operator', true);
    const created = await createServiceAccountsRepository(db()).create({
      realmId: operator,
      name: 'rp-account-closing',
      clientId: 'rp-account-closing',
      jwks: { keys: [{ kty: 'EC', crv: 'P-256', x: 'x', y: 'y', kid: 'k1' }] },
      createdBy: null,
    });
    const users = createUsersRepository(db());

    await inTransaction(async (tx) => {
      expect(await users.lockForDeletion(operator, created.userId, tx)).toBe(true);
      expect(await users.deleteAccount(operator, created.userId, tx)).toBe(false);
    });
    expect(await users.findById(operator, created.userId)).toMatchObject({
      isServiceAccount: true,
    });
  });

  it('refuses an account that holds an admin grant, and deletes it once the grant is revoked', async () => {
    const realmId = await realm('delete-3');
    const admin = await account(realmId);
    const grants = createAdminGrantsRepository(db(), { catalog });
    const grant = await grants.create({
      userId: admin.id,
      role: { kind: 'built-in', name: 'viewer' },
      targetRealmId: realmId,
      createdBy: null,
    });
    const users = createUsersRepository(db());

    expect(await inTransaction(async (tx) => users.deleteAccount(realmId, admin.id, tx))).toBe(
      false
    );
    expect(await users.findById(realmId, admin.id)).toBeDefined();

    await grants.revoke(realmId, grant.id);
    expect(await inTransaction(async (tx) => users.deleteAccount(realmId, admin.id, tx))).toBe(
      true
    );
    expect(await users.findById(realmId, admin.id)).toBeUndefined();
  });

  it('holds a new session of the account until the deletion commits, which then refuses it', async () => {
    const realmId = await realm('delete-4');
    const doomed = await account(realmId);
    const users = createUsersRepository(db());
    const locker = await pool().connect();
    const signIn = await pool().connect();
    try {
      await locker.query('BEGIN');
      const locked = await locker.query(
        'SELECT "id" FROM "users_lock_for_deletion"($1::uuid, $2::uuid)',
        [realmId, doomed.id]
      );
      expect(locked.rows).toHaveLength(1);

      // A sign-in that completes meanwhile: its session's foreign key waits
      // for the lock.
      let settled = false;
      const inserted = signIn
        .query(
          `INSERT INTO sessions (realm_id, user_id, auth_time, expires_at) VALUES ($1, $2, $3, $4)`,
          [realmId, doomed.id, Date.now(), Date.now() + 3_600_000]
        )
        .finally(() => {
          settled = true;
        });
      inserted.catch(() => undefined);
      await new Promise((resolve) => setTimeout(resolve, 300));
      expect(settled).toBe(false);

      const deleted = await locker.query(
        'SELECT "id" FROM "users_delete_account"($1::uuid, $2::uuid)',
        [realmId, doomed.id]
      );
      expect(deleted.rows).toHaveLength(1);
      await locker.query('COMMIT');

      // The account is gone: the waiting insert fails on its foreign key.
      await expect(inserted).rejects.toMatchObject({ code: '23503' });
      expect(await countOf('sessions', doomed.id)).toBe(0);
      expect(await users.findById(realmId, doomed.id)).toBeUndefined();
    } finally {
      await locker.query('ROLLBACK').catch(() => undefined);
      locker.release();
      signIn.release();
    }
  });

  it('lets the realm row stay: deleting an account never removes its realm', async () => {
    const realmId = await realm('delete-5');
    const doomed = await account(realmId);
    const users = createUsersRepository(db());
    await inTransaction(async (tx) => users.deleteAccount(realmId, doomed.id, tx));
    expect(await createRealmsRepository(db()).findById(realmId)).toBeDefined();
  });
});
