/**
 * Seed-then-migrate test for migration 0068: each account's primary identity
 * (ADR-015 Decision 8 and question 13, #846).
 *
 * After the backfill every user with a credential that is no authenticator app
 * has exactly one primary credential, and it is the oldest such credential;
 * from then on the database marks the credential written with the account,
 * marks no other, and never moves the mark.
 *
 * Requires Docker; self-skips without it. The schema is rebuilt from scratch
 * and upgraded through 0067, then 0068, so a later migration cannot change
 * what this test sees.
 */
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

const MIGRATION_IDX = 68;

/** A passkey's `credential_data` as a release before 0068 stored it, with no `user_verified`. */
const PASSKEY_DATA = { public_key: 'pk', rp_id: 'auth.example.com', user_handle: 'h' };

describe('migration 0068 — primary credential (seed-then-migrate)', () => {
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

  /** Apply every migration through 0068. */
  async function migrate(): Promise<void> {
    if (!container) throw new Error('no container');
    await applyQauthMigrations(container.connectionString, through);
  }

  async function realm(): Promise<string> {
    const { rows } = await db().query<{ id: string }>(
      `INSERT INTO realms (name) VALUES ('r') RETURNING id`
    );
    return rows[0].id;
  }

  async function user(realmId: string): Promise<string> {
    const { rows } = await db().query<{ id: string }>(
      `INSERT INTO users (realm_id) VALUES ($1) RETURNING id`,
      [realmId]
    );
    return rows[0].id;
  }

  /** Insert a credential; `id` given only where two share a `created_at`. */
  async function credential(
    realmId: string,
    userId: string,
    providerType: string,
    externalSub: string,
    createdAt: number,
    options: { readonly id?: string; readonly data?: Record<string, unknown> } = {}
  ): Promise<string> {
    const { rows } = await db().query<{ id: string }>(
      `INSERT INTO user_credentials
         (id, user_id, realm_id, provider_type, external_sub, credential_data, created_at, updated_at)
       VALUES (coalesce($1::uuid, uuidv7()), $2, $3, $4, $5, $6::jsonb, $7, $7) RETURNING id`,
      [
        options.id ?? null,
        userId,
        realmId,
        providerType,
        externalSub,
        JSON.stringify(options.data ?? {}),
        createdAt,
      ]
    );
    return rows[0].id;
  }

  /**
   * A new account as every account-creation path writes it: the user and its
   * first credential in one transaction, which gives both the same
   * `created_at`; the credential names no `is_primary`, as a release before
   * 0068 writes it.
   */
  async function account(
    realmId: string,
    providerType: string,
    externalSub: string
  ): Promise<{ userId: string; credentialId: string }> {
    const client = await db().connect();
    try {
      await client.query('BEGIN');
      const userId = (
        await client.query<{ id: string }>(
          `INSERT INTO users (realm_id) VALUES ($1) RETURNING id`,
          [realmId]
        )
      ).rows[0].id;
      const credentialId = (
        await client.query<{ id: string }>(
          `INSERT INTO user_credentials (user_id, realm_id, provider_type, external_sub)
           VALUES ($1, $2, $3, $4) RETURNING id`,
          [userId, realmId, providerType, externalSub]
        )
      ).rows[0].id;
      await client.query('COMMIT');
      return { userId, credentialId };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  /** A user written long before anything this test writes next. */
  async function oldUser(realmId: string): Promise<string> {
    const { rows } = await db().query<{ id: string }>(
      `INSERT INTO users (realm_id, created_at, updated_at) VALUES ($1, 1000, 1000) RETURNING id`,
      [realmId]
    );
    return rows[0].id;
  }

  /** Each user's primary credentials. */
  async function primaries(): Promise<Map<string, string[]>> {
    const { rows } = await db().query<{ user_id: string; id: string }>(
      `SELECT user_id, id FROM user_credentials WHERE is_primary ORDER BY user_id, id`
    );
    const byUser = new Map<string, string[]>();
    for (const row of rows) byUser.set(row.user_id, [...(byUser.get(row.user_id) ?? []), row.id]);
    return byUser;
  }

  it('marks exactly one primary credential per user, the oldest one, never an authenticator app', async () => {
    const realmId = await realm();
    // A password account that later bound a passkey; its authenticator app
    // claims an earlier time (a JS clock against the database's rounded one).
    const password = await user(realmId);
    await credential(realmId, password, 'totp', password, 900);
    const passwordFirst = await credential(realmId, password, 'password', 'a@example.com', 1_000);
    await credential(realmId, password, 'webauthn', 'cred-a', 2_000, { data: PASSKEY_DATA });
    // A passkey-only account with a second passkey.
    const passkey = await user(realmId);
    const passkeyFirst = await credential(realmId, passkey, 'webauthn', 'cred-b', 1_000, {
      data: PASSKEY_DATA,
    });
    await credential(realmId, passkey, 'webauthn', 'cred-c', 3_000, { data: PASSKEY_DATA });
    // An upstream account that later set a password.
    const upstream = await user(realmId);
    const upstreamFirst = await credential(realmId, upstream, 'oidc_corp', 'sub-1', 1_000, {
      data: { kind: 'upstream', iss: 'https://idp.example.com', verified: true },
    });
    await credential(realmId, upstream, 'password', 'u@example.com', 5_000);
    // Two credentials written in the same second: the lower id is the older.
    const tied = await user(realmId);
    const tiedFirst = await credential(realmId, tied, 'password', 't@example.com', 1_000, {
      id: '00000000-0000-7000-8000-000000000001',
    });
    await credential(realmId, tied, 'wallet', 'did:example:t', 1_000, {
      id: '00000000-0000-7000-8000-000000000002',
    });
    // An account with only an authenticator app, and one with no credential.
    const totpOnly = await user(realmId);
    await credential(realmId, totpOnly, 'totp', totpOnly, 1_000);
    const bare = await user(realmId);

    await migrate();

    const marked = await primaries();
    expect(marked.get(password)).toEqual([passwordFirst]);
    expect(marked.get(passkey)).toEqual([passkeyFirst]);
    expect(marked.get(upstream)).toEqual([upstreamFirst]);
    expect(marked.get(tied)).toEqual([tiedFirst]);
    expect(marked.has(totpOnly)).toBe(false);
    expect(marked.has(bare)).toBe(false);

    // Every user with a credential that is no authenticator app has exactly
    // one primary, and it is that user's oldest such credential.
    const { rows } = await db().query<{ user_id: string; oldest: string; primary_ids: string[] }>(
      `SELECT u.id AS user_id,
              (SELECT c.id FROM user_credentials c
                WHERE c.user_id = u.id AND c.provider_type <> 'totp'
                ORDER BY c.created_at, c.id LIMIT 1)::text AS oldest,
              ARRAY(SELECT c.id::text FROM user_credentials c
                     WHERE c.user_id = u.id AND c.is_primary) AS primary_ids
         FROM users u`
    );
    for (const row of rows) {
      expect(row.primary_ids).toEqual(row.oldest === null ? [] : [row.oldest]);
    }
  });

  it("leaves every credential's data as it was", async () => {
    const realmId = await realm();
    const owner = await user(realmId);
    await credential(realmId, owner, 'webauthn', 'cred-a', 1_000, { data: PASSKEY_DATA });
    const password = await user(realmId);
    await credential(realmId, password, 'password', 'p@example.com', 1_000, {
      data: { password_hash: 'h', email_verified: false },
    });

    await migrate();

    // A passkey with no user_verified was registered by a release whose
    // registration required the flag: the rule reads it as checked.
    const { rows } = await db().query<{ provider_type: string; data: Record<string, unknown> }>(
      `SELECT provider_type, credential_data AS data FROM user_credentials ORDER BY provider_type`
    );
    expect(rows).toEqual([
      { provider_type: 'password', data: { password_hash: 'h', email_verified: false } },
      { provider_type: 'webauthn', data: PASSKEY_DATA },
    ]);
  });

  describe('after the migration', () => {
    it('marks the credential written with the account, whatever the writer passed', async () => {
      await migrate();
      const realmId = await realm();
      // A release before 0068 names no column.
      const { userId: owner, credentialId: first } = await account(
        realmId,
        'password',
        'n@example.com'
      );
      const later = await credential(realmId, owner, 'webauthn', 'cred-n', 2_000);
      expect((await primaries()).get(owner)).toEqual([first]);
      expect(later).not.toBe(first);
    });

    it('marks no credential written later to an account that has none, and refuses one that claims the mark', async () => {
      await migrate();
      const realmId = await realm();
      const owner = await oldUser(realmId);
      await credential(realmId, owner, 'webauthn', 'cred-late', 2_000);
      expect((await primaries()).has(owner)).toBe(false);

      const other = await oldUser(realmId);
      await expect(
        db().query(
          `INSERT INTO user_credentials (user_id, realm_id, provider_type, external_sub, is_primary)
           VALUES ($1, $2, 'webauthn', 'cred-claim', true)`,
          [other, realmId]
        )
      ).rejects.toMatchObject({ code: '23514', constraint: 'user_credentials_primary_first' });
    });

    it('marks no authenticator app, and refuses one that claims the mark', async () => {
      await migrate();
      const realmId = await realm();
      const owner = await user(realmId);
      await credential(realmId, owner, 'totp', owner, 1_000);
      expect((await primaries()).has(owner)).toBe(false);
      const other = await user(realmId);
      await expect(
        db().query(
          `INSERT INTO user_credentials (user_id, realm_id, provider_type, external_sub, is_primary)
           VALUES ($1::uuid, $2, 'totp', $1::text, true)`,
          [other, realmId]
        )
      ).rejects.toMatchObject({ code: '23514', constraint: 'user_credentials_primary_first' });
    });

    it('refuses a later credential that claims the mark', async () => {
      await migrate();
      const realmId = await realm();
      const { userId: owner } = await account(realmId, 'password', 'l@example.com');
      await expect(
        db().query(
          `INSERT INTO user_credentials (user_id, realm_id, provider_type, external_sub, is_primary)
           VALUES ($1, $2, 'webauthn', 'cred-l', true)`,
          [owner, realmId]
        )
      ).rejects.toMatchObject({ code: '23514', constraint: 'user_credentials_primary_first' });
    });

    it('never moves the mark', async () => {
      await migrate();
      const realmId = await realm();
      const { userId: owner, credentialId: first } = await account(
        realmId,
        'password',
        'm@example.com'
      );
      const later = await credential(realmId, owner, 'webauthn', 'cred-m', 2_000);
      const stranger = await user(realmId);

      await expect(
        db().query(`UPDATE user_credentials SET is_primary = false WHERE id = $1`, [first])
      ).rejects.toMatchObject({ code: '23514', constraint: 'user_credentials_primary_permanent' });
      await expect(
        db().query(`UPDATE user_credentials SET is_primary = true WHERE id = $1`, [later])
      ).rejects.toMatchObject({ code: '23514', constraint: 'user_credentials_primary_permanent' });
      await expect(
        db().query(`UPDATE user_credentials SET user_id = $2 WHERE id = $1`, [first, stranger])
      ).rejects.toMatchObject({ code: '23514', constraint: 'user_credentials_primary_permanent' });

      // Any other change of the primary credential goes through.
      await db().query(
        `UPDATE user_credentials SET credential_data = '{"email_verified": true}', updated_at = 2
          WHERE id = $1`,
        [first]
      );
      expect((await primaries()).get(owner)).toEqual([first]);
    });

    it('leaves an account with no primary credential once it is deleted', async () => {
      await migrate();
      const realmId = await realm();
      const { userId: owner, credentialId: first } = await account(realmId, 'webauthn', 'cred-d1');
      const second = await credential(realmId, owner, 'webauthn', 'cred-d2', 2_000);
      expect((await primaries()).get(owner)).toEqual([first]);
      await db().query(`DELETE FROM user_credentials WHERE id = $1`, [first]);
      await credential(realmId, owner, 'webauthn', 'cred-d3', 3_000);
      expect((await primaries()).has(owner)).toBe(false);

      // Nor once every credential is gone: the next one is written later.
      await db().query(`DELETE FROM user_credentials WHERE user_id = $1`, [owner]);
      await credential(realmId, owner, 'webauthn', 'cred-d4', 4_000);
      expect((await primaries()).has(owner)).toBe(false);
      expect(second).not.toBe(first);
    });
  });
});
