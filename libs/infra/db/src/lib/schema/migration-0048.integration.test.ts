/**
 * Seed-then-migrate test for migration 0048: the operator-set first-party
 * client profile (ADR-017 Decision 2, #631).
 *
 * The migration is forward-only: it adds an enum type, three nullable columns
 * and four CHECKs, and rewrites nothing. A client created before it comes out
 * of it unchanged and not first party, and the previous release, which does
 * not know the columns, keeps creating and updating clients on the new schema
 * during a rolling upgrade. From then on each CHECK refuses its bad row, so no
 * write path, a hand-written UPDATE included, can mark a dynamic, CIMD, agent
 * or developer-owned client first party.
 *
 * Requires Docker; self-skips without it. The schema is rebuilt from scratch
 * and upgraded through 0047, then 0048, so a later migration cannot change
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

const MIGRATION_IDX = 48;

/** Every column of `oauth_clients` but the three new ones, as one row reads them. */
const ROW_WITHOUT_FIRST_PARTY = `to_jsonb(oauth_clients) - 'first_party_profile' - 'first_party_policy' - 'first_party_reason'`;

const POLICY = JSON.stringify({
  flows: ['login'],
  email_code_after_password: false,
  pkce_required: true,
});

/** A `pg` error as a refused statement rejects with it. */
interface PgError {
  code?: string;
  constraint?: string;
}

describe('migration 0048 — oauth_clients first-party profile (seed-then-migrate)', () => {
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

  /** Apply every migration through 0048. */
  async function migrate(): Promise<void> {
    if (!container) throw new Error('no container');
    await applyQauthMigrations(container.connectionString, through);
  }

  async function seedRealm(): Promise<string> {
    const {
      rows: [realm],
    } = await db().query<{ id: string }>(`INSERT INTO realms (name) VALUES ('r') RETURNING id`);
    return realm.id;
  }

  async function seedUser(realmId: string): Promise<string> {
    const {
      rows: [user],
    } = await db().query<{ id: string }>(`INSERT INTO users (realm_id) VALUES ($1) RETURNING id`, [
      realmId,
    ]);
    return user.id;
  }

  /** A client as the previous release writes one: it does not name the new columns. */
  async function insertClientAsPreviousRelease(realmId: string, clientId: string): Promise<string> {
    const {
      rows: [client],
    } = await db().query<{ id: string }>(
      `INSERT INTO oauth_clients (realm_id, client_id, client_secret_hash, name, redirect_uris, provisioned_by_operator)
       VALUES ($1, $2, 'hash', 'Notes', '["https://notes.example.com/cb"]', true) RETURNING id`,
      [realmId, clientId]
    );
    return client.id;
  }

  /**
   * Insert a client with the given column values on top of an operator's
   * `private_key_jwt` client, which every CHECK accepts with any profile.
   */
  async function insertClient(
    realmId: string,
    clientId: string,
    columns: Record<string, unknown>
  ): Promise<void> {
    const row: Record<string, unknown> = {
      realm_id: realmId,
      client_id: clientId,
      client_secret_hash: 'hash',
      name: 'Notes',
      redirect_uris: '["https://notes.example.com/cb"]',
      token_endpoint_auth_method: 'private_key_jwt',
      grant_types: '["authorization_code","refresh_token"]',
      provisioned_by_operator: true,
      ...columns,
    };
    const names = Object.keys(row);
    await db().query(
      `INSERT INTO oauth_clients (${names.join(', ')}) VALUES (${names.map((_, i) => `$${i + 1}`).join(', ')})`,
      Object.values(row)
    );
  }

  /** Expect `write` to be refused by the named CHECK. */
  async function expectRefusedBy(write: Promise<unknown>, constraint: string, label: string) {
    const error = await write.then(
      () => undefined,
      (caught: PgError) => caught
    );
    expect(error, label).toBeDefined();
    expect(error?.code, label).toBe('23514');
    expect(error?.constraint, label).toBe(constraint);
  }

  it('keeps every existing client unchanged, and not first party', async () => {
    const realmId = await seedRealm();
    const id = await insertClientAsPreviousRelease(realmId, 'notes');
    const {
      rows: [beforeRow],
    } = await db().query<{ row: unknown }>(
      `SELECT ${ROW_WITHOUT_FIRST_PARTY} AS row FROM oauth_clients WHERE id = $1`,
      [id]
    );

    await migrate();

    const {
      rows: [afterRow],
    } = await db().query<{
      row: unknown;
      first_party_profile: string | null;
      first_party_policy: unknown;
      first_party_reason: string | null;
    }>(
      `SELECT ${ROW_WITHOUT_FIRST_PARTY} AS row, first_party_profile, first_party_policy, first_party_reason
         FROM oauth_clients WHERE id = $1`,
      [id]
    );
    expect(afterRow.row).toEqual(beforeRow.row);
    expect(afterRow.first_party_profile).toBeNull();
    expect(afterRow.first_party_policy).toBeNull();
    expect(afterRow.first_party_reason).toBeNull();
  });

  it('adds nullable columns with no default, so the previous release keeps writing clients', async () => {
    await migrate();
    const { rows: columns } = await db().query<{
      column_name: string;
      is_nullable: string;
      column_default: string | null;
    }>(
      `SELECT column_name, is_nullable, column_default
         FROM information_schema.columns
        WHERE table_name = 'oauth_clients' AND column_name LIKE 'first_party_%'
        ORDER BY column_name`
    );
    expect(columns).toEqual([
      { column_name: 'first_party_policy', is_nullable: 'YES', column_default: null },
      { column_name: 'first_party_profile', is_nullable: 'YES', column_default: null },
      { column_name: 'first_party_reason', is_nullable: 'YES', column_default: null },
    ]);

    // The rolling leg: old code inserts and updates without the columns,
    // including a dynamic registration, which every CHECK lets through.
    const realmId = await seedRealm();
    const id = await insertClientAsPreviousRelease(realmId, 'notes');
    await db().query(`UPDATE oauth_clients SET name = 'Notes 2' WHERE id = $1`, [id]);
    await db().query(
      `INSERT INTO oauth_clients (realm_id, client_id, client_secret_hash, name, redirect_uris, dynamic_registered_at, metadata)
       VALUES ($1, 'dcr', 'hash', 'DCR', '["https://dcr.example.com/cb"]', 1, '{"registrationType":"dynamic"}')`,
      [realmId]
    );
    const { rows } = await db().query<{ client_id: string; first_party_profile: null }>(
      `SELECT client_id, first_party_profile FROM oauth_clients ORDER BY client_id`
    );
    expect(rows).toEqual([
      { client_id: 'dcr', first_party_profile: null },
      { client_id: 'notes', first_party_profile: null },
    ]);
  });

  it('accepts the two shapes an operator writes: a web front-end and a native backend', async () => {
    await migrate();
    const realmId = await seedRealm();

    await insertClient(realmId, 'portal', {
      first_party_profile: 'web_redirect',
      first_party_reason: 'The developer portal this deployment runs',
    });
    await insertClient(realmId, 'notes-backend', {
      first_party_profile: 'native_backend',
      first_party_policy: POLICY,
      first_party_reason: 'Our own notes app',
    });

    const { rows } = await db().query<{ client_id: string; first_party_profile: string }>(
      `SELECT client_id, first_party_profile FROM oauth_clients ORDER BY client_id`
    );
    expect(rows).toEqual([
      { client_id: 'notes-backend', first_party_profile: 'native_backend' },
      { client_id: 'portal', first_party_profile: 'web_redirect' },
    ]);
  });

  it('refuses a profile on a DCR, CIMD, agent or developer-owned client (oauth_clients_first_party_operator_only)', async () => {
    await migrate();
    const realmId = await seedRealm();
    const developerId = await seedUser(realmId);

    const cases: Array<[string, Record<string, unknown>]> = [
      ['dynamic registration time', { dynamic_registered_at: 1_790_000_000_000 }],
      ['dynamic registration marker', { metadata: '{"registrationType":"dynamic"}' }],
      ['CIMD client', { metadata: '{"registrationType":"cimd"}' }],
      ['agent', { is_agent: true }],
      ['developer-owned client', { developer_id: developerId }],
    ];
    for (const [label, columns] of cases) {
      for (const profile of [
        { first_party_profile: 'web_redirect' },
        { first_party_profile: 'native_backend', first_party_policy: POLICY },
      ]) {
        await expectRefusedBy(
          insertClient(realmId, `c-${label}`, { ...columns, ...profile }),
          'oauth_clients_first_party_operator_only',
          `${label}, ${profile.first_party_profile}`
        );
      }
      // Without a profile the same row is an ordinary client.
      await insertClient(realmId, `c-${label}`, columns);
    }

    // And no UPDATE flags such a row afterwards, nor makes a flagged row one.
    const { rows: plain } = await db().query<{ id: string }>(
      `SELECT id FROM oauth_clients ORDER BY client_id`
    );
    for (const { id } of plain) {
      await expectRefusedBy(
        db().query(`UPDATE oauth_clients SET first_party_profile = 'web_redirect' WHERE id = $1`, [
          id,
        ]),
        'oauth_clients_first_party_operator_only',
        `update ${id}`
      );
    }
    await insertClient(realmId, 'portal', {
      first_party_profile: 'web_redirect',
      first_party_reason: 'The portal',
    });
    const updates: Array<[string, string, unknown[]]> = [
      ['give it a developer', 'developer_id = $1', [developerId]],
      ['make it an agent', 'is_agent = true', []],
      ['stamp a dynamic registration', 'dynamic_registered_at = 1', []],
      ['mark it CIMD', `metadata = '{"registrationType":"cimd"}'`, []],
    ];
    for (const [label, set, params] of updates) {
      await expectRefusedBy(
        db().query(`UPDATE oauth_clients SET ${set} WHERE client_id = 'portal'`, params),
        'oauth_clients_first_party_operator_only',
        label
      );
    }
  });

  it('refuses a profile on a client that does not authenticate with private_key_jwt (oauth_clients_first_party_private_key_jwt)', async () => {
    await migrate();
    const realmId = await seedRealm();

    for (const method of ['client_secret_basic', 'client_secret_post', 'none']) {
      for (const profile of [
        { first_party_profile: 'web_redirect' },
        { first_party_profile: 'native_backend', first_party_policy: POLICY },
      ]) {
        await expectRefusedBy(
          insertClient(realmId, `c-${method}`, { token_endpoint_auth_method: method, ...profile }),
          'oauth_clients_first_party_private_key_jwt',
          `${method}, ${profile.first_party_profile}`
        );
      }
    }

    await insertClient(realmId, 'portal', { first_party_profile: 'web_redirect' });
    await expectRefusedBy(
      db().query(
        `UPDATE oauth_clients SET token_endpoint_auth_method = 'client_secret_basic' WHERE client_id = 'portal'`
      ),
      'oauth_clients_first_party_private_key_jwt',
      'switching a flagged client to a secret'
    );
  });

  it('holds a policy exactly on native_backend (oauth_clients_first_party_policy_native)', async () => {
    await migrate();
    const realmId = await seedRealm();

    await expectRefusedBy(
      insertClient(realmId, 'native-no-policy', { first_party_profile: 'native_backend' }),
      'oauth_clients_first_party_policy_native',
      'native_backend without a policy'
    );
    await expectRefusedBy(
      insertClient(realmId, 'web-policy', {
        first_party_profile: 'web_redirect',
        first_party_policy: POLICY,
      }),
      'oauth_clients_first_party_policy_native',
      'web_redirect with a policy'
    );
    await expectRefusedBy(
      insertClient(realmId, 'plain-policy', { first_party_policy: POLICY }),
      'oauth_clients_first_party_policy_native',
      'a policy with no profile'
    );

    await insertClient(realmId, 'native', {
      first_party_profile: 'native_backend',
      first_party_policy: POLICY,
    });
    await expectRefusedBy(
      db().query(`UPDATE oauth_clients SET first_party_policy = NULL WHERE client_id = 'native'`),
      'oauth_clients_first_party_policy_native',
      'dropping the policy and keeping the profile'
    );
    await expectRefusedBy(
      db().query(`UPDATE oauth_clients SET first_party_profile = NULL WHERE client_id = 'native'`),
      'oauth_clients_first_party_policy_native',
      'dropping the profile and keeping the policy'
    );
    // Removing both together is how an operator removes the profile.
    await db().query(
      `UPDATE oauth_clients SET first_party_profile = NULL, first_party_policy = NULL WHERE client_id = 'native'`
    );
  });

  it('holds native_backend to the authorization_code grant (oauth_clients_first_party_native_authorization_code)', async () => {
    await migrate();
    const realmId = await seedRealm();

    for (const grants of ['["refresh_token"]', '["client_credentials"]', '[]']) {
      await expectRefusedBy(
        insertClient(realmId, `native-${grants}`, {
          first_party_profile: 'native_backend',
          first_party_policy: POLICY,
          grant_types: grants,
        }),
        'oauth_clients_first_party_native_authorization_code',
        grants
      );
    }
    // A web front-end is not held to it by the database.
    await insertClient(realmId, 'portal', {
      first_party_profile: 'web_redirect',
      grant_types: '["refresh_token"]',
    });

    await insertClient(realmId, 'native', {
      first_party_profile: 'native_backend',
      first_party_policy: POLICY,
    });
    await expectRefusedBy(
      db().query(
        `UPDATE oauth_clients SET grant_types = '["refresh_token"]' WHERE client_id = 'native'`
      ),
      'oauth_clients_first_party_native_authorization_code',
      'dropping the grant from a flagged client'
    );
  });
});
