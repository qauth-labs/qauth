/**
 * Seed-then-migrate test for migration 0047: the domain an admin verified for
 * a client (ADR-019 Decision 6, #593).
 *
 * The migration is forward-only: it adds a nullable column and a CHECK, and
 * rewrites nothing. A client created before it comes out of it unchanged and
 * with no verified domain, and the previous release, which does not know the
 * column, keeps creating and updating clients on the new schema during a
 * rolling upgrade. From then on the database holds a verified domain only in
 * the form the screens show, the same form `isVerifiedDomain` accepts.
 *
 * Requires Docker; self-skips without it. The schema is rebuilt from scratch
 * and upgraded through 0046, then 0047, so a later migration cannot change
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
import { isVerifiedDomain } from '@qauth-labs/shared-validation';
import { Pool } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

const MIGRATION_IDX = 47;

/** Every column of `oauth_clients` but `verified_domain`, as one row reads them. */
const ROW_WITHOUT_VERIFIED_DOMAIN = `to_jsonb(oauth_clients) - 'verified_domain'`;

describe('migration 0047 — oauth_clients.verified_domain (seed-then-migrate)', () => {
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

  /** Apply every migration through 0047. */
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

  /** A client as the previous release writes one: it does not name the new column. */
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

  async function setVerifiedDomain(id: string, value: string | null): Promise<void> {
    await db().query(`UPDATE oauth_clients SET verified_domain = $2 WHERE id = $1`, [id, value]);
  }

  it('keeps every existing client unchanged, with no verified domain', async () => {
    const realmId = await seedRealm();
    const id = await insertClientAsPreviousRelease(realmId, 'notes');
    const {
      rows: [beforeRow],
    } = await db().query<{ row: unknown }>(
      `SELECT ${ROW_WITHOUT_VERIFIED_DOMAIN} AS row FROM oauth_clients WHERE id = $1`,
      [id]
    );

    await migrate();

    const {
      rows: [afterRow],
    } = await db().query<{ row: unknown; verified_domain: string | null }>(
      `SELECT ${ROW_WITHOUT_VERIFIED_DOMAIN} AS row, verified_domain FROM oauth_clients WHERE id = $1`,
      [id]
    );
    expect(afterRow.row).toEqual(beforeRow.row);
    expect(afterRow.verified_domain).toBeNull();
  });

  it('adds a nullable column with no default, so the previous release keeps writing clients', async () => {
    await migrate();
    const {
      rows: [column],
    } = await db().query<{
      is_nullable: string;
      column_default: string | null;
      character_maximum_length: number;
    }>(
      `SELECT is_nullable, column_default, character_maximum_length
         FROM information_schema.columns
        WHERE table_name = 'oauth_clients' AND column_name = 'verified_domain'`
    );
    expect(column).toEqual({
      is_nullable: 'YES',
      column_default: null,
      character_maximum_length: 253,
    });

    // The rolling leg: old code inserts and updates without the column.
    const realmId = await seedRealm();
    const id = await insertClientAsPreviousRelease(realmId, 'notes');
    await setVerifiedDomain(id, 'notes.example.com');
    await db().query(`UPDATE oauth_clients SET name = 'Notes 2' WHERE id = $1`, [id]);
    const {
      rows: [row],
    } = await db().query<{ verified_domain: string }>(
      `SELECT verified_domain FROM oauth_clients WHERE id = $1`,
      [id]
    );
    expect(row.verified_domain).toBe('notes.example.com');
  });

  it('holds a verified domain only in the form the screens show, as isVerifiedDomain reads it', async () => {
    await migrate();
    const realmId = await seedRealm();
    const id = await insertClientAsPreviousRelease(realmId, 'notes');

    const samples = [
      'notes.example.com',
      'xn--bcher-kva.example',
      'a.b.c.example',
      'a-b.example',
      'Notes.example.com',
      'bücher.example',
      'example.com.',
      '.example.com',
      'example..com',
      'localhost',
      '192.0.2.1',
      'example.com:443',
      'notes.example.com/',
      '-notes.example.com',
      'notes-.example.com',
      'notes_app.example.com',
      'notes.example.123',
      `${'a'.repeat(64)}.example`,
      ' notes.example.com',
    ];
    for (const value of samples) {
      const stored = await setVerifiedDomain(id, value).then(
        () => true,
        (error: { code?: string; constraint?: string }) => {
          expect(error.code, value).toBe('23514');
          expect(error.constraint, value).toBe('oauth_clients_verified_domain_form');
          return false;
        }
      );
      expect(stored, value).toBe(isVerifiedDomain(value));
    }

    await setVerifiedDomain(id, null);
  });
});
