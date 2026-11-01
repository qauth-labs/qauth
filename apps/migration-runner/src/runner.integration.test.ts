/**
 * The BUILT migration runner against a real Postgres (issue #474).
 *
 * Each case spawns `dist/apps/migration-runner/main.js`, the file the image
 * runs, so the exit codes, the output and the bundle itself are what is
 * tested. The `test-integration` target builds it first.
 *
 * Requires Docker; self-skips without it locally and fails on CI. One
 * container; each case gets a database of its own (`CREATE DATABASE`),
 * which also scopes the advisory lock: Postgres keys it per database.
 */
import { spawn } from 'node:child_process';
import { existsSync, readFileSync, rmSync } from 'node:fs';
import path from 'node:path';

import { MIGRATION_LOCK_NAME } from '@qauth-labs/infra-db/migrations';
import {
  appendQauthMigration,
  applyQauthMigrations,
  createPostgresDatabase,
  QAUTH_MIGRATIONS_FOLDER,
  qauthMigrationsFolderWithFirst,
  qauthMigrationTags,
  requireDockerOrSkip,
  type StartedPostgres,
  startPostgresContainer,
} from '@qauth-labs/shared-testing';
import { Client } from 'pg';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';

const RUNNER = path.resolve(process.cwd(), 'dist/apps/migration-runner/main.js');
const TAGS = qauthMigrationTags();
const KNOWN = TAGS.length;
const LAST = TAGS[KNOWN - 1] as string;

interface RunnerResult {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

interface StartedRunner {
  /** What it printed so far. */
  output(): string;
  readonly done: Promise<RunnerResult>;
}

/**
 * Start the built runner with nothing but PATH, DATABASE_URL and `env` in its
 * environment.
 */
function startRunner(
  databaseUrl: string,
  args: readonly string[] = [],
  env: Readonly<Record<string, string>> = {}
): StartedRunner {
  const child = spawn(process.execPath, [RUNNER, ...args], {
    env: { PATH: process.env['PATH'] ?? '', DATABASE_URL: databaseUrl, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (chunk: Buffer) => (stdout += chunk.toString('utf8')));
  child.stderr.on('data', (chunk: Buffer) => (stderr += chunk.toString('utf8')));
  const done = new Promise<RunnerResult>((resolve, reject) => {
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
  return { output: () => stdout, done };
}

function runRunner(
  databaseUrl: string,
  args: readonly string[] = [],
  env: Readonly<Record<string, string>> = {}
): Promise<RunnerResult> {
  return startRunner(databaseUrl, args, env).done;
}

async function until(condition: () => Promise<boolean> | boolean, what: string): Promise<void> {
  const deadline = Date.now() + 30_000;
  while (!(await condition())) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}

describe('migration runner (built program, testcontainers Postgres)', () => {
  let container: StartedPostgres | undefined;
  let dockerUp = false;
  let databases = 0;
  const folders: string[] = [];

  beforeAll(async () => {
    if (!existsSync(RUNNER)) {
      throw new Error(`${RUNNER} is missing: run \`pnpm nx run migration-runner:build\` first`);
    }
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    container = await startPostgresContainer();
  }, 180_000);

  afterEach(() => {
    for (const folder of folders.splice(0)) rmSync(folder, { recursive: true, force: true });
  });

  afterAll(async () => {
    await container?.stop();
  });

  /** A new, empty database on the container, by URL. */
  async function freshDatabase(ctx: { skip: () => void }): Promise<string> {
    if (!dockerUp || !container) {
      ctx.skip();
      throw new Error('unreachable');
    }
    return createPostgresDatabase(container.connectionString, `runner_${++databases}`);
  }

  /** Run one query on a database and disconnect. */
  async function query<R = Record<string, unknown>>(
    databaseUrl: string,
    text: string,
    values: unknown[] = []
  ): Promise<R[]> {
    const client = new Client({ connectionString: databaseUrl });
    await client.connect();
    try {
      return (await client.query(text, values)).rows as R[];
    } finally {
      await client.end();
    }
  }

  async function appliedRows(databaseUrl: string) {
    return query<{ hash: string; created_at: string }>(
      databaseUrl,
      'SELECT hash, created_at FROM drizzle.__drizzle_migrations ORDER BY id'
    );
  }

  it('applies every migration to an empty database, each with its duration, and a second run is a no-op', async (ctx) => {
    const url = await freshDatabase(ctx);

    const first = await runRunner(url);
    expect(first.stderr).toBe('');
    expect(first.code).toBe(0);
    const lines = first.stdout.trimEnd().split('\n');
    expect(lines[0]).toMatch(new RegExp(`^Applying ${KNOWN} migrations in one transaction: `));
    expect(lines.slice(1, -1)).toEqual(
      TAGS.map((tag) => expect.stringMatching(new RegExp(`^  ${tag} ran in \\d+ ms$`)))
    );
    expect(lines.at(-1)).toMatch(
      new RegExp(`^Applied ${KNOWN} migrations in \\d+ ms\\. The database is current\\.$`)
    );

    const journal = JSON.parse(
      readFileSync(path.join(QAUTH_MIGRATIONS_FOLDER, 'meta/_journal.json'), 'utf8')
    ) as { entries: { when: number }[] };
    const rows = await appliedRows(url);
    expect(rows.map((row) => Number(row.created_at))).toEqual(
      journal.entries.map((entry) => entry.when)
    );
    const [realms] = await query<{ present: boolean }>(
      url,
      "SELECT to_regclass('public.realms') IS NOT NULL AS present"
    );
    expect(realms?.present).toBe(true);

    const second = await runRunner(url);
    expect(second).toEqual({
      code: 0,
      stdout: `The database is current: all ${KNOWN} migrations are applied. Nothing to do.\n`,
      stderr: '',
    });
    expect(await appliedRows(url)).toEqual(rows);
  });

  it('lets two runners started together both exit 0, and applies each migration once', async (ctx) => {
    const url = await freshDatabase(ctx);

    // Hold the lock so both runners are waiting on it, then let them race.
    const holder = new Client({ connectionString: url });
    await holder.connect();
    let runners: StartedRunner[] = [];
    try {
      await holder.query('SELECT pg_advisory_lock(hashtextextended($1, 0))', [MIGRATION_LOCK_NAME]);
      runners = [startRunner(url), startRunner(url)];
      await until(
        () => runners.every((runner) => runner.output().includes('holds the migration lock')),
        'both runners to wait for the lock'
      );
    } finally {
      await holder.end();
    }
    const results = await Promise.all(runners.map((runner) => runner.done));

    for (const result of results) {
      expect(result.stderr).toBe('');
      expect(result.code).toBe(0);
      expect(result.stdout.split('\n')[0]).toBe(
        'Another migration runner holds the migration lock. Waiting for it to finish.'
      );
    }
    const applying = results.filter((result) => result.stdout.includes('Applying'));
    const idle = results.filter((result) => result.stdout.includes('Nothing to do.'));
    expect(applying).toHaveLength(1);
    expect(idle).toHaveLength(1);
    expect(applying[0]?.stdout).toContain(`Applied ${KNOWN} migrations in `);

    const rows = await appliedRows(url);
    expect(rows).toHaveLength(KNOWN);
    expect(new Set(rows.map((row) => row.hash)).size).toBe(KNOWN);
  });

  it('--check exits 1 on a database missing the last migration and 0 on a current one, changing nothing', async (ctx) => {
    const url = await freshDatabase(ctx);
    const behind = qauthMigrationsFolderWithFirst(KNOWN - 1);
    folders.push(behind);
    await applyQauthMigrations(url, behind);
    const before = await appliedRows(url);
    expect(before).toHaveLength(KNOWN - 1);

    const pending = await runRunner(url, ['--check']);
    expect(pending).toEqual({
      code: 1,
      stdout:
        `The database lacks 1 of ${KNOWN} migrations: ${LAST}. ` +
        'Run the migration runner without --check to apply them.\n',
      stderr: '',
    });
    expect(await appliedRows(url)).toEqual(before);

    const run = await runRunner(url);
    expect(run.code).toBe(0);
    expect(run.stdout.split('\n')[0]).toBe(`Applying 1 migration in one transaction: ${LAST}.`);

    const current = await runRunner(url, ['--check']);
    expect(current).toEqual({
      code: 0,
      stdout: `The database is current: all ${KNOWN} migrations are applied.\n`,
      stderr: '',
    });
  });

  it('--check on a database the runner never touched creates nothing', async (ctx) => {
    const url = await freshDatabase(ctx);

    const check = await runRunner(url, ['--check']);
    expect(check.code).toBe(1);
    expect(check.stdout).toMatch(
      new RegExp(`^The database lacks ${KNOWN} of ${KNOWN} migrations: `)
    );
    const [schema] = await query<{ present: boolean }>(
      url,
      "SELECT to_regnamespace('drizzle') IS NOT NULL AS present"
    );
    expect(schema?.present).toBe(false);
  });

  it('exits 1 naming the migration that failed, and rolls the whole run back', async (ctx) => {
    const url = await freshDatabase(ctx);
    // The first two real migrations, then one that collides with the first.
    const folder = qauthMigrationsFolderWithFirst(2);
    folders.push(folder);
    appendQauthMigration(folder, '9999_collides', 'CREATE TABLE "realms" ("id" integer);');

    const result = await runRunner(url, [`--migrations-folder=${folder}`]);
    expect(result.code).toBe(1);
    expect(result.stdout).toContain(`  ${TAGS[1]} ran in `);
    expect(result.stderr).toBe(
      'Migration 9999_collides failed: relation "realms" already exists (42P07)\n' +
        'The run rolled back: no migration of this run was applied.\n'
    );
    expect(await appliedRows(url)).toEqual([]);
    const [realms] = await query<{ present: boolean }>(
      url,
      "SELECT to_regclass('public.realms') IS NOT NULL AS present"
    );
    expect(realms?.present).toBe(false);
  });

  it('exits 0 on a database ahead of it, saying so', async (ctx) => {
    const url = await freshDatabase(ctx);
    const newer = qauthMigrationsFolderWithFirst(KNOWN);
    folders.push(newer);
    appendQauthMigration(newer, '9999_from_a_newer_release', 'SELECT 1;');
    await applyQauthMigrations(url, newer);

    const ahead =
      " The database also has 1 migration newer than this runner's, from a newer release; " +
      'nothing was done about them.';
    expect(await runRunner(url)).toEqual({
      code: 0,
      stdout: `The database is current: all ${KNOWN} migrations are applied. Nothing to do.${ahead}\n`,
      stderr: '',
    });
    expect(await runRunner(url, ['--check'])).toEqual({
      code: 0,
      stdout: `The database is current: all ${KNOWN} migrations are applied.${ahead}\n`,
      stderr: '',
    });
  });

  describe('the system client (#631, ADR-017 phase F0)', () => {
    const CALLBACK = 'https://portal.example.com/auth/callback';
    const JWKS = {
      keys: [{ kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' }],
    };
    const SYSTEM_CLIENT_ENV = {
      SYSTEM_CLIENT_REDIRECT_URI: CALLBACK,
      SYSTEM_CLIENT_JWKS: JSON.stringify(JWKS),
    };

    async function systemClient(url: string) {
      return query<{
        token_endpoint_auth_method: string;
        first_party_profile: string | null;
        first_party_policy: unknown;
        redirect_uris: string[];
        grant_types: string[];
        jwks: unknown;
        provisioned_by_operator: boolean;
      }>(
        url,
        `SELECT token_endpoint_auth_method, first_party_profile, first_party_policy, redirect_uris,
                grant_types, jwks, provisioned_by_operator
           FROM oauth_clients WHERE client_id = 'system'`
      );
    }

    it('skips a realm the auth server has not created yet, then provisions it, then changes nothing', async (ctx) => {
      const url = await freshDatabase(ctx);

      const early = await runRunner(url, [], SYSTEM_CLIENT_ENV);
      expect(early.code).toBe(0);
      expect(early.stderr).toContain('realm "master" does not exist yet');
      expect(await systemClient(url)).toEqual([]);

      // What the auth server's first boot does before the next run.
      await query(url, `INSERT INTO realms (name) VALUES ('master')`);

      const provisioned = await runRunner(url, [], SYSTEM_CLIENT_ENV);
      expect(provisioned.stderr).toBe('');
      expect(provisioned.code).toBe(0);
      expect(provisioned.stdout.trimEnd().split('\n').at(-1)).toBe(
        'Provisioned the system client "system" in realm "master": private_key_jwt, first-party profile web_redirect.'
      );
      expect(await systemClient(url)).toEqual([
        {
          token_endpoint_auth_method: 'private_key_jwt',
          first_party_profile: 'web_redirect',
          first_party_policy: null,
          redirect_uris: [CALLBACK],
          grant_types: ['authorization_code', 'refresh_token'],
          jwks: JWKS,
          provisioned_by_operator: true,
        },
      ]);
      const [{ count }] = await query<{ count: string }>(
        url,
        `SELECT count(*) FROM events WHERE type = 'urn:qauth:event:client.first_party_changed:v1-rc.0'`
      );
      expect(count).toBe('1');

      const again = await runRunner(url, [], SYSTEM_CLIENT_ENV);
      expect(again.code).toBe(0);
      expect(again.stdout.trimEnd().split('\n').at(-1)).toBe(
        'The system client "system" in realm "master" is already provisioned as configured.'
      );
    });

    it("exits 4, with the migrations applied, when SYSTEM_CLIENT_ID names a developer's client", async (ctx) => {
      const url = await freshDatabase(ctx);
      expect((await runRunner(url)).code).toBe(0);
      const [realm] = await query<{ id: string }>(
        url,
        `INSERT INTO realms (name) VALUES ('master') RETURNING id`
      );
      const [user] = await query<{ id: string }>(
        url,
        `INSERT INTO users (realm_id) VALUES ($1) RETURNING id`,
        [realm.id]
      );
      await query(
        url,
        `INSERT INTO oauth_clients (realm_id, client_id, client_secret_hash, name, redirect_uris, developer_id)
         VALUES ($1, 'mine', 'h', 'Mine', '["https://app.example.com/cb"]', $2)`,
        [realm.id, user.id]
      );

      const refused = await runRunner(url, [], { ...SYSTEM_CLIENT_ENV, SYSTEM_CLIENT_ID: 'mine' });

      expect(refused.code).toBe(4);
      expect(refused.stderr).toContain(`client "mine" in realm "master" is a developer's client`);
      const [row] = await query<{ first_party_profile: string | null; developer_id: string }>(
        url,
        `SELECT first_party_profile, developer_id FROM oauth_clients WHERE client_id = 'mine'`
      );
      expect(row).toEqual({ first_party_profile: null, developer_id: user.id });
    });

    it('exits 2 and touches nothing on a half-written configuration', async (ctx) => {
      const url = await freshDatabase(ctx);

      const result = await runRunner(url, [], { SYSTEM_CLIENT_REDIRECT_URI: CALLBACK });

      expect(result.code).toBe(2);
      expect(result.stdout).toBe('');
      expect(await query(url, `SELECT to_regclass('drizzle.__drizzle_migrations') AS t`)).toEqual([
        { t: null },
      ]);
    });
  });
});
