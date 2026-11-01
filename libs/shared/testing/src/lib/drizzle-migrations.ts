import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { drizzle } from 'drizzle-orm/node-postgres';
import { migrate } from 'drizzle-orm/node-postgres/migrator';
import { Pool } from 'pg';

/**
 * Applying QAuth's REAL generated migrations to a throwaway database
 * (issues #167, #240).
 *
 * Lives here, not in `libs/infra/db`, because two projects now need it and only
 * one of them may import that library: `apps/auth-server` is `scope:app` and the
 * workspace's module boundaries forbid a direct dependency on `scope:infra`. A
 * second copy of the migrator inside the app's test support would be the exact
 * drift this helper exists to prevent — the whole value of these suites is that
 * they run against the DDL the migrations actually produce, so both callers must
 * apply it the same way.
 *
 * Deliberately NOT a schema builder. Nothing here knows a table name; it runs
 * `drizzle-kit`'s output verbatim, journal and all, so a migration that is
 * broken in production is broken here too.
 */

/**
 * Absolute path to the generated Drizzle migrations folder.
 *
 * Resolved from `process.cwd()` because every integration entry point — the
 * `test-integration` targets and `pnpm test:integration` — runs vitest from the
 * workspace root, and the libraries' CommonJS typecheck rules out
 * `import.meta.url`.
 */
export const QAUTH_MIGRATIONS_FOLDER = path.resolve(process.cwd(), 'libs/infra/db/drizzle');

/**
 * Apply every generated migration to a database, then disconnect.
 *
 * Uses its own short-lived pool so the caller's application pool (or the
 * application itself, which may not have started yet) is untouched.
 *
 * @param connectionString - a `postgresql://` URL, typically a testcontainer's.
 * @param migrationsFolder - defaults to {@link QAUTH_MIGRATIONS_FOLDER}.
 */
export async function applyQauthMigrations(
  connectionString: string,
  migrationsFolder: string = QAUTH_MIGRATIONS_FOLDER
): Promise<void> {
  const pool = new Pool({ connectionString, max: 1 });
  try {
    await migrate(drizzle(pool), { migrationsFolder });
  } finally {
    await pool.end();
  }
}

/** One entry of drizzle-kit's journal, `meta/_journal.json`. */
interface JournalEntry {
  readonly idx: number;
  readonly tag: string;
  readonly when: number;
}

function readJournal(migrationsFolder: string): { entries: JournalEntry[] } {
  return JSON.parse(readFileSync(path.join(migrationsFolder, 'meta', '_journal.json'), 'utf8'));
}

/**
 * The tags of the generated migrations, oldest first, as the journal lists
 * them (`0035_event_deliveries`).
 */
export function qauthMigrationTags(migrationsFolder: string = QAUTH_MIGRATIONS_FOLDER): string[] {
  return readJournal(migrationsFolder).entries.map((entry) => entry.tag);
}

/**
 * A temporary copy of the migrations folder holding only its first `count`
 * migrations (issue #474). Applied with {@link applyQauthMigrations}, it
 * leaves a database behind the code by the rest, as the deployment of an
 * older release did. The caller removes the folder.
 */
export function qauthMigrationsFolderWithFirst(
  count: number,
  migrationsFolder: string = QAUTH_MIGRATIONS_FOLDER
): string {
  const journal = readJournal(migrationsFolder);
  const entries = journal.entries.slice(0, count);
  const folder = mkdtempSync(path.join(tmpdir(), 'qauth-migrations-'));
  mkdirSync(path.join(folder, 'meta'));
  writeFileSync(
    path.join(folder, 'meta', '_journal.json'),
    JSON.stringify({ ...journal, entries }, null, 2)
  );
  for (const entry of entries) {
    copyFileSync(
      path.join(migrationsFolder, `${entry.tag}.sql`),
      path.join(folder, `${entry.tag}.sql`)
    );
  }
  return folder;
}

/**
 * Add a migration to the end of a migrations folder copy (issue #474),
 * generated one second after the last one: a newer release's migration, or
 * one that fails.
 */
export function appendQauthMigration(migrationsFolder: string, tag: string, sql: string): void {
  const journalPath = path.join(migrationsFolder, 'meta', '_journal.json');
  const journal = JSON.parse(readFileSync(journalPath, 'utf8')) as {
    entries: (JournalEntry & Record<string, unknown>)[];
  };
  const last = journal.entries.at(-1);
  if (last === undefined) throw new Error(`${journalPath} has no migration to follow`);
  journal.entries.push({ ...last, idx: last.idx + 1, tag, when: last.when + 1000 });
  writeFileSync(journalPath, JSON.stringify(journal, null, 2));
  writeFileSync(path.join(migrationsFolder, `${tag}.sql`), sql);
}

/**
 * Every domain table an integration suite truncates between tests.
 *
 * Order is irrelevant (`CASCADE`), but completeness is not: a table missing from
 * this list leaks rows into the next test, and the failure surfaces as an
 * unrelated uniqueness violation somewhere far away.
 *
 * `admin_audit_log` and `admin_audit_log_checkpoints` are left out on purpose:
 * a trigger refuses `TRUNCATE` on them (migration 0026), and no foreign key
 * leads a `CASCADE` there. A suite that writes them uses a realm id of its own.
 */
export const QAUTH_DOMAIN_TABLES: readonly string[] = Object.freeze([
  'admin_approvals',
  'admin_grants',
  'admin_roles',
  'api_keys',
  'audit_logs',
  'event_chain_anchors',
  'event_deliveries',
  'event_delivery_positions',
  'events',
  'oid4vp_request_states',
  'realm_auth_method_plugins',
  'realm_public_keys',
  'realm_keys',
  'realm_secrets',
  'ssf_stream_subjects',
  'ssf_streams',
  'oauth_consents',
  'refresh_tokens',
  'authorization_codes',
  'email_verification_tokens',
  'oauth_clients',
  'users',
  'realm_hosts',
  'realms',
]);

/** The `TRUNCATE` statement that resets a migrated database between tests. */
export function truncateDomainTablesStatement(
  tables: readonly string[] = QAUTH_DOMAIN_TABLES
): string {
  return `TRUNCATE TABLE ${tables.map((table) => `"${table}"`).join(', ')} RESTART IDENTITY CASCADE`;
}
