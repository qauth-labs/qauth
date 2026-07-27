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

/**
 * Every domain table an integration suite truncates between tests.
 *
 * Order is irrelevant (`CASCADE`), but completeness is not: a table missing from
 * this list leaks rows into the next test, and the failure surfaces as an
 * unrelated uniqueness violation somewhere far away.
 */
export const QAUTH_DOMAIN_TABLES: readonly string[] = Object.freeze([
  'api_keys',
  'audit_logs',
  'oid4vp_request_states',
  'oauth_consents',
  'refresh_tokens',
  'authorization_codes',
  'email_verification_tokens',
  'oauth_clients',
  'users',
  'realms',
]);

/** The `TRUNCATE` statement that resets a migrated database between tests. */
export function truncateDomainTablesStatement(
  tables: readonly string[] = QAUTH_DOMAIN_TABLES
): string {
  return `TRUNCATE TABLE ${tables.map((table) => `"${table}"`).join(', ')} RESTART IDENTITY CASCADE`;
}
