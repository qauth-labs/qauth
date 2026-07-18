/**
 * ADR-002 identity backfill CLI (issue #226).
 *
 * Thin wrapper around `runIdentityBackfill` (`../lib/backfill/backfill-identity.ts`
 * — semantics, idempotency model, and refresh rules live there). Populates
 * `user_credentials` / `user_attributes` from the legacy `users` columns.
 *
 * Usage (from the repo root):
 *
 *   DATABASE_URL=postgresql://qauth:pw@host:5432/qauth \
 *     pnpm nx run infra-db:db:backfill-identity [-- --flags]
 *
 * Flags:
 *   --batch-size=<1-10000>  Users per keyset batch (default 1000).
 *   --refresh               Also update stale existing rows from the legacy
 *                           columns. PRE-CUTOVER ONLY: refresh copies FROM
 *                           users.email/email_normalized/password_hash, which
 *                           are authoritative only until the #228 auth-engine
 *                           cutover. Never run --refresh after cutover.
 *   --dry-run               Scan and report would-create/would-refresh counts;
 *                           write nothing.
 *   --verify-only           Only run the read-only verification queries (no
 *                           advisory lock, no writes). Exclusive with the
 *                           other flags.
 *   --help                  Print this help.
 *
 * Cutover runbook (echoed on issue #228): immediately before switching the
 * auth engine to the new tables, run `--refresh`, then `--verify-only`; both
 * must exit 0.
 *
 * Exit codes: 0 = success (write/verify runs additionally require clean
 * verification); 1 = runtime failure, verification mismatch, refresh
 * conflict, or another backfill already holds the advisory lock; 2 = usage
 * error.
 */
import * as dotenv from 'dotenv';

import {
  backfillSucceeded,
  type BackfillSummary,
  DEFAULT_BATCH_SIZE,
  MAX_BATCH_SIZE,
  runIdentityBackfill,
  verifyIdentityBackfill,
} from '../lib/backfill/backfill-identity';
import { createDatabase } from '../lib/db';

dotenv.config({ path: '../../../.env' });

/**
 * Advisory lock key preventing concurrent backfill runs (two interleaved
 * --refresh runs could write torn combinations of two legacy snapshots).
 * Arbitrary but stable; chosen from the issue number: 226 * 10^6 + 1.
 */
const BACKFILL_ADVISORY_LOCK_KEY = 226_000_001;

const USAGE = `Usage: backfill-identity.ts [--batch-size=<1-${MAX_BATCH_SIZE}>] [--refresh] [--dry-run] | [--verify-only] | [--help]
Set DATABASE_URL in the environment.

Populates user_credentials/user_attributes from the legacy users columns
(ADR-002, issue #226). Idempotent: re-runs skip users that already have rows.

--refresh is PRE-CUTOVER ONLY (it copies from the legacy users columns, which
stop being authoritative at the #228 cutover). Pre-cutover runbook: run
--refresh, then --verify-only; both must exit 0.`;

interface CliOptions {
  batchSize: number;
  refresh: boolean;
  dryRun: boolean;
  verifyOnly: boolean;
}

function usageError(message: string): never {
  console.error(`${message}\n\n${USAGE}`);
  process.exit(2);
}

function parseArgs(argv: string[]): CliOptions {
  const rest = argv.slice(2);
  if (rest.includes('--help')) {
    console.log(USAGE);
    process.exit(0);
  }

  const options: CliOptions = {
    batchSize: DEFAULT_BATCH_SIZE,
    refresh: false,
    dryRun: false,
    verifyOnly: false,
  };

  for (const arg of rest) {
    if (arg === '--refresh') options.refresh = true;
    else if (arg === '--dry-run') options.dryRun = true;
    else if (arg === '--verify-only') options.verifyOnly = true;
    else if (arg.startsWith('--batch-size=')) {
      const raw = arg.slice('--batch-size='.length);
      const parsed = Number(raw);
      if (!Number.isInteger(parsed) || parsed < 1 || parsed > MAX_BATCH_SIZE) {
        usageError(`Invalid --batch-size "${raw}" (expected an integer 1-${MAX_BATCH_SIZE}).`);
      }
      options.batchSize = parsed;
    } else {
      usageError(`Unknown argument "${arg}".`);
    }
  }

  if (
    options.verifyOnly &&
    (options.refresh || options.dryRun || options.batchSize !== DEFAULT_BATCH_SIZE)
  ) {
    usageError('--verify-only cannot be combined with other flags.');
  }
  return options;
}

function reportVerification(summary: BackfillSummary): void {
  const v = summary.verification;
  console.log('Verification (AC1 — every user has exactly one of each row):');
  console.log(`  users missing a password credential: ${v.missingCredentials}`);
  if (v.missingCredentialSampleUserIds.length > 0) {
    console.log(`    sample user ids: ${v.missingCredentialSampleUserIds.join(', ')}`);
  }
  console.log(`  users missing the email attribute:   ${v.missingAttributes}`);
  if (v.missingAttributeSampleUserIds.length > 0) {
    console.log(`    sample user ids: ${v.missingAttributeSampleUserIds.join(', ')}`);
  }
  console.log(`  users with duplicate credentials:    ${v.duplicateCredentials}`);
  if (v.duplicateCredentialSampleUserIds.length > 0) {
    console.log(`    sample user ids: ${v.duplicateCredentialSampleUserIds.join(', ')}`);
  }
}

function report(summary: BackfillSummary, options: CliOptions, elapsedMs: number): void {
  if (!options.verifyOnly) {
    const label = options.dryRun ? ' (dry-run: nothing was written)' : '';
    console.log(`\nBackfill summary${label}:`);
    console.log(`  users scanned: ${summary.usersScanned} in ${summary.batches} batches`);
    console.log(
      `  user_credentials: ${summary.credentials.created} created, ` +
        `${summary.credentials.skipped} skipped, ${summary.credentials.refreshed} refreshed`
    );
    console.log(
      `  user_attributes:  ${summary.attributes.created} created, ` +
        `${summary.attributes.skipped} skipped, ${summary.attributes.refreshed} refreshed`
    );
    console.log(`  elapsed: ${Math.round(elapsedMs)}ms\n`);
  }

  if (summary.refreshConflicts.length > 0) {
    console.error(
      'Refresh conflicts (email swap during the drift window — remediate manually,\n' +
        'a plain re-run heals one-directional reassignments):'
    );
    for (const c of summary.refreshConflicts) {
      console.error(`  user ${c.userId} could not take external_sub "${c.externalSub}"`);
    }
  }

  reportVerification(summary);
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv);

  const databaseUrl = process.env['DATABASE_URL'];
  if (!databaseUrl) {
    console.error(`DATABASE_URL must be set in the environment.\n\n${USAGE}`);
    process.exit(2);
  }

  // The script is strictly serial — one connection for the advisory lock,
  // one for the queries.
  const database = createDatabase({ connectionString: databaseUrl, pool: { max: 2, min: 0 } });

  let exitCode = 0;
  try {
    if (options.verifyOnly) {
      const verification = await verifyIdentityBackfill(database.db);
      const summary: BackfillSummary = {
        credentials: { created: 0, skipped: 0, refreshed: 0 },
        attributes: { created: 0, skipped: 0, refreshed: 0 },
        batches: 0,
        usersScanned: 0,
        refreshConflicts: [],
        verification,
      };
      reportVerification(summary);
      exitCode = backfillSucceeded(summary) ? 0 : 1;
      return;
    }

    // Hold the advisory lock on a dedicated client for the whole run; the
    // lock is session-scoped, so the client must not be released in between.
    const lockClient = await database.pool.connect();
    let lockAcquired = false;
    try {
      const lockResult = await lockClient.query<{ locked: boolean }>(
        'SELECT pg_try_advisory_lock($1) AS locked',
        [BACKFILL_ADVISORY_LOCK_KEY]
      );
      if (!lockResult.rows[0]?.locked) {
        console.error(
          'Another backfill run holds the advisory lock — refusing to run concurrently.'
        );
        exitCode = 1;
        return;
      }
      lockAcquired = true;

      const startedAt = performance.now();
      const summary = await runIdentityBackfill(database.db, {
        batchSize: options.batchSize,
        refresh: options.refresh,
        dryRun: options.dryRun,
      });
      report(summary, options, performance.now() - startedAt);

      // A dry run is informational: it exits 0 even when verification still
      // reports missing rows (nothing was written yet by design).
      exitCode = options.dryRun || backfillSucceeded(summary) ? 0 : 1;
    } finally {
      if (lockAcquired) {
        await lockClient.query('SELECT pg_advisory_unlock($1)', [BACKFILL_ADVISORY_LOCK_KEY]);
      }
      lockClient.release();
    }
  } finally {
    await database.close();
    process.exitCode = exitCode;
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? (err.stack ?? err.message) : err);
  process.exit(1);
});
