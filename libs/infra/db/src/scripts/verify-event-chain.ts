/**
 * Verify a realm's admin event chain (issues #459 and #827, ADR-019 Decision
 * 7).
 *
 * Every admin event of a realm carries the hash of the one before it. This
 * reads the chain, oldest first, and reports the first admin event that was
 * changed, or that follows one that was removed. It only reads, so run it as
 * a role that may read `events`; a writing role may not.
 *
 * Usage (from the repo root):
 *
 *   DATABASE_URL=postgresql://qauth:pw@host:5432/qauth \
 *     pnpm --dir libs/infra/db exec tsx src/scripts/verify-event-chain.ts \
 *     (--realm=<realm name> | --realm-id=<uuid>) [--from-seq=<seq> --from-hash=<hex>] [--json]
 *
 * `pnpm nx run infra-db:events:verify-chain -- …` runs it too, but Nx turns
 * every non-zero exit into 1, so a monitor runs the command above.
 *
 * It exits 0 when the chain verifies, 1 when it breaks, 2 on a usage error,
 * and 3 when the check could not run: the database unreachable or failing,
 * or the realm not found ({@link VERIFY_CHAIN_EXIT}). A monitor can so tell
 * a tampered chain from an outage. Keep the head it prints outside the
 * database: a later run from that head also shows the newest events cut.
 */
import * as dotenv from 'dotenv';
import { eq, sql } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';

import { createEventsRepository } from '../lib/repositories/events.repository';
import { realms } from '../lib/schema/core';
import { events } from '../lib/schema/events';
import type { Database } from '../types';
import {
  chainReportJson,
  describeChainReport,
  parseVerifyChainArgs,
  VERIFY_CHAIN_EXIT,
  VERIFY_CHAIN_USAGE,
} from './event-chain';

dotenv.config({ path: '../../../.env' });

/**
 * How long to wait for a connection. An unreachable database that drops
 * packets then exits 3 rather than holding a monitor's run open.
 */
const CONNECT_TIMEOUT_MS = 10_000;

/** Thrown for a check that cannot run for a reason the operator can act on. */
class CannotRun extends Error {}

/**
 * What went wrong, in one line. drizzle wraps a driver error in one that
 * names the failed query, and a refused connection to every address of a
 * host is an `AggregateError` with no message, so the innermost error says
 * why: its message and its code.
 */
function reasonOf(err: unknown): string {
  let current: unknown = err;
  while (current instanceof Error && current.cause instanceof Error) current = current.cause;
  if (current instanceof AggregateError && current.errors[0] instanceof Error) {
    current = current.errors[0];
  }
  if (!(current instanceof Error)) return String(current);
  const code = (current as { code?: unknown }).code;
  const message = current.message !== '' ? current.message : current.name;
  return typeof code === 'string' && !message.includes(code) ? `${message} (${code})` : message;
}

async function main(): Promise<number> {
  const args = parseVerifyChainArgs(process.argv);
  if (!args) {
    console.error(VERIFY_CHAIN_USAGE);
    return VERIFY_CHAIN_EXIT.usage;
  }

  const databaseUrl = process.env['DATABASE_URL'];
  if (!databaseUrl) {
    console.error('DATABASE_URL must be set in the environment.');
    return VERIFY_CHAIN_EXIT.usage;
  }

  const db = drizzle({
    connection: { connectionString: databaseUrl, connectionTimeoutMillis: CONNECT_TIMEOUT_MS },
  });
  // An idle connection that fails emits on the pool; unheard, Node would exit
  // with 1, as for a broken chain. The next query fails instead, and exits 3.
  db.$client.on('error', () => undefined);
  try {
    let realmId = args.realmId;
    if (args.realm !== undefined) {
      const [realm] = await db
        .select({ id: realms.id })
        .from(realms)
        .where(eq(realms.name, args.realm));
      if (!realm) {
        throw new CannotRun(
          `Realm "${args.realm}" not found. A deleted realm is named by --realm-id.`
        );
      }
      realmId = realm.id;
    } else if (realmId !== undefined) {
      // A deleted realm keeps its events, so an id is known when either names it.
      const { rows } = await db.execute<{ known: boolean }>(sql`
        select exists(select 1 from ${realms} where ${realms.id} = ${realmId}::uuid)
            or exists(select 1 from ${events} where ${events.realmId} = ${realmId}::uuid)
          as "known"
      `);
      if (rows[0]?.known !== true) {
        throw new CannotRun(`Realm ${realmId} not found: no realm and no event has that id.`);
      }
    }
    if (realmId === undefined) throw new Error('unreachable: the arguments name a realm');

    const report = await createEventsRepository(db as unknown as Database).verifyChain(
      realmId,
      args.from
    );
    const label = args.realm === undefined ? realmId : `"${args.realm}" (${realmId})`;
    if (args.json) console.log(chainReportJson(report));
    else for (const line of describeChainReport(report, label)) console.log(line);
    return report.ok ? VERIFY_CHAIN_EXIT.verified : VERIFY_CHAIN_EXIT.broken;
  } finally {
    // The verdict stands even when closing the connections fails.
    await db.$client.end().catch(() => undefined);
  }
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err: unknown) => {
    // Not a verdict on the chain: the check did not run to its end.
    console.error(
      err instanceof CannotRun ? err.message : `The chain could not be checked: ${reasonOf(err)}`
    );
    process.exitCode = VERIFY_CHAIN_EXIT.cannotRun;
  }
);
