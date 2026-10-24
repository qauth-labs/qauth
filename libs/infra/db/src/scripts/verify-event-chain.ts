/**
 * Verify a realm's admin event chain (issue #459, ADR-019 Decision 7).
 *
 * Every admin event of a realm carries the hash of the one before it. This
 * reads the chain, oldest first, and reports the first admin event that was
 * changed, or that follows one that was removed. It only reads.
 *
 * Usage (from the repo root):
 *
 *   DATABASE_URL=postgresql://qauth:pw@host:5432/qauth \
 *     pnpm nx run infra-db:events:verify-chain -- \
 *     (--realm=<realm name> | --realm-id=<uuid>) [--from-seq=<seq> --from-hash=<hex>] [--json]
 *
 * It exits 0 when the chain verifies, 1 when it breaks or the realm is not
 * found, and 2 on a usage error. Keep the head it prints outside the
 * database: a later run from that head also shows the newest events cut.
 */
import * as dotenv from 'dotenv';
import { eq } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';

import { createEventsRepository } from '../lib/repositories/events.repository';
import { realms } from '../lib/schema/core';
import type { Database } from '../types';
import {
  chainReportJson,
  describeChainReport,
  parseVerifyChainArgs,
  VERIFY_CHAIN_USAGE,
} from './event-chain';

dotenv.config({ path: '../../../.env' });

async function main(): Promise<void> {
  const args = parseVerifyChainArgs(process.argv);
  if (!args) {
    console.error(VERIFY_CHAIN_USAGE);
    process.exit(2);
  }

  const databaseUrl = process.env['DATABASE_URL'];
  if (!databaseUrl) {
    console.error('DATABASE_URL must be set in the environment.');
    process.exit(2);
  }

  const db = drizzle(databaseUrl);
  try {
    let realmId = args.realmId;
    if (args.realm !== undefined) {
      const [realm] = await db
        .select({ id: realms.id })
        .from(realms)
        .where(eq(realms.name, args.realm));
      if (!realm) {
        console.error(`Realm "${args.realm}" not found. A deleted realm is named by --realm-id.`);
        process.exitCode = 1;
        return;
      }
      realmId = realm.id;
    }
    if (realmId === undefined) throw new Error('unreachable: the arguments name a realm');

    const report = await createEventsRepository(db as unknown as Database).verifyChain(
      realmId,
      args.from
    );
    const label = args.realm === undefined ? realmId : `"${args.realm}" (${realmId})`;
    if (args.json) console.log(chainReportJson(report));
    else for (const line of describeChainReport(report, label)) console.log(line);
    if (!report.ok) process.exitCode = 1;
  } finally {
    await db.$client.end();
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
