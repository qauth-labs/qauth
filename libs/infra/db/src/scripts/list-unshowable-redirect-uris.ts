/**
 * List the clients with a redirect URI the consent screen cannot show (#914).
 *
 * Since #593 the consent screen refuses a redirect URI it cannot describe (an
 * underscore in the host, an IPv6 address that is not loopback, a scheme over
 * 64 characters), and so does every registration path. A client stored before
 * that with such a URI breaks; this lists them per realm, with why each URI
 * fails and who can replace it. It only reads. It reads no column newer than
 * migration 0023, so it also runs against a 0.1 database before an upgrade.
 *
 * Usage (from the repo root):
 *
 *   DATABASE_URL=postgresql://qauth:pw@host:5432/qauth \
 *     pnpm nx run infra-db:db:list-unshowable-redirect-uris -- [--realm=<realm name>]
 *
 * It exits 0 when no client holds such a URI, 1 when it lists any, 2 on a
 * usage error and 3 when it could not run ({@link LIST_UNSHOWABLE_EXIT}). Nx
 * turns every non-zero exit into 1, so a script that tells them apart runs
 * `pnpm --dir libs/infra/db exec tsx src/scripts/list-unshowable-redirect-uris.ts`.
 */
import * as dotenv from 'dotenv';
import { drizzle } from 'drizzle-orm/node-postgres';

import {
  describeUnshowableRedirectUris,
  LIST_UNSHOWABLE_EXIT,
  LIST_UNSHOWABLE_USAGE,
  listUnshowableRedirectUris,
  parseListUnshowableArgs,
} from './unshowable-redirect-uris';

dotenv.config({ path: '../../../.env' });

async function main(): Promise<number> {
  const args = parseListUnshowableArgs(process.argv);
  if (!args) {
    console.error(LIST_UNSHOWABLE_USAGE);
    return LIST_UNSHOWABLE_EXIT.usage;
  }

  const databaseUrl = process.env['DATABASE_URL'];
  if (!databaseUrl) {
    console.error('DATABASE_URL must be set in the environment.');
    return LIST_UNSHOWABLE_EXIT.usage;
  }

  const db = drizzle(databaseUrl);
  // An idle connection that fails emits on the pool; unheard, Node would exit
  // with 1, as for a list that is not empty. The query fails instead, and
  // exits 3.
  db.$client.on('error', () => undefined);
  try {
    const result = await listUnshowableRedirectUris(db, args);
    if (result.status === 'realm_not_found') {
      console.error(`Realm ${JSON.stringify(args.realm)} not found.`);
      return LIST_UNSHOWABLE_EXIT.cannotRun;
    }
    console.log(describeUnshowableRedirectUris(result.scan));
    return result.scan.clients.length === 0
      ? LIST_UNSHOWABLE_EXIT.none
      : LIST_UNSHOWABLE_EXIT.found;
  } finally {
    await db.$client.end().catch(() => undefined);
  }
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err: unknown) => {
    console.error(
      `The clients could not be listed: ${err instanceof Error ? err.message : String(err)}`
    );
    process.exitCode = LIST_UNSHOWABLE_EXIT.cannotRun;
  }
);
