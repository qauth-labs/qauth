/**
 * Suspend an OAuth client, or lift its suspension (ANT-2026-DR5XI3LV).
 *
 * A suspended client is refused everywhere a disabled client is: it gets no
 * authorization codes and cannot authenticate at the token, introspection or
 * revocation endpoints. Unlike `enabled`, which the client's owner may switch
 * either way through `PATCH /api/clients/:id`, only an operator sets or clears
 * `suspended`, through this script or the same `UPDATE` by hand.
 *
 * Usage (from the repo root):
 *
 *   DATABASE_URL=postgresql://qauth:pw@host:5432/qauth \
 *     pnpm nx run infra-db:db:suspend-oauth-client -- \
 *     --realm=<realm name> --client-id=<client_id> [--lift]
 *
 * Lifting a suspension does not touch `enabled`. A client that is also
 * disabled stays disabled until its owner re-enables it; the script says so.
 */
import * as dotenv from 'dotenv';
import { drizzle } from 'drizzle-orm/node-postgres';

import { parseSuspensionArgs, setClientSuspension, SUSPENSION_USAGE } from './client-suspension';

dotenv.config({ path: '../../../.env' });

async function main(): Promise<void> {
  const args = parseSuspensionArgs(process.argv);
  if (!args) {
    console.error(SUSPENSION_USAGE);
    process.exit(2);
  }

  const databaseUrl = process.env['DATABASE_URL'];
  if (!databaseUrl) {
    console.error('DATABASE_URL must be set in the environment.');
    process.exit(2);
  }

  const db = drizzle(databaseUrl);
  try {
    const result = await setClientSuspension(db, args);
    switch (result.status) {
      case 'realm_not_found':
        console.error(`Realm "${args.realm}" not found.`);
        process.exitCode = 1;
        return;
      case 'client_not_found':
        console.error(`Client "${args.clientId}" not found in realm "${args.realm}".`);
        process.exitCode = 1;
        return;
      case 'unchanged':
        console.log(
          `Client "${result.clientId}" is already ${result.suspended ? 'suspended' : 'not suspended'}; nothing changed.`
        );
        break;
      case 'suspended':
        console.log(`Client "${result.clientId}" is suspended.`);
        break;
      case 'lifted':
        console.log(`Client "${result.clientId}" is no longer suspended.`);
        break;
    }
    if (!result.suspended && !result.enabled) {
      console.log(
        'It is still disabled (enabled = false). Its owner can re-enable it through ' +
          'PATCH /api/clients/:id; a client with no owner is re-enabled with ' +
          "UPDATE oauth_clients SET enabled = true WHERE client_id = '<client_id>'."
      );
    }
  } finally {
    await db.$client.end();
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? (err.stack ?? err.message) : err);
  process.exit(1);
});
