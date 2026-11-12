/**
 * Disable a user account, or enable it again (#748).
 *
 * A disabled account cannot sign in or obtain tokens, and every browser
 * session and token it was issued before the change stays refused, also after
 * the account is enabled again: its holder signs in again. The change and its
 * event (`user.disabled` or `user.enabled`) commit in one transaction, and a
 * disablement ends in it the account's browser sessions (each with a
 * `user.session_revoked` event), refresh tokens and unredeemed authorization
 * codes (#893).
 *
 * Usage (from the repo root):
 *
 *   DATABASE_URL=postgresql://qauth:pw@host:5432/qauth \
 *     pnpm nx run infra-db:db:disable-user -- \
 *     --realm=<realm name> --user-id=<user id> [--enable]
 *
 * An `UPDATE users SET enabled = false` by hand refuses the old sessions and
 * tokens the same way, through the trigger, at their next use; but it ends
 * none of them at once, and records no event, so no Shared Signals receiver
 * hears of it.
 */
import * as dotenv from 'dotenv';
import { drizzle } from 'drizzle-orm/node-postgres';

import { parseUserEnablementArgs, setUserEnabled, USER_ENABLEMENT_USAGE } from './user-enablement';

dotenv.config({ path: '../../../.env' });

async function main(): Promise<void> {
  const args = parseUserEnablementArgs(process.argv);
  if (!args) {
    console.error(USER_ENABLEMENT_USAGE);
    process.exit(2);
  }

  const databaseUrl = process.env['DATABASE_URL'];
  if (!databaseUrl) {
    console.error('DATABASE_URL must be set in the environment.');
    process.exit(2);
  }

  const db = drizzle(databaseUrl);
  try {
    const result = await setUserEnabled(db, args);
    switch (result.status) {
      case 'realm_not_found':
        console.error(`Realm "${args.realm}" not found.`);
        process.exitCode = 1;
        return;
      case 'user_not_found':
        console.error(`User "${args.userId}" not found in realm "${args.realm}".`);
        process.exitCode = 1;
        return;
      case 'unchanged':
        console.log(
          `User "${result.userId}" is already ${result.enabled ? 'enabled' : 'disabled'}; nothing changed.`
        );
        break;
      case 'disabled':
        console.log(
          `User "${result.userId}" is disabled. Ended ${result.endedSessions} browser ` +
            `session${result.endedSessions === 1 ? '' : 's'}, and revoked its refresh tokens ` +
            'and unredeemed authorization codes.'
        );
        break;
      case 'enabled':
        console.log(`User "${result.userId}" is enabled.`);
        break;
    }
    if (result.notValidBefore !== null) {
      console.log(
        `Sessions and tokens issued before ${new Date(result.notValidBefore).toISOString()} ` +
          'stay refused; the user signs in again.'
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
