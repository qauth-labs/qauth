/**
 * Operator switch of a user account (#748).
 *
 * A disabled account cannot sign in or obtain tokens. Disabling it also ends,
 * for good, everything it already holds: `users.not_valid_before` takes the
 * time of the change (trigger `users_not_valid_before`, migration 0044), and
 * the auth server refuses every browser session and token of the user issued
 * before it, also after the account is enabled again.
 *
 * QAuth has no admin API operation for users yet (#681), so this is operator
 * tooling that talks to the database directly, like `client-suspension.ts`.
 * The logic lives here, apart from the CLI in `disable-user.ts`, so it can be
 * tested without running the script.
 */
import { userInfo } from 'node:os';

import { and, eq, sql } from 'drizzle-orm';
import type { NodePgDatabase } from 'drizzle-orm/node-postgres';

import { createEventsRepository } from '../lib/repositories/events.repository';
import { realms, users } from '../lib/schema/core';
import type { Database, DbTransaction } from '../types';

export interface UserEnablementArgs {
  realm: string;
  userId: string;
  /** `false` to disable the account, `true` to enable it again. */
  enable: boolean;
}

export const USER_ENABLEMENT_USAGE =
  'Usage: disable-user.ts --realm=<realm name> --user-id=<user id> [--enable]\n' +
  '       Disables the account, or with --enable enables it again.\n' +
  '       Set DATABASE_URL in the environment.';

/** A user id: `users.id` is a uuid column, and a malformed one must not reach Postgres. */
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Parse `--realm=<name> --user-id=<uuid> [--enable]` from `process.argv`.
 * Returns null when a required argument is missing or malformed, or an
 * unknown flag is given, so the caller prints the usage instead of guessing.
 */
export function parseUserEnablementArgs(argv: readonly string[]): UserEnablementArgs | null {
  let realm: string | undefined;
  let userId: string | undefined;
  let enable = false;
  for (const arg of argv.slice(2)) {
    if (arg.startsWith('--realm=')) realm = arg.slice('--realm='.length);
    else if (arg.startsWith('--user-id=')) userId = arg.slice('--user-id='.length);
    else if (arg === '--enable') enable = true;
    else return null;
  }
  if (!realm || !userId || !UUID.test(userId)) return null;
  return { realm, userId: userId.toLowerCase(), enable };
}

export type UserEnablementResult =
  | { status: 'realm_not_found' }
  | { status: 'user_not_found' }
  | {
      status: 'disabled' | 'enabled' | 'unchanged';
      userId: string;
      enabled: boolean;
      /**
       * When the account was last disabled, in epoch ms; `null` when it never
       * was. Sessions and tokens issued before it stay refused.
       */
      notValidBefore: number | null;
    };

/** Any drizzle node-postgres database, whatever schema generic it was built with. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type OperatorDb = NodePgDatabase<any>;

/**
 * The operating-system user running the tool, the `actor.id` of its event.
 * `undefined` when the process has no user entry (a container without one),
 * so the event still names the tool as its actor.
 */
function operatorUser(): string | undefined {
  try {
    const name = userInfo().username;
    return name.length > 0 && name.length <= 255 ? name : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Disable an account, or enable it again, and record it as an event
 * (`user.disabled` or `user.enabled`, actor `operator_cli`), in one
 * transaction. Idempotent: an account already in the requested state is
 * reported `unchanged` and nothing is written.
 *
 * Disabling sets `not_valid_before` through the triggers, from the database's
 * clock at the commit. Enabling never clears it: whoever held a session or a
 * token from before signs in again.
 */
export async function setUserEnabled(
  db: OperatorDb,
  args: UserEnablementArgs
): Promise<UserEnablementResult> {
  const result = await changeEnablement(db, args);
  if (result.status !== 'disabled') return result;
  // The deferred trigger moved the time to the commit: report what is stored.
  const [stored] = await db
    .select({ notValidBefore: users.notValidBefore })
    .from(users)
    .where(eq(users.id, result.userId))
    .limit(1);
  return { ...result, notValidBefore: stored?.notValidBefore ?? result.notValidBefore };
}

async function changeEnablement(
  db: OperatorDb,
  args: UserEnablementArgs
): Promise<UserEnablementResult> {
  return db.transaction(async (tx) => {
    const [realm] = await tx
      .select({ id: realms.id })
      .from(realms)
      .where(eq(realms.name, args.realm))
      .limit(1);
    if (!realm) return { status: 'realm_not_found' as const };

    // FOR UPDATE: a concurrent run for the same account waits for this one,
    // so the state it reports and the event it writes cannot interleave.
    const [user] = await tx
      .select({
        userId: users.id,
        enabled: users.enabled,
        notValidBefore: users.notValidBefore,
      })
      .from(users)
      .where(and(eq(users.realmId, realm.id), eq(users.id, args.userId)))
      .limit(1)
      .for('update');
    if (!user) return { status: 'user_not_found' as const };

    if (user.enabled === args.enable) {
      return { status: 'unchanged' as const, ...user };
    }

    const [updated] = await tx
      .update(users)
      .set({
        enabled: args.enable,
        updatedAt: sql`(EXTRACT(EPOCH FROM now()) * 1000)::bigint`,
      })
      .where(eq(users.id, user.userId))
      .returning({
        userId: users.id,
        enabled: users.enabled,
        notValidBefore: users.notValidBefore,
      });

    // The event commits with the change. The tool's database handle has a
    // schema generic of its own; at run time it is the same node-postgres
    // database and transaction the repository takes.
    const operator = operatorUser();
    await createEventsRepository(db as unknown as Database).emit(tx as unknown as DbTransaction, {
      type: args.enable
        ? 'urn:qauth:event:user.enabled:v1-rc.0'
        : 'urn:qauth:event:user.disabled:v1-rc.0',
      realm: realm.id,
      actor: { type: 'operator_cli', ...(operator === undefined ? {} : { id: operator }) },
      subject: { type: 'user', id: user.userId },
      data: {},
    });

    return { status: args.enable ? ('enabled' as const) : ('disabled' as const), ...updated };
  });
}
