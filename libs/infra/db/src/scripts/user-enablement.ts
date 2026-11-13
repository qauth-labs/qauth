/**
 * Operator switch of a user account (#748).
 *
 * A disabled account cannot sign in or obtain tokens. Disabling it also ends,
 * for good, everything it already holds: `users.not_valid_before` takes the
 * time of the change (trigger `users_not_valid_before`, migration 0044), and
 * the auth server refuses every browser session and token of the user issued
 * before it, also after the account is enabled again. That rule is the
 * authority: it also covers an `UPDATE` by hand.
 *
 * The tool also ends at once, in the disabling transaction, what the account
 * holds in the database (#893): its browser sessions, its refresh tokens and
 * its unredeemed authorization codes. So no row of it reads as live, and a
 * Shared Signals receiver hears of each ended session (`user.session_revoked`,
 * CAEP `session-revoked`), and each client a session served with a
 * back-channel logout URI is queued its logout token.
 *
 * QAuth has no admin API operation for users yet (#681), so this is operator
 * tooling that talks to the database directly, like `client-suspension.ts`.
 * The logic lives here, apart from the CLI in `disable-user.ts`, so it can be
 * tested without running the script.
 */
import { userInfo } from 'node:os';

import { and, eq, sql } from 'drizzle-orm';
import type { NodePgDatabase } from 'drizzle-orm/node-postgres';

import { createAuthorizationCodesRepository } from '../lib/repositories/authorization-codes.repository';
import { createEventsRepository } from '../lib/repositories/events.repository';
import { createRefreshTokensRepository } from '../lib/repositories/refresh-tokens.repository';
import { createSessionsRepository } from '../lib/repositories/sessions.repository';
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

/** What the account is, after a run that found it. */
interface UserEnablementState {
  userId: string;
  enabled: boolean;
  /**
   * When the account was last disabled, in epoch ms; `null` when it never
   * was. Sessions and tokens issued before it stay refused.
   */
  notValidBefore: number | null;
}

export type UserEnablementResult =
  | { status: 'realm_not_found' }
  | { status: 'user_not_found' }
  | ({ status: 'enabled' | 'unchanged' } & UserEnablementState)
  | ({
      status: 'disabled';
      /** How many live browser sessions of the account the disablement ended. */
      endedSessions: number;
    } & UserEnablementState);

/**
 * The `revoked_reason` of the refresh tokens a disablement revokes. A session
 * it ends is `admin`, as the auth server ends a disabled account's session it
 * meets.
 */
export const DISABLED_ACCOUNT_REVOKE_REASON = 'account_disabled';

/** The tool's events' actor: the operator on the server host. */
interface OperatorActor {
  readonly type: 'operator_cli';
  readonly id?: string;
}

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
 * clock at the commit, and ends in the same transaction what the account
 * holds ({@link endWhatTheAccountHolds}). Enabling never clears it and ends
 * nothing: whoever held a session or a token from before signs in again.
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
  // READ COMMITTED, whatever the database's default: ending the sessions
  // needs it (the sessions repository's `revokeForUser` refuses another).
  return db.transaction(
    async (tx): Promise<UserEnablementResult> => {
      const [realm] = await tx
        .select({ id: realms.id })
        .from(realms)
        .where(eq(realms.name, args.realm))
        .limit(1);
      if (!realm) return { status: 'realm_not_found' as const };

      // FOR NO KEY UPDATE: a concurrent run for the same account waits for this
      // one, so the state it reports and the event it writes cannot interleave.
      // Not FOR UPDATE: a refresh-token rotation holds the account's token lock
      // shared and then inserts a token, whose foreign key takes a key-share
      // lock on this row, while this run waits for that token lock to revoke
      // the tokens. FOR UPDATE would block that key-share lock: a deadlock.
      const [user] = await tx
        .select({
          userId: users.id,
          enabled: users.enabled,
          notValidBefore: users.notValidBefore,
        })
        .from(users)
        .where(and(eq(users.realmId, realm.id), eq(users.id, args.userId)))
        .limit(1)
        .for('no key update');
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

      // The events commit with the change. The tool's database handle has a
      // schema generic of its own; at run time it is the same node-postgres
      // database and transaction the repository takes.
      const operator = operatorUser();
      const actor: OperatorActor = {
        type: 'operator_cli',
        ...(operator === undefined ? {} : { id: operator }),
      };
      const database = db as unknown as Database;
      const t = tx as unknown as DbTransaction;
      const events = createEventsRepository(database);

      // A disablement ends what the account holds before it records its
      // admin events. Recording one takes the realm's chain lock, which an
      // admin API write takes last, after the rows it changes: taken before
      // the account's codes, tokens and sessions, it could deadlock against
      // such a write holding one of them (a client's suspension, say).
      const ended = args.enable
        ? []
        : await endWhatTheAccountHolds(database, t, {
            realmId: realm.id,
            userId: user.userId,
            events,
          });
      await events.emit(t, {
        type: args.enable
          ? 'urn:qauth:event:user.enabled:v1-rc.0'
          : 'urn:qauth:event:user.disabled:v1-rc.0',
        realm: realm.id,
        actor,
        subject: { type: 'user', id: user.userId },
        data: {},
      });
      if (args.enable) return { status: 'enabled' as const, ...updated };

      // One user.session_revoked per ended session, sent to Shared Signals
      // receivers as CAEP session-revoked naming the session.
      for (const sid of ended) {
        await events.emit(t, {
          type: 'urn:qauth:event:user.session_revoked:v1-rc.0',
          realm: realm.id,
          actor,
          subject: { type: 'user', id: user.userId },
          data: { sid, reason: 'account_disabled' },
        });
      }
      return { status: 'disabled' as const, ...updated, endedSessions: ended.length };
    },
    { isolationLevel: 'read committed' }
  );
}

/**
 * End what a disabled account holds, in the disabling transaction `tx`
 * (#893): its unredeemed authorization codes, its live refresh tokens and its
 * browser sessions not yet ended, each session with, through the sessions
 * repository, a back-channel logout notice (`user.client_session_ended`) for
 * each client it served that has a logout URI. The account's row is locked
 * and disabled already, and nothing commits until the disablement does; the
 * caller records the admin events (`user.disabled`, a `user.session_revoked`
 * per ended session) after it.
 *
 * A session, token or code issued while the transaction is open, which none
 * of these statements sees, is refused all the same by the auth server: it
 * counts as issued before `not_valid_before`, which takes the time of the
 * commit.
 *
 * @returns the ids of the browser sessions it ended
 */
async function endWhatTheAccountHolds(
  db: Database,
  tx: DbTransaction,
  account: {
    readonly realmId: string;
    readonly userId: string;
    readonly events: ReturnType<typeof createEventsRepository>;
  }
): Promise<string[]> {
  const { realmId, userId, events } = account;
  // Codes first, as a sign-out ends them: a code redeemed after the tokens
  // below would open a refresh family they did not reach.
  await createAuthorizationCodesRepository(db).invalidateForUser(userId, tx);
  await createRefreshTokensRepository(db).revokeAllForUser(
    userId,
    DISABLED_ACCOUNT_REVOKE_REASON,
    tx
  );
  const ended = await createSessionsRepository(db, { events }).revokeForUser(
    realmId,
    userId,
    'admin',
    {},
    tx
  );
  return ended.map(({ session }) => session.id);
}
