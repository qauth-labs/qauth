/**
 * An operator's verification of an account from the server host (ADR-015
 * Decision 8, amended 2026-11-08; issue #1052): the migration runner's
 * `verify-account` command.
 *
 * The admin API's `users.verify` is the audited, approved way an operator
 * verifies an account. A deployment that has no admin API set up yet (no
 * admin listener, or no admin with a passkey to approve with) has this one:
 * whoever can run the migration runner against the database already holds
 * it, as the table owner. It records the same verification on the account,
 * `users.operator_verified_at` and `operator_verified_by` (`operator_cli`,
 * with the operating-system user that ran it when the host names one), and
 * the same `user.verified` event, with the method `operator_cli` and the
 * actor `operator_cli`, in one transaction.
 *
 * It refuses a disabled account and one the realm does not hold (a deleted
 * account has no row). An account an operator already verified keeps its
 * first verification, and nothing is written. It never touches
 * `email_verified`.
 *
 * The module reaches only `pg`, `drizzle-orm`, the event contract and the
 * shared validation rules, so the migration runner bundles it
 * (`@qauth-labs/infra-db/account-verification`).
 */
import { userInfo } from 'node:os';

import { OPERATOR_CLI_USER_MAX_LENGTH, operatorVerifiedBy } from '@qauth-labs/shared-validation';
import { and, eq, isNull } from 'drizzle-orm';
import { drizzle, type NodePgDatabase } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';

import type { Database, DbTransaction } from '../../types';
import { createEventsRepository } from '../repositories/events.repository';
import { realms, users } from '../schema/core';

/** The account to verify: a realm by name, and an account of it by id. */
export interface AccountVerificationArgs {
  readonly realm: string;
  readonly userId: string;
}

/** What {@link verifyAccount} did. */
export type AccountVerificationResult =
  | { readonly status: 'realm_not_found' }
  | { readonly status: 'user_not_found' }
  | { readonly status: 'disabled'; readonly userId: string }
  | {
      /** An operator verified it before: that verification is kept, and nothing was written. */
      readonly status: 'already_verified';
      readonly userId: string;
      readonly verifiedAt: number;
      readonly verifiedBy: string | null;
    }
  | {
      readonly status: 'verified';
      readonly userId: string;
      readonly verifiedAt: number;
      /** The stored `operator_verified_by`: `operator_cli` or `operator_cli:<os user>`. */
      readonly verifiedBy: string;
    };

/** Any drizzle node-postgres database, whatever schema generic it was built with. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type OperatorDb = NodePgDatabase<any>;

/** Whether `name` can be recorded as the operating-system user. */
function recordable(name: string): boolean {
  try {
    operatorVerifiedBy({ method: 'operator_cli', osUser: name });
    return true;
  } catch {
    return false;
  }
}

/**
 * The operating-system user running the command, as the verification and its
 * event record it; `null` when the process has no user entry (a container
 * without one), or a name of 1 to {@link OPERATOR_CLI_USER_MAX_LENGTH}
 * characters without a control character cannot be read, so the record names
 * the command alone.
 */
export function commandOperator(): string | null {
  try {
    const name = userInfo().username;
    return recordable(name) ? name : null;
  } catch {
    return null;
  }
}

/**
 * Verify the account, as the operator `operator` (the operating-system user,
 * or `null`), and record the `user.verified` event, in one transaction. The
 * account row is locked first, so a concurrent run, or a `users.verify` of
 * the admin API, waits for this one and then finds it verified.
 */
export async function verifyAccount(
  db: OperatorDb,
  args: AccountVerificationArgs,
  operator: string | null
): Promise<AccountVerificationResult> {
  const verifiedBy = operatorVerifiedBy({ method: 'operator_cli', osUser: operator });
  return db.transaction(async (tx) => {
    const [realm] = await tx
      .select({ id: realms.id })
      .from(realms)
      .where(eq(realms.name, args.realm))
      .limit(1);
    if (!realm) return { status: 'realm_not_found' as const };

    const [user] = await tx
      .select({
        id: users.id,
        enabled: users.enabled,
        operatorVerifiedAt: users.operatorVerifiedAt,
        operatorVerifiedBy: users.operatorVerifiedBy,
      })
      .from(users)
      .where(and(eq(users.realmId, realm.id), eq(users.id, args.userId)))
      .limit(1)
      .for('update');
    if (!user) return { status: 'user_not_found' as const };
    if (!user.enabled) return { status: 'disabled' as const, userId: user.id };
    if (user.operatorVerifiedAt !== null) {
      return {
        status: 'already_verified' as const,
        userId: user.id,
        verifiedAt: user.operatorVerifiedAt,
        verifiedBy: user.operatorVerifiedBy,
      };
    }

    const now = Date.now();
    const [updated] = await tx
      .update(users)
      .set({ operatorVerifiedAt: now, operatorVerifiedBy: verifiedBy, updatedAt: now })
      .where(and(eq(users.id, user.id), eq(users.enabled, true), isNull(users.operatorVerifiedAt)))
      .returning({ id: users.id, operatorVerifiedAt: users.operatorVerifiedAt });
    // The row is locked: what was read is what the update met.
    if (!updated || updated.operatorVerifiedAt === null) {
      throw new Error('The account changed under its lock');
    }

    // The event commits with the verification. The tool's database handle
    // has a schema generic of its own; at run time it is the same
    // node-postgres database and transaction the repository takes.
    await createEventsRepository(db as unknown as Database).emit(tx as unknown as DbTransaction, {
      type: 'urn:qauth:event:user.verified:v1-rc.0',
      realm: realm.id,
      actor: { type: 'operator_cli', ...(operator === null ? {} : { id: operator }) },
      subject: { type: 'user', id: user.id },
      data: { method: 'operator_cli' },
    });

    return {
      status: 'verified' as const,
      userId: updated.id,
      verifiedAt: updated.operatorVerifiedAt,
      verifiedBy,
    };
  });
}

/**
 * {@link verifyAccount} on the database at `connectionString`, over one
 * connection that is closed again.
 */
export async function verifyAccountAt(
  connectionString: string,
  args: AccountVerificationArgs,
  operator: string | null = commandOperator()
): Promise<AccountVerificationResult> {
  const pool = new Pool({
    connectionString,
    max: 1,
    connectionTimeoutMillis: 10_000,
    application_name: 'qauth-migration-runner',
  });
  try {
    return await verifyAccount(drizzle(pool), args, operator);
  } finally {
    await pool.end().catch(() => undefined);
  }
}

/** One line on what {@link verifyAccount} did, for the command's output. */
export function describeAccountVerificationResult(
  result: AccountVerificationResult,
  args: AccountVerificationArgs
): string {
  switch (result.status) {
    case 'realm_not_found':
      return `No realm is named ${JSON.stringify(args.realm)}. Nothing was changed.`;
    case 'user_not_found':
      return `The realm ${JSON.stringify(args.realm)} holds no account ${args.userId}. Nothing was changed.`;
    case 'disabled':
      return `The account ${result.userId} is disabled: enable it before verifying it. Nothing was changed.`;
    case 'already_verified':
      return (
        `An operator already verified the account ${result.userId} at ` +
        `${new Date(result.verifiedAt).toISOString()} (${result.verifiedBy ?? 'unknown'}). ` +
        'That verification is kept; nothing was changed.'
      );
    case 'verified':
      return (
        `Verified the account ${result.userId} as ${result.verifiedBy}, and recorded the ` +
        'user.verified event. It counts as verified for sign-in and for owning an agent; ' +
        'email_verified is unchanged.'
      );
  }
}
