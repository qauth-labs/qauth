/**
 * Operator suspension of an OAuth client (ANT-2026-DR5XI3LV).
 *
 * `oauth_clients.enabled` is the client OWNER's switch: `PATCH /api/clients/:id`
 * may set it either way. An operator who must keep a client off uses
 * `oauth_clients.suspended` instead, which no route writes and the owner can
 * therefore never undo. A suspended client is refused wherever a disabled one
 * is.
 *
 * A suspension cuts the client off for good, as disabling an account does
 * (#893): in its transaction it revokes every refresh token the client holds
 * and spends its unredeemed authorization codes, so lifting it brings none of
 * them back. Lifting it revokes them as well, should any be left: those a
 * suspension by hand or one made before #893 did not reach, or a code minted
 * while the suspension's transaction was open. A suspended client obtains
 * nothing, so whatever is still live when its suspension lifts dates from
 * before it.
 *
 * QAuth has no operator role or operator API (ADR-012 §4), so this is operator
 * tooling that talks to the database directly, like `seed-oauth-clients.ts`.
 * The logic lives here, apart from the CLI in `suspend-oauth-client.ts`, so it
 * can be tested without running the script.
 */
import { userInfo } from 'node:os';

import { and, eq, sql } from 'drizzle-orm';
import type { NodePgDatabase } from 'drizzle-orm/node-postgres';

import { createAuthorizationCodesRepository } from '../lib/repositories/authorization-codes.repository';
import { createEventsRepository } from '../lib/repositories/events.repository';
import { createRefreshTokensRepository } from '../lib/repositories/refresh-tokens.repository';
import { oauthClients, realms } from '../lib/schema/core';
import type { Database, DbTransaction } from '../types';

export interface SuspensionArgs {
  realm: string;
  clientId: string;
  /** `true` to suspend, `false` to lift a suspension. */
  suspend: boolean;
}

export const SUSPENSION_USAGE =
  'Usage: suspend-oauth-client.ts --realm=<realm name> --client-id=<client_id> [--lift]\n' +
  '       Suspends the client, or with --lift ends its suspension.\n' +
  '       Set DATABASE_URL in the environment.';

/**
 * Parse `--realm=<name> --client-id=<id> [--lift]` from `process.argv`.
 * Returns null when a required argument is missing or an unknown flag is
 * given, so the caller prints the usage instead of guessing.
 */
export function parseSuspensionArgs(argv: readonly string[]): SuspensionArgs | null {
  let realm: string | undefined;
  let clientId: string | undefined;
  let suspend = true;
  for (const arg of argv.slice(2)) {
    if (arg.startsWith('--realm=')) realm = arg.slice('--realm='.length);
    else if (arg.startsWith('--client-id=')) clientId = arg.slice('--client-id='.length);
    else if (arg === '--lift') suspend = false;
    else return null;
  }
  if (!realm || !clientId) return null;
  return { realm, clientId, suspend };
}

/** What the client is, after a run that found it. */
interface SuspensionState {
  id: string;
  clientId: string;
  suspended: boolean;
  /** The owner's switch, unchanged by this tool. */
  enabled: boolean;
}

export type SuspensionResult =
  | { status: 'realm_not_found' }
  | { status: 'client_not_found' }
  | ({ status: 'unchanged' } & SuspensionState)
  | ({
      status: 'suspended' | 'lifted';
      /**
       * How many refresh tokens of the client the run revoked: on a lift,
       * those left from before the suspension.
       */
      revokedTokens: number;
    } & SuspensionState);

/**
 * The `revoked_reason` of the refresh tokens a suspension revokes (#893).
 * The admin API's `clients.disable` writes the same.
 */
export const SUSPENDED_CLIENT_REVOKE_REASON = 'client_suspended';

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
 * Suspend a client, or lift its suspension, and record it as an event
 * (`client.suspended` or `client.suspension_lifted`, actor `operator_cli`), in
 * one transaction. Idempotent: a client already in the requested state is
 * reported `unchanged` and nothing is written. `enabled` is never touched.
 * A suspension, and the lift of one, also revokes the client's refresh tokens
 * and spends its unredeemed codes, in the same transaction.
 *
 * Since #458 nothing writes `audit_logs`; the event store holds the record.
 */
export async function setClientSuspension(
  db: OperatorDb,
  args: SuspensionArgs
): Promise<SuspensionResult> {
  return db.transaction(async (tx): Promise<SuspensionResult> => {
    const [realm] = await tx
      .select({ id: realms.id })
      .from(realms)
      .where(eq(realms.name, args.realm))
      .limit(1);
    if (!realm) return { status: 'realm_not_found' as const };

    // FOR NO KEY UPDATE: a concurrent run for the same client waits for this
    // one, so the state it reports and the event it writes cannot interleave.
    // Not FOR UPDATE: revoking the client's tokens waits for the client's
    // token lock, which an insert of a token holds shared while its foreign
    // key takes a key-share lock on this row (#631, `revokeAllForClient`).
    const [client] = await tx
      .select({
        id: oauthClients.id,
        clientId: oauthClients.clientId,
        suspended: oauthClients.suspended,
        enabled: oauthClients.enabled,
      })
      .from(oauthClients)
      .where(and(eq(oauthClients.realmId, realm.id), eq(oauthClients.clientId, args.clientId)))
      .limit(1)
      .for('no key update');
    if (!client) return { status: 'client_not_found' as const };

    if (client.suspended === args.suspend) {
      return { status: 'unchanged' as const, ...client };
    }

    const [updated] = await tx
      .update(oauthClients)
      .set({
        suspended: args.suspend,
        suspendedAt: args.suspend ? sql`(EXTRACT(EPOCH FROM now()) * 1000)::bigint` : null,
        updatedAt: sql`(EXTRACT(EPOCH FROM now()) * 1000)::bigint`,
      })
      .where(eq(oauthClients.id, client.id))
      .returning({
        id: oauthClients.id,
        clientId: oauthClients.clientId,
        suspended: oauthClients.suspended,
        enabled: oauthClients.enabled,
      });

    // The event commits with the change. The tool's database handle has a
    // schema generic of its own; at run time it is the same node-postgres
    // database and transaction the repository takes.
    const operator = operatorUser();
    const database = db as unknown as Database;
    const t = tx as unknown as DbTransaction;

    // What the client holds ends with the suspension (#893), and what is
    // left of it when the suspension lifts, so a lift brings none back:
    // codes first, so none redeemed meanwhile opens a family the revocation
    // misses. Before the event: recording it takes the realm's chain lock,
    // which an admin API write takes last, after the rows it changes, so
    // taking it first could deadlock against one holding a code or token of
    // this client.
    await createAuthorizationCodesRepository(database).invalidateForClient(client.id, t);
    const revokedTokens = await createRefreshTokensRepository(database).revokeAllForClient(
      client.id,
      SUSPENDED_CLIENT_REVOKE_REASON,
      t
    );
    await createEventsRepository(database).emit(t, {
      type: args.suspend
        ? 'urn:qauth:event:client.suspended:v1-rc.0'
        : 'urn:qauth:event:client.suspension_lifted:v1-rc.0',
      realm: realm.id,
      actor: { type: 'operator_cli', ...(operator === undefined ? {} : { id: operator }) },
      subject: { type: 'client', id: client.clientId },
      client: { id: client.clientId },
      data: {},
    });
    return {
      status: args.suspend ? ('suspended' as const) : ('lifted' as const),
      ...updated,
      revokedTokens,
    };
  });
}
