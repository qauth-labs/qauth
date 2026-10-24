/**
 * Operator suspension of an OAuth client (ANT-2026-DR5XI3LV).
 *
 * `oauth_clients.enabled` is the client OWNER's switch: `PATCH /api/clients/:id`
 * may set it either way. An operator who must keep a client off uses
 * `oauth_clients.suspended` instead, which no route writes and the owner can
 * therefore never undo. A suspended client is refused wherever a disabled one
 * is.
 *
 * QAuth has no operator role or operator API (ADR-012 §4), so this is operator
 * tooling that talks to the database directly, like `seed-oauth-clients.ts`.
 * The logic lives here, apart from the CLI in `suspend-oauth-client.ts`, so it
 * can be tested without running the script.
 */
import { userInfo } from 'node:os';

import { and, eq, sql } from 'drizzle-orm';
import type { NodePgDatabase } from 'drizzle-orm/node-postgres';

import { createEventsRepository } from '../lib/repositories/events.repository';
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

export type SuspensionResult =
  | { status: 'realm_not_found' }
  | { status: 'client_not_found' }
  | {
      status: 'suspended' | 'lifted' | 'unchanged';
      id: string;
      clientId: string;
      suspended: boolean;
      /** The owner's switch, unchanged by this tool. */
      enabled: boolean;
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
 * Suspend a client, or lift its suspension, and record it as an event
 * (`client.suspended` or `client.suspension_lifted`, actor `operator_cli`), in
 * one transaction. Idempotent: a client already in the requested state is
 * reported `unchanged` and nothing is written. `enabled` is never touched.
 *
 * Since #458 nothing writes `audit_logs`; the event store holds the record.
 */
export async function setClientSuspension(
  db: OperatorDb,
  args: SuspensionArgs
): Promise<SuspensionResult> {
  return db.transaction(async (tx) => {
    const [realm] = await tx
      .select({ id: realms.id })
      .from(realms)
      .where(eq(realms.name, args.realm))
      .limit(1);
    if (!realm) return { status: 'realm_not_found' as const };

    // FOR UPDATE: a concurrent run for the same client waits for this one, so
    // the state it reports and the event it writes cannot interleave.
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
      .for('update');
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
    await createEventsRepository(db as unknown as Database).emit(tx as unknown as DbTransaction, {
      type: args.suspend
        ? 'urn:qauth:event:client.suspended:v1-rc.0'
        : 'urn:qauth:event:client.suspension_lifted:v1-rc.0',
      realm: realm.id,
      actor: { type: 'operator_cli', ...(operator === undefined ? {} : { id: operator }) },
      subject: { type: 'client', id: client.clientId },
      client: { id: client.clientId },
      data: {},
    });

    return { status: args.suspend ? ('suspended' as const) : ('lifted' as const), ...updated };
  });
}
