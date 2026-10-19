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
import { and, eq, sql } from 'drizzle-orm';
import type { NodePgDatabase } from 'drizzle-orm/node-postgres';

import { auditLogs } from '../lib/schema/audit';
import { oauthClients, realms } from '../lib/schema/core';

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
 * Suspend a client, or lift its suspension, and record it in `audit_logs`, in
 * one transaction. Idempotent: a client already in the requested state is
 * reported `unchanged` and nothing is written. `enabled` is never touched.
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
    // the state it reports and the audit row it writes cannot interleave.
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

    await tx.insert(auditLogs).values({
      userId: null,
      oauthClientId: client.id,
      event: args.suspend ? 'oauth.client.suspended' : 'oauth.client.suspension_lifted',
      eventType: 'client',
      success: true,
      metadata: { clientId: client.clientId, by: 'operator', tool: 'db:suspend-oauth-client' },
    });

    return { status: args.suspend ? ('suspended' as const) : ('lifted' as const), ...updated };
  });
}
