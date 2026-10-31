/**
 * Operator grants for CIMD clients (#770).
 *
 * A CIMD client's metadata document owns its identity: every re-resolution
 * rewrites the row's name, redirect URIs, grant types and the rest from it
 * (ADR-012). It never rewrites `scopes` or `audience`, and a CIMD row starts
 * with no scopes, so which scopes the client may receive is the operator's
 * call. This writes that call, from the `cimd_clients` section of the seed
 * manifest, and nothing else.
 *
 * The logic lives here, apart from the CLI in `seed-oauth-clients.ts`, so it
 * can be tested without running the script.
 */
import { randomBytes } from 'node:crypto';

import { and, eq, sql } from 'drizzle-orm';
import type { NodePgDatabase } from 'drizzle-orm/node-postgres';

import { oauthClients } from '../lib/schema/core';
import type { CimdClientSpec } from './seed-manifest';

/**
 * - `created`: no row existed; one now waits for its first resolution.
 * - `updated`: the CIMD row's `scopes` or `audience` changed.
 * - `unchanged`: the CIMD row already held the entry's values.
 * - `not_cimd`: a row with this `client_id` exists and is not a CIMD row.
 *   Nothing was written.
 */
export type CimdGrantStatus = 'created' | 'updated' | 'unchanged' | 'not_cimd';

export interface CimdGrantResult {
  clientId: string;
  status: CimdGrantStatus;
}

/** Any drizzle node-postgres database, whatever schema generic it was built with. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type OperatorDb = NodePgDatabase<any>;

/**
 * A value for the NOT NULL `client_secret_hash` that no secret can match,
 * shaped like the auth server's own CIMD sentinel (`cimdSentinelSecretHash` in
 * `apps/auth-server/src/app/helpers/client-resolution.ts`). Re-resolution
 * never rewrites the column, so this is the value the row keeps.
 */
function unusableSecretHash(): string {
  const salt = randomBytes(16).toString('base64').replace(/=+$/, '');
  const digest = randomBytes(32).toString('base64').replace(/=+$/, '');
  return `$argon2id$v=19$m=65536,t=3,p=4$${salt}$${digest}`;
}

function sameValue(a: readonly string[] | null, b: readonly string[] | null): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

/**
 * The row the auth server would write for this CIMD client, before it has
 * read the document. The first resolution replaces every document field, so
 * the placeholders below never reach a client: `resolveClient` re-resolves a
 * CIMD row before any use, and an unreadable document leaves the client
 * unknown. Until then the row has no redirect URI to send a code to.
 */
function buildPendingCimdRow(
  realmId: string,
  spec: CimdClientSpec
): typeof oauthClients.$inferInsert {
  return {
    realmId,
    clientId: spec.client_id,
    clientSecretHash: unusableSecretHash(),
    name: spec.client_id,
    description: 'CIMD client (client_id metadata document)',
    redirectUris: [],
    grantTypes: ['authorization_code', 'refresh_token'],
    responseTypes: ['code'],
    tokenEndpointAuthMethod: 'none',
    requirePkce: true,
    enabled: true,
    developerId: null,
    // The redirect URIs will be the document's, not the operator's, so this
    // row does not receive authorization errors by redirect (ADR-012).
    provisionedByOperator: false,
    // ADR-019 Decision 6 (#593): a CIMD client's verified domain is the host
    // of its client id URL, never an operator-set one.
    verifiedDomain: null,
    isAgent: false,
    scopes: spec.scopes,
    audience: spec.audience ?? null,
    metadata: { registrationType: 'cimd', client_id_metadata_url: spec.client_id },
  };
}

/**
 * Converge one CIMD client's `scopes` and `audience` on a manifest entry, in
 * one transaction. Idempotent. Never touches another column of an existing
 * row, so `enabled`, `suspended` and the document's fields stay as they are.
 */
export async function applyCimdClientGrant(
  db: OperatorDb,
  realmId: string,
  spec: CimdClientSpec
): Promise<CimdGrantResult> {
  const audience = spec.audience ?? null;
  return db.transaction(async (tx) => {
    const [existing] = await tx
      .select({
        id: oauthClients.id,
        metadata: oauthClients.metadata,
        scopes: oauthClients.scopes,
        audience: oauthClients.audience,
      })
      .from(oauthClients)
      .where(and(eq(oauthClients.realmId, realmId), eq(oauthClients.clientId, spec.client_id)))
      .limit(1)
      .for('update');

    if (!existing) {
      await tx.insert(oauthClients).values(buildPendingCimdRow(realmId, spec));
      return { clientId: spec.client_id, status: 'created' as const };
    }

    // A pre-registered row wins over CIMD resolution and is never refreshed
    // from a document, so granting through this path would change what the
    // operator wrote for it. Refuse; it belongs in `clients`.
    if (existing.metadata?.['registrationType'] !== 'cimd') {
      return { clientId: spec.client_id, status: 'not_cimd' as const };
    }

    if (sameValue(existing.scopes, spec.scopes) && sameValue(existing.audience, audience)) {
      return { clientId: spec.client_id, status: 'unchanged' as const };
    }

    await tx
      .update(oauthClients)
      .set({
        scopes: spec.scopes,
        audience,
        updatedAt: sql`(EXTRACT(EPOCH FROM now()) * 1000)::bigint`,
      })
      .where(eq(oauthClients.id, existing.id));
    return { clientId: spec.client_id, status: 'updated' as const };
  });
}
