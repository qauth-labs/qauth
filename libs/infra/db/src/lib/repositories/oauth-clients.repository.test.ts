import { drizzle } from 'drizzle-orm/node-postgres';
import type { Pool } from 'pg';
import { describe, expect, it } from 'vitest';

import type { DbClient } from '../db';
import { createOAuthClientsRepository } from './oauth-clients.repository';

/**
 * SQL-shape tests for `upsertCimdClient`, so the property below is pinned on a
 * machine with no Docker daemon. The container-backed suite
 * (`repositories.integration.test.ts`) proves the behaviour against Postgres.
 */

interface CapturedQuery {
  readonly text: string;
  readonly values: readonly unknown[];
}

/** A `pg` client that records queries instead of running them. */
function createRecordingDb(): { db: DbClient; queries: CapturedQuery[] } {
  const queries: CapturedQuery[] = [];
  const client = {
    query: (config: { text?: string; values?: unknown[] } | string, values?: unknown[]) => {
      const text = typeof config === 'string' ? config : (config.text ?? '');
      const params = typeof config === 'string' ? (values ?? []) : (config.values ?? values ?? []);
      queries.push({ text, values: params });
      return Promise.resolve({ rows: [], rowCount: 0, fields: [], command: '', oid: 0 });
    },
  };
  return { db: drizzle(client as unknown as Pool) as unknown as DbClient, queries };
}

const CIMD_ROW = {
  realmId: '11111111-1111-1111-1111-111111111111',
  clientId: 'https://app.example.com/client.json',
  clientSecretHash: 'sentinel-hash',
  name: 'Example',
  redirectUris: ['https://app.example.com/cb'],
  tokenEndpointAuthMethod: 'none' as const,
  enabled: true,
};

// Regression (ANT-2026-SSI34ODQ): the resolver reads the row, fetches the
// client's own metadata document — for as long as the client's host makes it
// take — and only then upserts. The conflict set wrote `enabled` from that
// earlier read, so an operator's `enabled = false` committed during the fetch
// was overwritten with the stale `true`.
describe('createOAuthClientsRepository.upsertCimdClient', () => {
  it('can only narrow `enabled` on conflict: the live row AND the new value', async () => {
    const { db, queries } = createRecordingDb();

    await createOAuthClientsRepository(db).upsertCimdClient(CIMD_ROW);

    expect(queries).toHaveLength(1);
    const sql = queries[0].text.toLowerCase();
    const conflictSet = sql.slice(sql.indexOf('on conflict'), sql.indexOf('returning'));
    expect(conflictSet).toContain('"enabled" = "oauth_clients"."enabled" and excluded.enabled');
  });
});
