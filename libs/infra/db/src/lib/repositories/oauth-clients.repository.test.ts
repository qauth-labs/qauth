import { drizzle } from 'drizzle-orm/node-postgres';
import type { Pool } from 'pg';
import { describe, expect, it } from 'vitest';

import type { UpdateOAuthClient } from '../../types/repository';
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

  // Regression (ANT-2026-O8U3P920): only an operator-provisioned client gets
  // automatic error redirects. A CIMD document's host chooses its redirect
  // URIs, so neither a new row nor a refreshed one may carry the marker.
  it('never writes `provisioned_by_operator = true`, on insert or on conflict', async () => {
    const { db, queries } = createRecordingDb();

    await createOAuthClientsRepository(db).upsertCimdClient({
      ...CIMD_ROW,
      provisionedByOperator: true,
    });

    expect(queries).toHaveLength(1);
    const { text, values } = queries[0];
    const sql = text.toLowerCase();
    const conflictAt = sql.indexOf('on conflict');
    const conflictSet = sql.slice(conflictAt, sql.indexOf('returning'));
    const inConflict = /"provisioned_by_operator" = \$(\d+)/.exec(conflictSet);
    expect(inConflict).not.toBeNull();
    expect(values[Number(inConflict?.[1]) - 1]).toBe(false);

    // The INSERT column list and its VALUES tuple, in order.
    const columns = sql
      .slice(sql.indexOf('(') + 1, sql.indexOf(')'))
      .split(',')
      .map((c) => c.trim());
    const tuple = sql.slice(sql.indexOf('values (') + 'values ('.length, conflictAt);
    const placeholders = tuple
      .slice(0, tuple.indexOf(')'))
      .split(',')
      .map((p) => p.trim());
    const at = columns.indexOf('"provisioned_by_operator"');
    expect(at).toBeGreaterThanOrEqual(0);
    const placeholder = /^\$(\d+)$/.exec(placeholders[at]);
    expect(placeholder).not.toBeNull();
    expect(values[Number(placeholder?.[1]) - 1]).toBe(false);
  });

  // Regression (ANT-2026-DR5XI3LV): a suspension is operator state. The
  // statement must not name it at all, so a re-resolution can neither clear
  // it nor race an operator who is setting it.
  it('never names `suspended` or `suspended_at`', async () => {
    const { db, queries } = createRecordingDb();

    await createOAuthClientsRepository(db).upsertCimdClient(CIMD_ROW);

    const sql = queries[0].text.toLowerCase();
    const conflictAt = sql.indexOf('on conflict');
    const conflictSet = sql.slice(conflictAt, sql.indexOf('returning'));
    expect(conflictSet).not.toContain('"suspended"');
    expect(conflictSet).not.toContain('"suspended_at"');

    // On insert the columns take their defaults (false / NULL), never a value
    // the caller passed.
    const columns = sql
      .slice(sql.indexOf('(') + 1, sql.indexOf(')'))
      .split(',')
      .map((c) => c.trim());
    const tuple = sql.slice(sql.indexOf('values (') + 'values ('.length, conflictAt);
    const placeholders = tuple
      .slice(0, tuple.indexOf(')'))
      .split(',')
      .map((p) => p.trim());
    expect(placeholders[columns.indexOf('"suspended"')]).toBe('default');
    expect(placeholders[columns.indexOf('"suspended_at"')]).toBe('default');
  });
});

// ANT-2026-DR5XI3LV: application code writes clients through `update`, and
// `UpdateOAuthClient` has no `suspended` / `suspendedAt`, so no route can set
// or lift a suspension, even by mistake. Pinned at compile time.
describe('UpdateOAuthClient', () => {
  it('cannot carry a suspension', () => {
    // @ts-expect-error -- `suspended` is operator state, not an update field.
    const lift: UpdateOAuthClient = { suspended: false };
    // @ts-expect-error -- nor is the time it began.
    const clear: UpdateOAuthClient = { suspendedAt: null };
    const owner: UpdateOAuthClient = { enabled: true };
    expect([lift, clear, owner]).toHaveLength(3);
  });
});
