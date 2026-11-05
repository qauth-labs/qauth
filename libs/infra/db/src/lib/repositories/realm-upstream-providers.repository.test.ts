import { drizzle } from 'drizzle-orm/node-postgres';
import type { Pool } from 'pg';
import { describe, expect, it } from 'vitest';

import type { DbClient } from '../db';
import { createRealmUpstreamProvidersRepository } from './realm-upstream-providers.repository';

/**
 * The statements of the upstream provider repository (#639), against a
 * recording client. The behaviour on a real database is held by
 * `realm-upstream-providers.integration.test.ts`.
 */

interface CapturedQuery {
  readonly text: string;
  readonly values: readonly unknown[];
}

/** A `pg` client that records its queries and answers each with `rows`. */
function createRecordingDb(rows: unknown[][] = []): { db: DbClient; queries: CapturedQuery[] } {
  const queries: CapturedQuery[] = [];
  const client = {
    query: (config: { text?: string; values?: unknown[] } | string, values?: unknown[]) => {
      const text = typeof config === 'string' ? config : (config.text ?? '');
      const params = typeof config === 'string' ? (values ?? []) : (config.values ?? values ?? []);
      queries.push({ text, values: params });
      const answer = rows.shift() ?? [];
      return Promise.resolve({
        rows: answer,
        rowCount: answer.length,
        fields: [],
        command: '',
        oid: 0,
      });
    },
  };
  return { db: drizzle(client as unknown as Pool) as unknown as DbClient, queries };
}

const REALM_ID = '0190f5a8-7c3e-7d10-8a4b-3c2d1e0f9a8b';

describe('realmUpstreamProviders (#639)', () => {
  it('lists a realm by display order, then type', async () => {
    const { db, queries } = createRecordingDb();

    await createRealmUpstreamProvidersRepository(db).listByRealm(REALM_ID);

    expect(queries).toHaveLength(1);
    expect(queries[0].text).toMatch(/"realm_id" = \$1/);
    expect(queries[0].text).toMatch(
      /order by "realm_upstream_providers"."display_order" asc, "realm_upstream_providers"."type" asc/i
    );
  });

  it('stamps updated_at on an update, and filters it on the realm and the type', async () => {
    const { db, queries } = createRecordingDb();

    await createRealmUpstreamProvidersRepository(db).update(REALM_ID, 'oidc_corp', {
      enabled: false,
    });

    expect(queries[0].text).toMatch(/^update "realm_upstream_providers" set .*"updated_at" = /i);
    expect(queries[0].text).toMatch(
      /"realm_id" = \$\d+ and "realm_upstream_providers"\."type" = /i
    );
    expect(queries[0].values).toContain(REALM_ID);
    expect(queries[0].values).toContain('oidc_corp');
  });

  it('answers a realm id that is not a UUID without a statement', async () => {
    const { db, queries } = createRecordingDb();
    const repo = createRealmUpstreamProvidersRepository(db);

    await expect(repo.listByRealm('nope')).resolves.toEqual([]);
    await expect(repo.find('nope', 'oidc_corp')).resolves.toBeUndefined();
    await expect(repo.update('nope', 'oidc_corp', { enabled: false })).resolves.toBeUndefined();
    await expect(repo.delete('nope', 'oidc_corp')).resolves.toBe(false);

    expect(queries).toEqual([]);
  });

  it('says whether a delete removed a row', async () => {
    const { db } = createRecordingDb([[{ id: 'x' }], []]);
    const repo = createRealmUpstreamProvidersRepository(db);

    await expect(repo.delete(REALM_ID, 'oidc_corp')).resolves.toBe(true);
    await expect(repo.delete(REALM_ID, 'oidc_corp')).resolves.toBe(false);
  });
});
