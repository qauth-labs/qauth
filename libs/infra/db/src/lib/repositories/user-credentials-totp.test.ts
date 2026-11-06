import { drizzle } from 'drizzle-orm/node-postgres';
import type { Pool } from 'pg';
import { describe, expect, it } from 'vitest';

import type { DbClient } from '../db';
import { createUserCredentialsRepository } from './user-credentials.repository';

/**
 * The TOTP writes of `user_credentials` (#653), by the statements they send:
 * a time step is taken by one conditional UPDATE, and a binding is one
 * INSERT that rewrites only the account's own row. Their behaviour against
 * PostgreSQL is in `identity-repositories.integration.test.ts`.
 */

interface CapturedQuery {
  readonly text: string;
  readonly values: readonly unknown[];
}

function createRecordingDb(rows: unknown[] = []): { db: DbClient; queries: CapturedQuery[] } {
  const queries: CapturedQuery[] = [];
  const client = {
    query: (config: { text?: string; values?: unknown[] } | string, values?: unknown[]) => {
      const text = typeof config === 'string' ? config : (config.text ?? '');
      const params = typeof config === 'string' ? (values ?? []) : (config.values ?? values ?? []);
      queries.push({ text, values: params });
      return Promise.resolve({ rows, rowCount: rows.length, fields: [], command: '', oid: 0 });
    },
  };
  return { db: drizzle(client as unknown as Pool) as unknown as DbClient, queries };
}

const REALM_ID = '0190f5a8-7c3e-7d10-8a4b-3c2d1e0f9a8b';
const USER_ID = '0190f5a8-7c3e-7d10-8a4b-3c2d1e0f0001';

describe('userCredentials.acceptTotpStep (#653)', () => {
  it('takes the step in one UPDATE of the enabled TOTP whose last step is lower', async () => {
    const { db, queries } = createRecordingDb();
    expect(await createUserCredentialsRepository(db).acceptTotpStep(REALM_ID, USER_ID, 42)).toBe(
      false
    );
    expect(queries).toHaveLength(1);
    const [query] = queries;
    expect(query.text).toMatch(/^update "user_credentials"/);
    expect(query.text).toContain('"disabled_at" is null');
    expect(query.text).toContain(
      `jsonb_typeof("user_credentials"."credential_data" -> 'last_step') = 'number'`
    );
    expect(query.text).toMatch(/::numeric < \$\d+::numeric/);
    expect(query.values).toEqual(expect.arrayContaining([REALM_ID, 'totp', USER_ID, 42]));
  });

  it('reports a taken step only when a row changed', async () => {
    const { db } = createRecordingDb([{ id: 'credential' }]);
    expect(await createUserCredentialsRepository(db).acceptTotpStep(REALM_ID, USER_ID, 42)).toBe(
      true
    );
  });

  it('sends nothing for a step that cannot be one', async () => {
    const { db, queries } = createRecordingDb([{ id: 'credential' }]);
    const repository = createUserCredentialsRepository(db);
    for (const step of [-1, 1.5, Number.NaN, Number.MAX_SAFE_INTEGER + 1]) {
      expect(await repository.acceptTotpStep(REALM_ID, USER_ID, step)).toBe(false);
    }
    expect(queries).toEqual([]);
  });
});

describe('userCredentials.upsertTotp (#653)', () => {
  it("inserts the account's TOTP, or rewrites only the account's own row and clears its mark", async () => {
    const { db, queries } = createRecordingDb();
    await createUserCredentialsRepository(db).upsertTotp({
      realmId: REALM_ID,
      userId: USER_ID,
      credentialData: { secret: 'v1.k.iv.ct', last_step: 7 },
      at: 1_800_000_000_000,
    });
    expect(queries).toHaveLength(1);
    const [query] = queries;
    expect(query.text).toMatch(/^insert into "user_credentials"/);
    expect(query.text).toContain(
      'on conflict ("realm_id","provider_type","external_sub") do update set'
    );
    expect(query.text).toContain('"credential_data" = excluded.credential_data');
    const mark = /do update set .*"disabled_at" = \$(\d+)/.exec(query.text);
    expect(mark).not.toBeNull();
    expect(query.values[Number(mark?.[1]) - 1]).toBeNull();
    expect(query.text).toMatch(/where "user_credentials"\."user_id" = \$\d+/);
    expect(query.values).toEqual(expect.arrayContaining([REALM_ID, 'totp', USER_ID]));
  });
});
