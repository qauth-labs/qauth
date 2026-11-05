import { NotFoundError } from '@qauth-labs/shared-errors';
import { drizzle } from 'drizzle-orm/node-postgres';
import type { Pool } from 'pg';
import { describe, expect, it } from 'vitest';

import type { DbClient } from '../db';
import { createUserRequiredActionsRepository } from './user-required-actions.repository';

/**
 * The statements of the required-actions repository (#635), against a
 * recording client. The behaviour on a real database is held by
 * `user-required-actions.integration.test.ts`.
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
const USER_ID = '0190f5a8-7c3e-7d10-8a4b-3c2d1e0f0001';
const INPUT = {
  realmId: REALM_ID,
  userId: USER_ID,
  action: 'update_password',
  source: 'admin',
} as const;

describe('userRequiredActions.add (#635)', () => {
  it('refuses a user the realm does not have, and writes nothing', async () => {
    const { db, queries } = createRecordingDb();

    await expect(createUserRequiredActionsRepository(db).add(INPUT)).rejects.toBeInstanceOf(
      NotFoundError
    );

    expect(queries).toHaveLength(1);
    expect(queries[0].text).toMatch(/^select /i);
  });

  it('keeps a row that is already there, and says it wrote nothing', async () => {
    // The user exists; the insert returns no row, as ON CONFLICT DO NOTHING does.
    const { db, queries } = createRecordingDb([[{ id: USER_ID }], []]);

    await expect(createUserRequiredActionsRepository(db).add(INPUT)).resolves.toBe(false);

    expect(queries[1].text).toMatch(/^insert into "user_required_actions"/i);
    expect(queries[1].text).toMatch(/on conflict \("user_id",\s*"action"\) do nothing/i);
    expect(queries[1].text).not.toMatch(/do update/i);
  });

  it('says it wrote a row when the insert returns one', async () => {
    const { db } = createRecordingDb([[{ id: USER_ID }], [{ id: 'row' }]]);

    await expect(createUserRequiredActionsRepository(db).add(INPUT)).resolves.toBe(true);
  });
});

describe('userRequiredActions.listForUser (#635)', () => {
  it('reads one user in one realm, oldest first', async () => {
    const { db, queries } = createRecordingDb();

    await createUserRequiredActionsRepository(db).listForUser(REALM_ID, USER_ID);

    expect(queries[0].text).toMatch(/order by "user_required_actions"."created_at" asc/i);
    expect(queries[0].values).toEqual([REALM_ID, USER_ID]);
  });
});

describe('userRequiredActions.remove (#635)', () => {
  it('says whether a row was deleted', async () => {
    const none = createRecordingDb();
    await expect(
      createUserRequiredActionsRepository(none.db).remove(REALM_ID, USER_ID, 'update_password')
    ).resolves.toBe(false);

    const one = createRecordingDb([[{ id: 'row' }]]);
    await expect(
      createUserRequiredActionsRepository(one.db).remove(REALM_ID, USER_ID, 'update_password')
    ).resolves.toBe(true);
    expect(one.queries[0].values).toEqual([REALM_ID, USER_ID, 'update_password']);
  });
});
