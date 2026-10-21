import { NotFoundError } from '@qauth-labs/shared-errors';
import { drizzle } from 'drizzle-orm/node-postgres';
import type { Pool } from 'pg';
import { describe, expect, it } from 'vitest';

import type { DbClient } from '../db';
import { createUsersRepository } from './users.repository';

/**
 * A malformed id never reaches PostgreSQL (#754).
 *
 * `users.id` is a `uuid` column; PostgreSQL rejects any other shape as a query
 * parameter (22P02), which surfaced as a 500 when `/oauth/userinfo` looked up a
 * `client_credentials` token's `sub` (a `client_id`). These tests pin that the
 * id-keyed methods answer "no such user" without issuing a query.
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

const MALFORMED_IDS = [
  'reporting-service',
  'https://app.example.com/client.json',
  '',
  '0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11',
  "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11' OR '1'='1",
];

describe('createUsersRepository — malformed ids', () => {
  it.each(MALFORMED_IDS)('findById(%j) answers undefined without querying', async (id) => {
    const { db, queries } = createRecordingDb();

    await expect(createUsersRepository(db).findById(id)).resolves.toBeUndefined();

    expect(queries).toEqual([]);
  });

  it.each(MALFORMED_IDS)(
    'findByIdOrThrow(%j) throws NotFoundError without querying',
    async (id) => {
      const { db, queries } = createRecordingDb();

      await expect(createUsersRepository(db).findByIdOrThrow(id)).rejects.toBeInstanceOf(
        NotFoundError
      );

      expect(queries).toEqual([]);
    }
  );

  it('update, updateLastLogin and delete refuse a malformed id without querying', async () => {
    const { db, queries } = createRecordingDb();
    const users = createUsersRepository(db);

    await expect(users.update('reporting-service', { firstName: 'x' })).rejects.toBeInstanceOf(
      NotFoundError
    );
    await expect(users.updateLastLogin('reporting-service')).rejects.toBeInstanceOf(NotFoundError);
    await expect(users.delete('reporting-service')).resolves.toBe(false);

    expect(queries).toEqual([]);
  });

  it.each([
    // A uuidv7, as `users.id` defaults to.
    '019a0b9e-4c2f-7d31-9f6e-2b8c4d5e6f70',
    // Version and variant bits PostgreSQL accepts but RFC 9562 does not
    // define: such a row must stay reachable.
    '11111111-1111-1111-1111-111111111111',
    // PostgreSQL reads uuid input case-insensitively.
    'A0EEBC99-9C0B-4EF8-BB6D-6BB9BD380A11',
  ])('findById(%j) queries the users table', async (id) => {
    const { db, queries } = createRecordingDb();

    await createUsersRepository(db).findById(id);

    expect(queries).toHaveLength(1);
    expect(queries[0]?.text).toContain('from "users"');
    expect(queries[0]?.values).toContain(id);
  });
});
