import { BadRequestError } from '@qauth-labs/shared-errors';
import { drizzle } from 'drizzle-orm/node-postgres';
import type { Pool } from 'pg';
import { describe, expect, it } from 'vitest';

import type { DbClient } from '../db';
import { createRealmsRepository } from './realms.repository';

/**
 * The realm policy seeds and the event retention limits (#536, ADR-019
 * Decision 10): a new realm gets the environment's seeds for the policies
 * its creator leaves out, and no create or update keeps admin events fewer
 * than 90 days. A refused value never reaches PostgreSQL.
 */

interface CapturedQuery {
  readonly text: string;
  readonly values: readonly unknown[];
}

/** A `pg` client that records queries and answers each with no row. */
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

/** The value an INSERT into `realms` bound for one column. */
function insertedValue(query: CapturedQuery, column: string): unknown {
  const columns = /insert into "realms" \(([^)]*)\)/.exec(query.text)?.[1];
  if (columns === undefined) throw new Error(`not an insert into realms: ${query.text}`);
  const names = columns.split(', ').map((name) => name.replaceAll('"', ''));
  const values = /values \(([^)]*)\)/.exec(query.text)?.[1].split(', ') ?? [];
  const placeholder = values[names.indexOf(column)];
  if (placeholder === 'default') return 'default';
  return query.values[Number(placeholder?.slice(1)) - 1];
}

describe('createRealmsRepository — event retention (#536)', () => {
  it('seeds a new realm with the retention the environment sets', async () => {
    const { db, queries } = createRecordingDb();
    const realms = createRealmsRepository(db, {
      seeds: { userEventRetentionDays: 30, adminEventRetentionDays: 400 },
    });

    await realms.create({ name: 'seeded' });

    expect(insertedValue(queries[0], 'user_event_retention_days')).toBe(30);
    expect(insertedValue(queries[0], 'admin_event_retention_days')).toBe(400);
  });

  it('lets the creator set a policy the seeds would fill', async () => {
    const { db, queries } = createRecordingDb();
    const realms = createRealmsRepository(db, {
      seeds: { userEventRetentionDays: 30, adminEventRetentionDays: 400 },
    });

    await realms.create({ name: 'own', adminEventRetentionDays: 120 });

    expect(insertedValue(queries[0], 'user_event_retention_days')).toBe(30);
    expect(insertedValue(queries[0], 'admin_event_retention_days')).toBe(120);
  });

  it('leaves the column defaults to a realm without seeds', async () => {
    const { db, queries } = createRecordingDb();

    await createRealmsRepository(db).create({ name: 'plain' });

    expect(insertedValue(queries[0], 'user_event_retention_days')).toBe('default');
    expect(insertedValue(queries[0], 'admin_event_retention_days')).toBe('default');
  });

  it('refuses an admin retention of 89 days and accepts 90', async () => {
    const { db, queries } = createRecordingDb();
    const realms = createRealmsRepository(db);
    const id = '0192e000-0000-7000-8000-000000000001';

    await expect(realms.update(id, { adminEventRetentionDays: 89 })).rejects.toThrow(
      new BadRequestError(
        'Realm event retention is out of range: adminEventRetentionDays: must be at least 90 days'
      )
    );
    await expect(realms.create({ name: 'short', adminEventRetentionDays: 89 })).rejects.toThrow(
      BadRequestError
    );
    await expect(
      realms.createWithPrimaryHost(
        { name: 'short', issuer: 'https://short.example.com', adminEventRetentionDays: 89 },
        'short.example.com'
      )
    ).rejects.toThrow(BadRequestError);
    expect(queries).toEqual([]);

    // 90 days passes the check and reaches the database, which has no such realm here.
    await expect(realms.update(id, { adminEventRetentionDays: 90 })).rejects.toThrow('not found');
    expect(queries).toHaveLength(1);
  });

  it('refuses seeds out of range when the repository is made', () => {
    const { db } = createRecordingDb();
    expect(() => createRealmsRepository(db, { seeds: { adminEventRetentionDays: 89 } })).toThrow(
      'createRealmsRepository: adminEventRetentionDays: must be at least 90 days'
    );
    expect(() => createRealmsRepository(db, { seeds: { userEventRetentionDays: 0 } })).toThrow(
      TypeError
    );
  });
});
