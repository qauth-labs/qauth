import { drizzle } from 'drizzle-orm/node-postgres';
import type { Pool } from 'pg';
import { describe, expect, it } from 'vitest';

import type { Database, EventRetentionBatchRequest } from '../../types';
import { encodeEventPosition } from '../events/position';
import { createEventRetentionRepository } from './event-retention.repository';

/**
 * A malformed retention request never reaches PostgreSQL (#536): the
 * container suite covers what the job deletes.
 */

const REALM = '0192e000-0000-7000-8000-000000000001';

/** A `pg` client that records queries instead of running them. */
function createRecordingDb(): { db: Database; queries: string[] } {
  const queries: string[] = [];
  const client = {
    query: (config: { text?: string } | string) => {
      queries.push(typeof config === 'string' ? config : (config.text ?? ''));
      return Promise.resolve({ rows: [], rowCount: 0, fields: [], command: '', oid: 0 });
    },
  };
  return { db: drizzle(client as unknown as Pool) as unknown as Database, queries };
}

function request(overrides: Partial<EventRetentionBatchRequest> = {}): EventRetentionBatchRequest {
  return {
    realmId: REALM,
    category: 'user',
    before: 1_800_000_000_000,
    through: encodeEventPosition({ realmId: REALM, xid: 10n, seq: 5n }),
    limit: 100,
    now: 1_800_000_000_000,
    ...overrides,
  };
}

describe('createEventRetentionRepository — refused requests', () => {
  it.each([
    ['a realm id that is not a UUID', { realmId: 'master' }],
    ['an unknown category', { category: 'system' as 'user' }],
    ['a time that is not epoch milliseconds', { before: 1.5 }],
    ['a negative clock', { now: -1 }],
    ['no row to delete', { limit: 0 }],
    ['more than 10000 rows', { limit: 10_001 }],
    [
      "another realm's position",
      {
        through: encodeEventPosition({
          realmId: '0192e000-0000-7000-8000-000000000002',
          xid: 10n,
          seq: 5n,
        }),
      },
    ],
  ])('deleteBatch refuses %s without querying', async (_label, overrides) => {
    const { db, queries } = createRecordingDb();
    await expect(
      createEventRetentionRepository(db).deleteBatch(request(overrides))
    ).rejects.toBeInstanceOf(TypeError);
    expect(queries).toEqual([]);
  });

  it('offeredThrough refuses a realm id that is not a UUID without querying', async () => {
    const { db, queries } = createRecordingDb();
    await expect(createEventRetentionRepository(db).offeredThrough('master')).rejects.toThrow(
      TypeError
    );
    expect(queries).toEqual([]);
  });

  it('realms refuses a fallback that keeps admin events fewer than 90 days', async () => {
    const { db, queries } = createRecordingDb();
    await expect(
      createEventRetentionRepository(db).realms({
        userEventRetentionDays: 90,
        adminEventRetentionDays: 89,
      })
    ).rejects.toThrow('adminEventRetentionDays: must be at least 90 days');
    expect(queries).toEqual([]);
  });
});
