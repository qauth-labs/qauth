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

describe('createRealmsRepository — sso_max_lifespan (#552)', () => {
  const MESSAGE =
    'Realm sso_max_lifespan must be a positive whole number of seconds, or null for no limit';

  it.each([0, -1, -3600, 1.5])('refuses %s seconds before the database sees it', async (value) => {
    const { db, queries } = createRecordingDb();
    const realms = createRealmsRepository(db);
    const id = '0192e000-0000-7000-8000-000000000001';

    await expect(realms.update(id, { ssoMaxLifespan: value })).rejects.toThrow(
      new BadRequestError(MESSAGE)
    );
    await expect(realms.create({ name: 'zero', ssoMaxLifespan: value })).rejects.toThrow(MESSAGE);
    await expect(
      realms.createWithPrimaryHost(
        { name: 'zero', issuer: 'https://zero.example.com', ssoMaxLifespan: value },
        'zero.example.com'
      )
    ).rejects.toThrow(MESSAGE);
    expect(queries).toEqual([]);
  });

  it('accepts a positive limit and null, which means no limit', async () => {
    const { db, queries } = createRecordingDb();
    const realms = createRealmsRepository(db);
    const id = '0192e000-0000-7000-8000-000000000001';

    // Both pass the check and reach the database, which has no such realm here.
    await expect(realms.update(id, { ssoMaxLifespan: 3600 })).rejects.toThrow('not found');
    await expect(realms.update(id, { ssoMaxLifespan: null })).rejects.toThrow('not found');
    expect(queries).toHaveLength(2);
  });
});

describe('createRealmsRepository — dynamic registration allowlist (#507)', () => {
  it.each([
    ['openid', 'qauth:admin:read'],
    ['qauth:admin:security'],
    ['openid', 'QAuth:Admin:Write'],
  ])('refuses %j before the database sees it', async (...scopes) => {
    const { db, queries } = createRecordingDb();
    const realms = createRealmsRepository(db);
    const id = '0192e000-0000-7000-8000-000000000001';
    const message =
      /^Realm dynamic_registration_allowed_scopes must not hold a scope in the "qauth:" namespace/;

    await expect(realms.update(id, { dynamicRegistrationAllowedScopes: scopes })).rejects.toThrow(
      BadRequestError
    );
    await expect(
      realms.create({ name: 'admin', dynamicRegistrationAllowedScopes: scopes })
    ).rejects.toThrow(message);
    await expect(
      realms.createWithPrimaryHost(
        {
          name: 'admin',
          issuer: 'https://admin.example.com',
          dynamicRegistrationAllowedScopes: scopes,
        },
        'admin.example.com'
      )
    ).rejects.toThrow(message);
    expect(queries).toEqual([]);
  });

  // Other servers' admin: scopes are ordinary scopes.
  it('accepts admin: scopes and scopes that only contain "qauth"', async () => {
    const { db, queries } = createRecordingDb();
    const realms = createRealmsRepository(db);
    const id = '0192e000-0000-7000-8000-000000000001';

    // It passes the check and reaches the database, which has no such realm here.
    await expect(
      realms.update(id, {
        dynamicRegistrationAllowedScopes: ['openid', 'admin:read', 'admin:org', 'example:qauth'],
      })
    ).rejects.toThrow('not found');
    expect(queries).toHaveLength(1);
  });
});

describe('createRealmsRepository — sso_idle_timeout (#552)', () => {
  const MESSAGE =
    'Realm sso_idle_timeout must be a positive whole number of seconds, or null for no limit';

  it.each([0, -1, -900, 2.5])('refuses %s seconds before the database sees it', async (value) => {
    const { db, queries } = createRecordingDb();
    const realms = createRealmsRepository(db);
    const id = '0192e000-0000-7000-8000-000000000001';

    await expect(realms.update(id, { ssoIdleTimeout: value })).rejects.toThrow(
      new BadRequestError(MESSAGE)
    );
    await expect(realms.create({ name: 'zero', ssoIdleTimeout: value })).rejects.toThrow(MESSAGE);
    await expect(
      realms.createWithPrimaryHost(
        { name: 'zero', issuer: 'https://zero.example.com', ssoIdleTimeout: value },
        'zero.example.com'
      )
    ).rejects.toThrow(MESSAGE);
    expect(queries).toEqual([]);
  });

  it('accepts a positive timeout and null, which means no limit', async () => {
    const { db, queries } = createRecordingDb();
    const realms = createRealmsRepository(db);
    const id = '0192e000-0000-7000-8000-000000000001';

    await expect(realms.update(id, { ssoIdleTimeout: 1800 })).rejects.toThrow('not found');
    await expect(realms.update(id, { ssoIdleTimeout: null })).rejects.toThrow('not found');
    expect(queries).toHaveLength(2);
  });
});
