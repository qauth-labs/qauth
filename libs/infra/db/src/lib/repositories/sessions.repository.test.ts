import { drizzle } from 'drizzle-orm/node-postgres';
import type { Pool } from 'pg';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { NewSession, SessionsRepository } from '../../types';
import type { DbClient } from '../db';
import { createSessionsRepository } from './sessions.repository';

/**
 * SQL-shape tests for the browser sessions repository (issue #468).
 *
 * ADR-019 Decision 1: every lookup by a session or user id also takes the
 * realm id. These tests run every method against a client that records the
 * SQL instead of executing it, so the rule is checked without Docker. The
 * container-backed suite (`sessions.integration.test.ts`) covers the
 * constraints and the index.
 */

interface CapturedQuery {
  readonly text: string;
  readonly values: readonly unknown[];
}

const REALM_ID = '0190a000-0000-7000-8000-000000000001';
const SESSION_ID = '0190a000-0000-7000-8000-0000000000aa';
const USER_ID = '0190a000-0000-7000-8000-0000000000bb';
const NOW = 1_800_000_000_000;

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

const NEW_SESSION: NewSession = {
  realmId: REALM_ID,
  userId: USER_ID,
  authTime: NOW - 5_000,
  amr: ['pwd'],
  assuranceLevel: null,
  ipAddress: '192.0.2.1',
  userAgent: 'test-agent',
  expiresAt: NOW + 86_400_000,
};

/**
 * One call per repository method. Typed over `keyof SessionsRepository`, so a
 * new method does not compile until it is listed here, and the test below
 * fails if the factory returns one this map does not know.
 */
const CALLS: Record<keyof SessionsRepository, (repo: SessionsRepository) => Promise<unknown>> = {
  create: (repo) => repo.create(NEW_SESSION),
  findById: (repo) => repo.findById(REALM_ID, SESSION_ID),
  updateLastSeen: (repo) => repo.updateLastSeen(REALM_ID, SESSION_ID, { minIntervalMs: 60_000 }),
  revoke: (repo) => repo.revoke(REALM_ID, SESSION_ID, 'sign_out'),
  listActiveForUser: (repo) => repo.listActiveForUser(REALM_ID, USER_ID),
};

async function run(method: keyof SessionsRepository): Promise<CapturedQuery> {
  const { db, queries } = createRecordingDb();
  await CALLS[method](createSessionsRepository(db));
  expect(queries).toHaveLength(1);
  return queries[0];
}

/**
 * Never called: it only has to compile. Each line passes a bare id where the
 * realm id belongs, and `typecheck` fails if any of them stops being an error.
 */
export function bareIdsDoNotCompile(repo: SessionsRepository): void {
  // @ts-expect-error a session id alone does not find a session
  void repo.findById(SESSION_ID);
  // @ts-expect-error a session id alone does not touch a session
  void repo.updateLastSeen(SESSION_ID);
  // @ts-expect-error a session id and a reason do not end a session
  void repo.revoke(SESSION_ID, 'sign_out');
  // @ts-expect-error a user id alone does not list sessions
  void repo.listActiveForUser(USER_ID);
}

describe('createSessionsRepository', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('exposes create, find by id, update last seen, revoke and list, and nothing else', () => {
    const { db } = createRecordingDb();
    const methods = Object.keys(createSessionsRepository(db)).sort();

    expect(methods).toEqual(Object.keys(CALLS).sort());
  });

  it.each(['findById', 'updateLastSeen', 'revoke'] as const)(
    '%s names the session by realm and id together',
    async (method) => {
      const query = await run(method);
      const text = query.text.toLowerCase();

      expect(text).toContain('where ("sessions"."realm_id" = $');
      expect(text).toMatch(/"sessions"\."realm_id" = \$\d+ and "sessions"\."id" = \$\d+/);
      expect(query.values).toEqual(expect.arrayContaining([REALM_ID, SESSION_ID]));
    }
  );

  it('create takes the realm from the input and writes it', async () => {
    const query = await run('create');

    expect(query.text.toLowerCase()).toContain('insert into "sessions"');
    expect(query.values).toContain(REALM_ID);
    expect(query.values).toContain(USER_ID);
  });

  it('create leaves the id to the database and starts the session live', async () => {
    const { db, queries } = createRecordingDb();
    const smuggled = {
      ...NEW_SESSION,
      id: '0190a000-0000-7000-8000-0000000000ff',
      revokedAt: NOW,
      revokedReason: 'admin',
    } as NewSession;

    await createSessionsRepository(db).create(smuggled);

    const [query] = queries;
    expect(query.text.toLowerCase()).toMatch(/values \(default, /);
    expect(query.values).not.toContain('0190a000-0000-7000-8000-0000000000ff');
    expect(query.values).not.toContain('admin');
    expect(query.values).not.toContain(NOW);
  });

  it('updateLastSeen writes only a live row seen at least the interval ago', async () => {
    const query = await run('updateLastSeen');
    const text = query.text.toLowerCase();

    expect(text).toContain('update "sessions" set "last_seen_at" = $1');
    expect(text).toContain('"sessions"."revoked_at" is null');
    expect(text).toContain('"sessions"."expires_at" > $');
    expect(text).toContain('"sessions"."last_seen_at" <= $');
    expect(query.values).toEqual([NOW, REALM_ID, SESSION_ID, NOW, NOW - 60_000]);
  });

  it('updateLastSeen without an interval always writes a live row', async () => {
    const { db, queries } = createRecordingDb();

    await createSessionsRepository(db).updateLastSeen(REALM_ID, SESSION_ID);

    expect(queries[0].values).toEqual([NOW, REALM_ID, SESSION_ID, NOW, NOW]);
  });

  it('revoke ends only a session not yet revoked, with its reason', async () => {
    const query = await run('revoke');
    const text = query.text.toLowerCase();

    expect(text).toContain('set "revoked_at" = $1, "revoked_reason" = $2');
    expect(text).toContain('"sessions"."revoked_at" is null');
    expect(query.values).toEqual([NOW, 'sign_out', REALM_ID, SESSION_ID]);
  });

  it('listActiveForUser lists the live sessions of one user in one realm, newest first', async () => {
    const query = await run('listActiveForUser');
    const text = query.text.toLowerCase();

    expect(text).toMatch(/"sessions"\."realm_id" = \$1 and "sessions"\."user_id" = \$2/);
    expect(text).toContain('"sessions"."revoked_at" is null');
    expect(text).toContain('"sessions"."expires_at" > $3');
    expect(text).toContain('order by "sessions"."created_at" desc, "sessions"."id" desc');
    expect(query.values).toEqual([REALM_ID, USER_ID, NOW]);
  });
});
