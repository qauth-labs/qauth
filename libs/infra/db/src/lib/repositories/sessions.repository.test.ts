import { drizzle } from 'drizzle-orm/node-postgres';
import type { Pool } from 'pg';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { Database, NewSession, SessionsRepository } from '../../types';
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
const CLIENT_ID = '0190a000-0000-7000-8000-0000000000cc';
const NOW = 1_800_000_000_000;

/**
 * A `pg` client that records queries instead of running them. Every query
 * answers no rows, unless `respond` gives rows (in drizzle's array row mode,
 * or as objects for a raw `execute`) for its text.
 */
function createRecordingDb(respond: (text: string) => unknown[] | undefined = () => undefined): {
  db: DbClient;
  queries: CapturedQuery[];
} {
  const queries: CapturedQuery[] = [];

  const client = {
    query: (config: { text?: string; values?: unknown[] } | string, values?: unknown[]) => {
      const text = typeof config === 'string' ? config : (config.text ?? '');
      const params = typeof config === 'string' ? (values ?? []) : (config.values ?? values ?? []);
      queries.push({ text, values: params });
      const rows = respond(text) ?? [];
      return Promise.resolve({ rows, rowCount: rows.length, fields: [], command: '', oid: 0 });
    },
  };

  return { db: drizzle(client as unknown as Pool) as unknown as DbClient, queries };
}

/** Transaction control, which {@link run} leaves out. */
const TRANSACTION_CONTROL = /^(begin|commit|rollback)\b/i;

/** The statements of a recording, without transaction control. */
function statementsOf(queries: readonly CapturedQuery[]): CapturedQuery[] {
  return queries.filter((query) => !TRANSACTION_CONTROL.test(query.text.trim()));
}

/** A `sessions` row as `RETURNING *` gives it, in column order. */
const SESSION_ROW: unknown[] = [
  SESSION_ID,
  REALM_ID,
  USER_ID,
  String(NOW - 5_000),
  ['pwd'],
  null,
  '192.0.2.1',
  'test-agent',
  String(NOW + 86_400_000),
  String(NOW),
  'sign_out',
  String(NOW - 10_000),
  String(NOW - 10_000),
];

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
  // In a transaction of the recording client, as it requires.
  recordClient: (repo) =>
    recordingDb.transaction((tx) => repo.recordClient(REALM_ID, SESSION_ID, CLIENT_ID, tx)),
  listClientsForSession: (repo) => repo.listClientsForSession(REALM_ID, SESSION_ID),
  listClientsForUser: (repo) => repo.listClientsForUser(REALM_ID, USER_ID),
  listSessionsForClient: (repo) => repo.listSessionsForClient(REALM_ID, CLIENT_ID),
};

/** Set by {@link run} to the recording client of the call it makes. */
let recordingDb: DbClient;

/**
 * Make one call against a recording client that answers no rows, and return
 * its one statement (transaction control left out).
 */
async function run(method: keyof SessionsRepository): Promise<CapturedQuery> {
  const { db, queries } = createRecordingDb();
  recordingDb = db;
  await CALLS[method](createSessionsRepository(db));
  const statements = statementsOf(queries);
  expect(statements).toHaveLength(1);
  return statements[0];
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
  // @ts-expect-error a session id alone does not list its clients
  void repo.listClientsForSession(SESSION_ID);
  // @ts-expect-error a user id alone does not list the clients of their sessions
  void repo.listClientsForUser(USER_ID);
  // @ts-expect-error a client id alone does not list its sessions
  void repo.listSessionsForClient(CLIENT_ID);
}

/**
 * Never called: `recordClient` takes the transaction that mints the code, and
 * one without it, or with the root client in its place, does not compile.
 */
export function recordClientNeedsATransaction(repo: SessionsRepository, root: Database): void {
  // @ts-expect-error the share lock must last until the code's transaction ends
  void repo.recordClient(REALM_ID, SESSION_ID, CLIENT_ID);
  // @ts-expect-error on the root client the share lock ends with the statement
  void repo.recordClient(REALM_ID, SESSION_ID, CLIENT_ID, root);
}

/** The isolation level a caller's transaction reports, as `current_setting` answers it. */
function isolationLevel(level: string): (text: string) => unknown[] | undefined {
  return (text) =>
    text.toLowerCase().includes("current_setting('transaction_isolation')")
      ? [{ level }]
      : undefined;
}

describe('createSessionsRepository', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('exposes the session methods and the client registry methods, and nothing else', () => {
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

  it('revoke deletes the ended session’s registry rows in the same transaction, in a later statement', async () => {
    const { db, queries } = createRecordingDb((text) =>
      text.toLowerCase().startsWith('update "sessions"') ? [SESSION_ROW] : undefined
    );

    const ended = await createSessionsRepository(db).revoke(REALM_ID, SESSION_ID, 'sign_out');

    expect(ended?.session.id).toBe(SESSION_ID);
    expect(ended?.clients).toEqual([]);
    expect(
      queries.map((query) => query.text.toLowerCase().split(' ').slice(0, 3).join(' '))
    ).toEqual([
      'begin isolation level',
      'update "sessions" set',
      'delete from "session_clients"',
      'update "authorization_codes" set',
      'commit',
    ]);
    // READ COMMITTED whatever the server's default: the DELETE needs a
    // snapshot taken after the UPDATE got the row.
    expect(queries[0].text.toLowerCase()).toBe('begin isolation level read committed');
    const remove = queries[2];
    expect(remove.text.toLowerCase()).toContain('where "session_clients"."session_id" = $1');
    expect(remove.text.toLowerCase()).toContain('returning');
    expect(remove.values).toEqual([SESSION_ID]);
  });

  it('revoke spends the ended session’s unredeemed codes in the same transaction', async () => {
    const { db, queries } = createRecordingDb((text) =>
      text.toLowerCase().startsWith('update "sessions"') ? [SESSION_ROW] : undefined
    );

    await createSessionsRepository(db).revoke(REALM_ID, SESSION_ID, 'sign_out');

    const spend = queries.find((query) =>
      query.text.toLowerCase().startsWith('update "authorization_codes"')
    );
    expect(spend?.text.toLowerCase()).toContain('set "used" = $1, "used_at" = $2');
    expect(spend?.text.toLowerCase()).toContain(
      'where ("authorization_codes"."session_id" = $3 and "authorization_codes"."used" = $4)'
    );
    expect(spend?.values).toEqual([true, NOW, SESSION_ID, false]);
  });

  it('revoke deletes nothing and spends no code when it ended no session', async () => {
    const { db, queries } = createRecordingDb();

    await createSessionsRepository(db).revoke(REALM_ID, SESSION_ID, 'sign_out');

    expect(
      queries.some((query) => /session_clients|authorization_codes/.test(query.text.toLowerCase()))
    ).toBe(false);
  });

  it('revoke returns the registry rows it deleted', async () => {
    const { db } = createRecordingDb((text) => {
      const lower = text.toLowerCase();
      if (lower.startsWith('update "sessions"')) return [SESSION_ROW];
      if (lower.startsWith('delete from "session_clients"')) {
        return [[SESSION_ID, CLIENT_ID, String(NOW - 1_000)]];
      }
      return undefined;
    });

    const ended = await createSessionsRepository(db).revoke(REALM_ID, SESSION_ID, 'sign_out');

    expect(ended?.clients).toEqual([
      { sessionId: SESSION_ID, oauthClientId: CLIENT_ID, firstSeenAt: NOW - 1_000 },
    ]);
  });

  it('revoke inside a caller’s transaction checks it is READ COMMITTED, then runs as a savepoint of it', async () => {
    const level = isolationLevel('read committed');
    const { db, queries } = createRecordingDb((text) =>
      text.toLowerCase().startsWith('update "sessions"') ? [SESSION_ROW] : level(text)
    );

    await db.transaction((tx) =>
      createSessionsRepository(db).revoke(REALM_ID, SESSION_ID, 'sign_out', tx)
    );

    expect(queries.map((query) => query.text.toLowerCase().split(' ')[0])).toEqual([
      'begin',
      'select',
      'savepoint',
      'update',
      'delete',
      'update',
      'release',
      'commit',
    ]);
  });

  it.each(['repeatable read', 'serializable'])(
    'revoke refuses a caller’s transaction at %s and writes nothing',
    async (level) => {
      const { db, queries } = createRecordingDb(isolationLevel(level));

      await expect(
        db.transaction((tx) =>
          createSessionsRepository(db).revoke(REALM_ID, SESSION_ID, 'sign_out', tx)
        )
      ).rejects.toThrow(`sessions.revoke needs a READ COMMITTED transaction`);
      expect(queries.some((query) => /^(update|delete)\b/i.test(query.text.trim()))).toBe(false);
    }
  );

  it('recordClient locks the live session for share, then adds the row once', async () => {
    const { db, queries } = createRecordingDb((text) =>
      text.toLowerCase().startsWith('select') ? [[SESSION_ID]] : undefined
    );

    const recorded = await db.transaction((tx) =>
      createSessionsRepository(db).recordClient(REALM_ID, SESSION_ID, CLIENT_ID, tx)
    );

    expect(recorded).toBe(true);
    const statements = statementsOf(queries);
    expect(statements).toHaveLength(2);
    const [lock, insert] = statements.map((query) => ({
      ...query,
      text: query.text.toLowerCase(),
    }));
    // The client must be one of the session's realm (ADR-019 Decision 1).
    expect(lock.text).toContain(
      'inner join "oauth_clients" on ("oauth_clients"."id" = $1 and "oauth_clients"."realm_id" = "sessions"."realm_id")'
    );
    expect(lock.text).toMatch(/"sessions"\."realm_id" = \$2 and "sessions"\."id" = \$3/);
    expect(lock.text).toContain('"sessions"."revoked_at" is null');
    expect(lock.text).toContain('"sessions"."expires_at" > $4');
    // Only the session row is locked, not the client's.
    expect(lock.text.trim()).toMatch(/for share of "sessions"$/);
    expect(lock.values).toEqual([CLIENT_ID, REALM_ID, SESSION_ID, NOW]);
    expect(insert.text).toContain('insert into "session_clients"');
    expect(insert.text).toContain('on conflict do nothing');
    expect(insert.values).toEqual([SESSION_ID, CLIENT_ID]);
  });

  it('recordClient writes nothing and answers false when no live session matches', async () => {
    const { db, queries } = createRecordingDb();

    expect(
      await db.transaction((tx) =>
        createSessionsRepository(db).recordClient(REALM_ID, SESSION_ID, CLIENT_ID, tx)
      )
    ).toBe(false);
    expect(statementsOf(queries)).toHaveLength(1);
  });

  it.each([
    ['listClientsForSession', '"session_clients"."session_id" = $3', SESSION_ID],
    ['listClientsForUser', '"sessions"."user_id" = $3', USER_ID],
    ['listSessionsForClient', '"session_clients"."oauth_client_id" = $3', CLIENT_ID],
  ] as const)(
    '%s reads the registry of the realm’s live sessions only, oldest first',
    async (method, filter, id) => {
      const query = await run(method);
      const text = query.text.toLowerCase();

      expect(text).toContain(
        'from "session_clients" inner join "sessions" on "sessions"."id" = "session_clients"."session_id"'
      );
      expect(text).toContain(
        'where ("sessions"."realm_id" = $1 and "sessions"."revoked_at" is null and ' +
          `"sessions"."expires_at" > $2 and ${filter})`
      );
      expect(text).toContain(
        'order by "session_clients"."first_seen_at" asc, "session_clients"."session_id" asc, "session_clients"."oauth_client_id" asc'
      );
      expect(query.values).toEqual([REALM_ID, NOW, id]);
    }
  );

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
