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
const OTHER_SESSION = '0190a000-0000-7000-8000-0000000000ab';
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
  listForUser: (repo) => repo.listForUser(REALM_ID, USER_ID, { limit: 10 }),
  listForClient: (repo) => repo.listForClient(REALM_ID, CLIENT_ID, { limit: 10 }),
  revokeForUser: (repo) => repo.revokeForUser(REALM_ID, USER_ID, 'sign_out_everywhere'),
  revokeRealmBatch: (repo) =>
    repo.revokeRealmBatch(REALM_ID, 'key_retired', { createdThrough: NOW, limit: 100 }),
  revokeLapsedBatch: (repo) =>
    repo.revokeLapsedBatch({ now: NOW, defaultMaxLifespanMs: 86_400_000, limit: 100 }),
  deleteEnded: (repo) => repo.deleteEnded({ before: NOW, limit: 100 }),
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
  // @ts-expect-error a user id alone does not list a page of sessions
  void repo.listForUser(USER_ID, { limit: 10 });
  // @ts-expect-error a client id alone does not list a page of sessions
  void repo.listForClient(CLIENT_ID, { limit: 10 });
  // @ts-expect-error a user id alone does not end the user's sessions
  void repo.revokeForUser(USER_ID, 'sign_out_everywhere');
  // @ts-expect-error a batch of a realm's sessions names the realm
  void repo.revokeRealmBatch('key_retired', { createdThrough: NOW, limit: 100 });
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
      if (lower.includes('from "oauth_clients"')) return [[CLIENT_ID, REALM_ID, 'app', 'App']];
      return undefined;
    });

    const ended = await createSessionsRepository(db).revoke(REALM_ID, SESSION_ID, 'sign_out');

    expect(ended?.clients).toEqual([
      {
        sessionId: SESSION_ID,
        oauthClientId: CLIENT_ID,
        firstSeenAt: NOW - 1_000,
        clientId: 'app',
        clientName: 'App',
      },
    ]);
  });

  it('revoke names each client it returns by its client_id, and leaves out one not of the session’s realm', async () => {
    const OTHER_CLIENT = '0190a000-0000-7000-8000-0000000000cd';
    const { db, queries } = createRecordingDb((text) => {
      const lower = text.toLowerCase();
      if (lower.startsWith('update "sessions"')) return [SESSION_ROW];
      if (lower.startsWith('delete from "session_clients"')) {
        return [
          [SESSION_ID, CLIENT_ID, String(NOW - 1_000)],
          [SESSION_ID, OTHER_CLIENT, String(NOW - 2_000)],
        ];
      }
      if (lower.startsWith('select') && lower.includes('from "oauth_clients"')) {
        return [
          [CLIENT_ID, REALM_ID, 'app', 'App'],
          [OTHER_CLIENT, '0190a000-0000-7000-8000-000000000002', 'foreign', 'Foreign'],
        ];
      }
      return undefined;
    });

    const ended = await createSessionsRepository(db).revoke(REALM_ID, SESSION_ID, 'sign_out');

    expect(ended?.clients.map((client) => client.clientId)).toEqual(['app']);
    const lookup = queries.find((query) =>
      query.text.toLowerCase().includes('from "oauth_clients"')
    );
    expect(lookup?.text.toLowerCase()).toContain('where "oauth_clients"."id" in ($1, $2)');
    expect(
      queries.map((query) => query.text.toLowerCase().split(' ').slice(0, 2).join(' '))
    ).toEqual([
      'begin isolation',
      'update "sessions"',
      'delete from',
      'select "id",',
      'update "authorization_codes"',
      'commit',
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

describe('session lists and bulk revocations (#550)', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  const AFTER = { createdAt: NOW - 60_000, id: SESSION_ID };

  it('listForUser reads one page of the user’s sessions in the realm, newest first, after a position', async () => {
    const { db, queries } = createRecordingDb();

    expect(
      await createSessionsRepository(db).listForUser(REALM_ID, USER_ID, { limit: 10, after: AFTER })
    ).toEqual([]);

    expect(queries).toHaveLength(1);
    const text = queries[0].text.toLowerCase();
    expect(text).toContain('from "sessions" where');
    expect(text).not.toContain('join');
    expect(text).toContain(
      '"sessions"."realm_id" = $1 and "sessions"."user_id" = $2 and ' +
        '("sessions"."created_at" < $3 or ("sessions"."created_at" = $4 and "sessions"."id" < $5))'
    );
    expect(text).toContain('order by "sessions"."created_at" desc, "sessions"."id" desc limit $6');
    expect(queries[0].values).toEqual([
      REALM_ID,
      USER_ID,
      NOW - 60_000,
      NOW - 60_000,
      SESSION_ID,
      10,
    ]);
  });

  it('listForClient reads the sessions whose registry names the client, in the realm', async () => {
    const { db, queries } = createRecordingDb();

    await createSessionsRepository(db).listForClient(REALM_ID, CLIENT_ID, { limit: 5 });

    const text = queries[0].text.toLowerCase();
    expect(text).toContain(
      'inner join "session_clients" on "session_clients"."session_id" = "sessions"."id"'
    );
    expect(text).toContain(
      'where ("sessions"."realm_id" = $1 and "session_clients"."oauth_client_id" = $2)'
    );
    expect(queries[0].values).toEqual([REALM_ID, CLIENT_ID, 5]);
  });

  it('a list reads the registry of the sessions on the page, with their clients', async () => {
    const { db, queries } = createRecordingDb((text) => {
      const lower = text.toLowerCase();
      if (lower.includes('from "sessions"')) return [SESSION_ROW];
      if (lower.includes('from "session_clients"')) {
        return [[SESSION_ID, CLIENT_ID, String(NOW - 1_000)]];
      }
      if (lower.includes('from "oauth_clients"')) return [[CLIENT_ID, REALM_ID, 'app', 'App']];
      return undefined;
    });

    const [listed] = await createSessionsRepository(db).listForUser(REALM_ID, USER_ID, {
      limit: 10,
    });

    expect(listed.session.id).toBe(SESSION_ID);
    expect(listed.clients).toEqual([
      {
        sessionId: SESSION_ID,
        oauthClientId: CLIENT_ID,
        firstSeenAt: NOW - 1_000,
        clientId: 'app',
        clientName: 'App',
      },
    ]);
    expect(queries[1].text.toLowerCase()).toContain('where "session_clients"."session_id" in ($1)');
    expect(queries[1].values).toEqual([SESSION_ID]);
  });

  it('revokeForUser locks the user’s unrevoked sessions in id order, then ends them as revoke ends one', async () => {
    const { db, queries } = createRecordingDb((text) => {
      const lower = text.toLowerCase();
      if (lower.startsWith('select "id" from "sessions"')) return [[SESSION_ID]];
      if (lower.startsWith('update "sessions"')) return [SESSION_ROW];
      return undefined;
    });

    const ended = await createSessionsRepository(db).revokeForUser(REALM_ID, USER_ID, 'reset', {
      exceptId: OTHER_SESSION,
      createdBefore: NOW - 1_000,
    });

    expect(ended.map((session) => session.session.id)).toEqual([SESSION_ID]);
    expect(
      queries.map((query) => query.text.toLowerCase().split(' ').slice(0, 3).join(' '))
    ).toEqual([
      'begin isolation level',
      'select "id" from',
      'update "sessions" set',
      'delete from "session_clients"',
      'update "authorization_codes" set',
      'commit',
    ]);
    expect(queries[0].text.toLowerCase()).toBe('begin isolation level read committed');
    const lock = queries[1];
    expect(lock.text.toLowerCase()).toContain(
      'where ("sessions"."revoked_at" is null and ("sessions"."realm_id" = $1 and ' +
        '"sessions"."user_id" = $2 and "sessions"."id" <> $3 and "sessions"."created_at" < $4))'
    );
    expect(lock.text.toLowerCase().trim()).toMatch(/order by "sessions"\."id" asc for update$/);
    expect(lock.values).toEqual([REALM_ID, USER_ID, OTHER_SESSION, NOW - 1_000]);
    const update = queries[2];
    expect(update.text.toLowerCase()).toContain('set "revoked_at" = $1, "revoked_reason" = $2');
    expect(update.text.toLowerCase()).toContain(
      'where ("sessions"."id" in ($3) and "sessions"."revoked_at" is null)'
    );
    expect(update.values).toEqual([NOW, 'reset', SESSION_ID]);
  });

  it('revokeForUser writes nothing more when it locks no session', async () => {
    const { db, queries } = createRecordingDb();

    expect(
      await createSessionsRepository(db).revokeForUser(REALM_ID, USER_ID, 'sign_out_everywhere')
    ).toEqual([]);
    expect(statementsOf(queries)).toHaveLength(1);
  });

  it.each(['repeatable read', 'serializable'])(
    'revokeForUser refuses a caller’s transaction at %s and writes nothing',
    async (level) => {
      const { db, queries } = createRecordingDb(isolationLevel(level));

      await expect(
        db.transaction((tx) =>
          createSessionsRepository(db).revokeForUser(
            REALM_ID,
            USER_ID,
            'sign_out_everywhere',
            {},
            tx
          )
        )
      ).rejects.toThrow('sessions.revokeForUser needs a READ COMMITTED transaction');
      expect(queries.some((query) => /^(update|delete)\b/i.test(query.text.trim()))).toBe(false);
    }
  );

  it('revokeRealmBatch locks one batch of the realm in id order after the last one, created by the run’s start', async () => {
    const { db, queries } = createRecordingDb((text) =>
      text.toLowerCase().startsWith('select "id" from "sessions"')
        ? [[SESSION_ID], [OTHER_SESSION]]
        : undefined
    );

    const batch = await createSessionsRepository(db).revokeRealmBatch(REALM_ID, 'key_retired', {
      after: SESSION_ID,
      createdThrough: NOW - 5,
      activeSince: NOW - 3_600_000,
      limit: 2,
    });

    // The UPDATE answered no row (another transaction ended both): the batch
    // still moves past them.
    expect(batch).toEqual({ ended: [], last: OTHER_SESSION, selected: 2 });
    const lock = statementsOf(queries)[0];
    expect(lock.text.toLowerCase()).toContain(
      'where ("sessions"."revoked_at" is null and ("sessions"."realm_id" = $1 and ' +
        '"sessions"."id" > $2 and "sessions"."created_at" <= $3 and "sessions"."last_seen_at" >= $4))'
    );
    expect(lock.text.toLowerCase().trim()).toMatch(
      /order by "sessions"\."id" asc limit \$5 for update$/
    );
    expect(lock.values).toEqual([REALM_ID, SESSION_ID, NOW - 5, NOW - 3_600_000, 2]);
    expect(queries[0].text.toLowerCase()).toBe('begin isolation level read committed');
  });

  it('revokeRealmBatch reports an empty batch, which ends the run', async () => {
    const { db } = createRecordingDb();

    expect(
      await createSessionsRepository(db).revokeRealmBatch(REALM_ID, 'admin', {
        createdThrough: NOW,
        limit: 500,
      })
    ).toEqual({ ended: [], last: null, selected: 0 });
  });

  it('revokeLapsedBatch judges both ends with the realm’s lifetimes and SESSION_COOKIE_TTL, and records when each session ended', async () => {
    const { db, queries } = createRecordingDb((text) =>
      text.toLowerCase().startsWith('select "sessions"."id"') ? [[SESSION_ID]] : undefined
    );

    await createSessionsRepository(db).revokeLapsedBatch({
      now: NOW,
      defaultMaxLifespanMs: 86_400_000,
      limit: 50,
    });

    const [lock, update] = statementsOf(queries).map((query) => ({
      ...query,
      text: query.text.toLowerCase(),
    }));
    expect(lock.text).toContain('inner join "realms" on "realms"."id" = "sessions"."realm_id"');
    const absolute =
      'least("sessions"."expires_at", "sessions"."created_at" + coalesce("realms"."sso_max_lifespan" * 1000,';
    expect(lock.text).toContain(absolute);
    expect(lock.text).toContain('"realms"."sso_idle_timeout" is not null');
    expect(lock.text).toContain(
      '"sessions"."last_seen_at" + "realms"."sso_idle_timeout" * 1000 <='
    );
    expect(lock.text.trim()).toMatch(/limit \$\d+ for update of "sessions"$/);
    expect(lock.values).toEqual(expect.arrayContaining([86_400_000, NOW, 50]));
    expect(update.text).toMatch(/^update "sessions" set "revoked_at" = least\(least\(/);
    expect(update.text).toContain("then 'idle' else 'expired' end");
    expect(update.text).toContain('from "realms"');
    expect(update.text).toContain('returning');
  });

  it('deleteEnded selects rows revoked or expired before the cut-off, then deletes them if that still holds', async () => {
    const { db, queries } = createRecordingDb((text) =>
      text.toLowerCase().startsWith('select') ? [[SESSION_ID]] : [[SESSION_ID]]
    );

    expect(
      await createSessionsRepository(db).deleteEnded({
        before: NOW,
        after: OTHER_SESSION,
        limit: 1,
      })
    ).toEqual({ deleted: 1, last: SESSION_ID, selected: 1 });

    const [select, remove] = queries.map((query) => ({ ...query, text: query.text.toLowerCase() }));
    const ended = '("sessions"."revoked_at" < $2 or "sessions"."expires_at" < $3)';
    expect(select.text).toContain(`where ("sessions"."id" > $1 and ${ended})`);
    expect(select.values).toEqual([OTHER_SESSION, NOW, NOW, 1]);
    expect(remove.text).toContain('delete from "sessions"');
    expect(remove.text).toContain(
      'where ("sessions"."id" in ($1) and ("sessions"."revoked_at" < $2 or "sessions"."expires_at" < $3))'
    );
  });
});
