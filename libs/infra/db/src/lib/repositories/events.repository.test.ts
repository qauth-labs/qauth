import { type EventEnvelope, EventValidationError } from '@qauth-labs/shared-events';
import { drizzle } from 'drizzle-orm/node-postgres';
import type { Pool } from 'pg';
import { describe, expect, expectTypeOf, it } from 'vitest';
import { z } from 'zod';

import type {
  AdminEventInput,
  Database,
  DbTransaction,
  EmitEvent,
  EventsRepository,
  EventTelemetrySink,
} from '../../types';
import { EVENT_CHAIN_GENESIS_HASH, eventChainHash } from '../events/chain';
import {
  decodeEventPosition,
  encodeEventPosition,
  type EventPosition,
  EventPositionError,
  eventStreamStart,
} from '../events/position';
import {
  createEventsRepository,
  EVENT_READ_LIMIT_MAX,
  EVENT_ROW_SCHEMA_VERSION,
} from './events.repository';

/**
 * Statement-level tests for the event store (issue #457), without Docker:
 * what `emit` refuses before it writes, what it binds into the INSERT, and
 * what `readAfter` checks and returns. The container suite
 * (`events.integration.test.ts`) runs the transactions, the read horizon and
 * the grants against Postgres.
 */

interface CapturedQuery {
  readonly text: string;
  readonly values: readonly unknown[];
}

/**
 * A `pg` client that records queries instead of running them. A read gets
 * `rows`, or what `respond` answers for it; every other statement gets none.
 */
function createRecordingDb(
  rows: Record<string, unknown>[] = [],
  respond?: (query: CapturedQuery, queries: CapturedQuery[]) => Record<string, unknown>[]
): {
  db: Database;
  queries: CapturedQuery[];
} {
  const queries: CapturedQuery[] = [];
  const client = {
    query: (config: { text?: string; values?: unknown[] } | string, values?: unknown[]) => {
      const text = typeof config === 'string' ? config : (config.text ?? '');
      const params = typeof config === 'string' ? (values ?? []) : (config.values ?? values ?? []);
      queries.push({ text, values: params });
      const read = text.trim().toLowerCase().startsWith('select');
      const result = read ? (respond?.({ text, values: params }, queries) ?? rows) : [];
      return Promise.resolve({ rows: result, rowCount: result.length, fields: [], command: '' });
    },
  };
  return { db: drizzle(client as unknown as Pool) as unknown as Database, queries };
}

/** The recording database, typed as the transaction `emit` takes. */
const asTransaction = (db: Database) => db as unknown as DbTransaction;

const REALM_ID = '0192f1c4-1111-7000-8000-000000000001';
const OTHER_REALM_ID = '0192f1c4-2222-7000-8000-000000000002';
const USER_ID = '0192f1c4-4444-7000-8000-000000000004';
const NOW = Date.UTC(2026, 9, 23, 12, 0, 0, 0);

const SIGNED_IN: EmitEvent<'urn:qauth:event:user.signed_in:v1-rc.0'> = {
  type: 'urn:qauth:event:user.signed_in:v1-rc.0',
  realm: REALM_ID,
  actor: { type: 'user', id: USER_ID },
  subject: { type: 'user', id: USER_ID },
  client: { id: 'portal' },
  request: { traceId: 'req-1', ip: '203.0.113.5', userAgent: 'Mozilla/5.0' },
  data: { method: 'password' },
};

function insertOf(queries: CapturedQuery[]): CapturedQuery {
  const insert = queries.find((q) => q.text.toLowerCase().startsWith('insert into "events"'));
  if (!insert) throw new Error('no INSERT into events');
  return insert;
}

/** A row as node-postgres returns the read's: `bigint` and `xid8` as text. */
function readRow(xid: number, seq: number, overrides: Record<string, unknown> = {}) {
  return {
    horizon: '900',
    seq: String(seq),
    xid: String(xid),
    id: '0192f1c4-9999-7000-8000-000000000009',
    realm_id: REALM_ID,
    category: 'user',
    type: 'urn:qauth:event:user.signed_in:v1-rc.0',
    time: String(NOW),
    actor_type: 'user',
    actor_id: USER_ID,
    actor_delegation_chain: null,
    subject_type: 'user',
    subject_id: USER_ID,
    client_id: null,
    request_id: 'req-1',
    request_ip: null,
    request_user_agent: null,
    data: { method: 'password' },
    schema_version: EVENT_ROW_SCHEMA_VERSION,
    ...overrides,
  };
}

/** The row the read returns when no event qualifies: the horizon alone. */
function horizonOnly(horizon: string) {
  return {
    ...Object.fromEntries(Object.keys(readRow(0, 0)).map((key) => [key, null])),
    horizon,
  };
}

describe('emit', () => {
  it("writes the event in the caller's transaction and returns its id", async () => {
    const { db, queries } = createRecordingDb();
    const repo = createEventsRepository(db, { now: () => NOW });

    const id = await repo.emit(asTransaction(db), {
      ...SIGNED_IN,
      realm: REALM_ID.toUpperCase(),
    });

    expect(z.uuidv7().safeParse(id).success).toBe(true);
    expect(parseInt(id.replaceAll('-', '').slice(0, 12), 16)).toBe(NOW);
    expect(queries).toHaveLength(1);
    const insert = insertOf(queries);
    // Nothing is read back, so a role granted only INSERT can write.
    expect(insert.text.toLowerCase()).not.toContain('returning');
    expect(insert.values).toEqual(
      expect.arrayContaining([
        id,
        REALM_ID, // lower case, as Postgres prints it
        'user', // the category, from the registry
        SIGNED_IN.type,
        NOW,
        USER_ID,
        'portal',
        'req-1',
        '203.0.113.5',
        'Mozilla/5.0',
        JSON.stringify({ method: 'password' }),
        EVENT_ROW_SCHEMA_VERSION,
      ])
    );
  });

  it('rejects an unknown type and writes nothing', async () => {
    const { db, queries } = createRecordingDb();
    const repo = createEventsRepository(db);
    const unknown = { ...SIGNED_IN, type: 'urn:qauth:event:user.teleported:v1' } as never;

    await expect(repo.emit(asTransaction(db), unknown)).rejects.toThrow(EventValidationError);
    await expect(repo.emit(asTransaction(db), unknown)).rejects.toThrow(/unknown event type/);
    await expect(repo.emitInOwnTransaction(unknown)).rejects.toThrow(EventValidationError);
    expect(queries).toHaveLength(0);
  });

  it.each([
    ['a member its schema does not declare', { method: 'password', secret: 'x' }],
    ['a value outside its enum', { method: 'telepathy' }],
    ['a missing required member', {}],
  ])('rejects a payload with %s and writes nothing', async (_label, data) => {
    const { db, queries } = createRecordingDb();
    const repo = createEventsRepository(db);
    const bad = { ...SIGNED_IN, data } as never;

    await expect(repo.emit(asTransaction(db), bad)).rejects.toThrow(EventValidationError);
    await expect(repo.emit(asTransaction(db), bad)).rejects.toThrow(
      /not a valid urn:qauth:event:user\.signed_in:v1-rc\.0 event/
    );
    expect(queries).toHaveLength(0);
  });

  it('rejects an envelope that fails the contract: a subject of the wrong kind, a realm that is no UUID', async () => {
    const { db, queries } = createRecordingDb();
    const repo = createEventsRepository(db);

    await expect(
      repo.emit(asTransaction(db), { ...SIGNED_IN, subject: { type: 'client', id: 'portal' } })
    ).rejects.toThrow(EventValidationError);
    await expect(repo.emit(asTransaction(db), { ...SIGNED_IN, realm: 'master' })).rejects.toThrow(
      EventValidationError
    );
    expect(queries).toHaveLength(0);
  });

  it('rejects a text Postgres cannot store, a NUL character, and writes nothing', async () => {
    const { db, queries } = createRecordingDb();
    const repo = createEventsRepository(db);

    await expect(
      repo.emit(asTransaction(db), {
        ...SIGNED_IN,
        request: { userAgent: 'Mozilla\u0000/5.0' },
      })
    ).rejects.toThrow(/\/request\/userAgent: holds a NUL character/);
    expect(queries).toHaveLength(0);
  });
});

describe('emitInOwnTransaction', () => {
  it('writes one INSERT on the root database, which is a transaction of its own', async () => {
    const { db, queries } = createRecordingDb();
    const repo = createEventsRepository(db, { now: () => NOW });

    const id = await repo.emitInOwnTransaction(SIGNED_IN);

    expect(queries.map((q) => q.text.split(' ').slice(0, 3).join(' ').toLowerCase())).toEqual([
      'insert into "events"',
    ]);
    expect(insertOf(queries).values).toContain(id);
  });
});

/** A sink that keeps what it is handed, with the statements that had run by then. */
function recordingSink(queries: readonly CapturedQuery[]) {
  const handed: Array<{ event: EventEnvelope; statements: string[] }> = [];
  const sink: EventTelemetrySink = {
    record: (event) => handed.push({ event, statements: queries.map((q) => q.text.toLowerCase()) }),
  };
  return { sink, handed };
}

/** A JWS in compact form: the shape the payload scanner refuses anywhere in an event. */
const JWS_SHAPED = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJlLXZhbHVl';

describe('telemetry (issue #541)', () => {
  it('hands the stored envelope to the sink once the transaction has committed, never inside it', async () => {
    const { db, queries } = createRecordingDb();
    const { sink, handed } = recordingSink(queries);
    const repo = createEventsRepository(db, { now: () => NOW, telemetry: sink });

    const id = await db.transaction(async (tx) => {
      const emitted = await repo.emit(tx, SIGNED_IN);
      expect(handed).toEqual([]);
      return emitted;
    });

    expect(handed).toHaveLength(1);
    expect(handed[0].statements.at(-1)).toBe('commit');
    expect(handed[0].event).toEqual({
      id,
      type: SIGNED_IN.type,
      time: new Date(NOW).toISOString(),
      realm: REALM_ID,
      category: 'user',
      actor: SIGNED_IN.actor,
      subject: SIGNED_IN.subject,
      client: SIGNED_IN.client,
      request: SIGNED_IN.request,
      data: SIGNED_IN.data,
    });
  });

  it('never hands over an event whose transaction rolls back', async () => {
    const { db, queries } = createRecordingDb();
    const { sink, handed } = recordingSink(queries);
    const repo = createEventsRepository(db, { telemetry: sink });

    await expect(
      db.transaction(async (tx) => {
        await repo.emit(tx, SIGNED_IN);
        throw new Error('the change failed');
      })
    ).rejects.toThrow('the change failed');
    expect(handed).toEqual([]);
  });

  it('hands over an event written in its own transaction right after the insert', async () => {
    const { db, queries } = createRecordingDb();
    const { sink, handed } = recordingSink(queries);
    const repo = createEventsRepository(db, { telemetry: sink });

    const id = await repo.emitInOwnTransaction(SIGNED_IN);

    expect(handed.map((entry) => entry.event.id)).toEqual([id]);
    expect(handed[0].statements).toHaveLength(1);
    expect(handed[0].statements[0]).toMatch(/^insert into "events"/);
  });

  it('a sink that throws fails neither write', async () => {
    const { db } = createRecordingDb();
    const repo = createEventsRepository(db, {
      telemetry: {
        record: () => {
          throw new Error('collector gone');
        },
      },
    });

    await expect(repo.emitInOwnTransaction(SIGNED_IN)).resolves.toEqual(expect.any(String));
    await expect(db.transaction((tx) => repo.emit(tx, SIGNED_IN))).resolves.toEqual(
      expect.any(String)
    );
  });

  it('an event with a secret-shaped value fails the scanner and reaches neither the table nor the sink', async () => {
    const { db, queries } = createRecordingDb();
    const { sink, handed } = recordingSink(queries);
    const repo = createEventsRepository(db, { telemetry: sink });
    const leaking = { ...SIGNED_IN, request: { userAgent: JWS_SHAPED } };

    await expect(repo.emitInOwnTransaction(leaking)).rejects.toThrow(
      /\/request\/userAgent: the value is shaped like a token/
    );
    await expect(db.transaction((tx) => repo.emit(tx, leaking))).rejects.toThrow(
      EventValidationError
    );
    expect(queries.filter((q) => q.text.toLowerCase().startsWith('insert'))).toEqual([]);
    expect(handed).toEqual([]);
  });

  it('leaves the database untouched without a sink', () => {
    const { db } = createRecordingDb();
    createEventsRepository(db);
    expect(Object.hasOwn(db, 'transaction')).toBe(false);
  });
});

describe('readAfter', () => {
  it('refuses a realm id that is no UUID, a position of another realm and a limit out of range, before it reads', async () => {
    const { db, queries } = createRecordingDb();
    const repo = createEventsRepository(db);
    const start = eventStreamStart(REALM_ID);

    await expect(repo.readAfter('master', start, 10)).rejects.toThrow(TypeError);
    await expect(repo.readAfter('', start, 10)).rejects.toThrow(TypeError);
    await expect(repo.readAfter(OTHER_REALM_ID, start, 10)).rejects.toThrow(EventPositionError);
    await expect(
      repo.readAfter(REALM_ID, 'cDE6bm90LWEtcG9zaXRpb24' as EventPosition, 10)
    ).rejects.toThrow(EventPositionError);
    for (const limit of [0, -1, 1.5, EVENT_READ_LIMIT_MAX + 1, Number.NaN]) {
      await expect(repo.readAfter(REALM_ID, start, limit)).rejects.toThrow(TypeError);
    }
    await expect(
      repo.readAfter(REALM_ID, start, 10, { fromTime: Number.POSITIVE_INFINITY })
    ).rejects.toThrow(TypeError);
    expect(queries).toHaveLength(0);
  });

  it('reads one realm after the position, below the snapshot horizon, in (xid, seq) order, in one statement', async () => {
    const { db, queries } = createRecordingDb([horizonOnly('900')]);
    const repo = createEventsRepository(db);
    const from = encodeEventPosition({ realmId: REALM_ID, xid: 758n, seq: 12n });

    await repo.readAfter(REALM_ID.toUpperCase(), from, 50, {
      types: ['urn:qauth:event:user.signed_in:v1-rc.0'],
      category: 'user',
      subjectId: USER_ID,
      clientId: 'portal',
      fromTime: NOW,
    });

    expect(queries).toHaveLength(1);
    const [read] = queries;
    const text = read.text.replace(/\s+/g, ' ');
    expect(text).toContain('pg_snapshot_xmin(pg_current_snapshot())');
    expect(text).toContain('"events"."xid" < "horizon"."xmin"');
    expect(text).toMatch(/\("events"\."xid", "events"\."seq"\) > \(\$\d+::xid8, \$\d+::bigint\)/);
    expect(text).toContain('order by "events"."xid", "events"."seq"');
    expect(read.values).toEqual(
      expect.arrayContaining([
        REALM_ID,
        '758',
        '12',
        'urn:qauth:event:user.signed_in:v1-rc.0',
        'user',
        USER_ID,
        'portal',
        NOW,
        50,
      ])
    );
  });

  it('rebuilds each envelope with the members its row has, and continues from the last when the page is full', async () => {
    const rows = [
      readRow(800, 3, {
        actor_type: 'client',
        actor_id: 'agent-1',
        actor_delegation_chain: ['agent-1', 'portal'],
        client_id: 'agent-1',
        request_id: null,
      }),
      readRow(801, 7, {
        actor_type: 'system',
        actor_id: null,
        subject_type: null,
        subject_id: null,
      }),
    ];
    const { db } = createRecordingDb(rows);
    const repo = createEventsRepository(db);

    const page = await repo.readAfter(REALM_ID, eventStreamStart(REALM_ID), 2);

    expect(page.events.map((stored) => stored.event)).toEqual([
      {
        id: rows[0].id,
        type: rows[0].type,
        time: new Date(NOW).toISOString(),
        realm: REALM_ID,
        category: 'user',
        actor: { type: 'client', id: 'agent-1', delegationChain: ['agent-1', 'portal'] },
        subject: { type: 'user', id: USER_ID },
        client: { id: 'agent-1' },
        data: { method: 'password' },
      },
      {
        id: rows[1].id,
        type: rows[1].type,
        time: new Date(NOW).toISOString(),
        realm: REALM_ID,
        category: 'user',
        actor: { type: 'system' },
        request: { traceId: 'req-1' },
        data: { method: 'password' },
      },
    ]);
    expect(page.events.map((stored) => decodeEventPosition(stored.position))).toEqual([
      { realmId: REALM_ID, xid: 800n, seq: 3n },
      { realmId: REALM_ID, xid: 801n, seq: 7n },
    ]);
    expect(page.next).toBe(page.events[1].position);
  });

  it('continues from the horizon after a short page, and never from before the position read from', async () => {
    const repoWith = (rows: Record<string, unknown>[]) =>
      createEventsRepository(createRecordingDb(rows).db);

    const short = await repoWith([readRow(800, 3)]).readAfter(
      REALM_ID,
      eventStreamStart(REALM_ID),
      10
    );
    expect(decodeEventPosition(short.next)).toEqual({ realmId: REALM_ID, xid: 900n, seq: 0n });

    const empty = await repoWith([horizonOnly('900')]).readAfter(
      REALM_ID,
      eventStreamStart(REALM_ID),
      10
    );
    expect(empty.events).toEqual([]);
    expect(decodeEventPosition(empty.next)).toEqual({ realmId: REALM_ID, xid: 900n, seq: 0n });

    const ahead = encodeEventPosition({ realmId: REALM_ID, xid: 950n, seq: 4n });
    const behind = await repoWith([horizonOnly('900')]).readAfter(REALM_ID, ahead, 10);
    expect(behind.next).toBe(ahead);
  });

  it('refuses a row stored in a later layout than this release reads', async () => {
    const { db } = createRecordingDb([readRow(800, 3, { schema_version: 2 })]);
    const repo = createEventsRepository(db);

    await expect(repo.readAfter(REALM_ID, eventStreamStart(REALM_ID), 10)).rejects.toThrow(
      /layout 2/
    );
  });
});

describe('oldestUnreadEventAge', () => {
  it('is 0 when no committed event is held back', async () => {
    const { db } = createRecordingDb([{ oldest: null }]);
    await expect(createEventsRepository(db).oldestUnreadEventAge()).resolves.toBe(0);
  });

  it('is the age in seconds of the oldest event at or above the horizon', async () => {
    const { db, queries } = createRecordingDb([{ oldest: String(NOW - 42_500) }]);
    const repo = createEventsRepository(db, { now: () => NOW });

    await expect(repo.oldestUnreadEventAge()).resolves.toBe(42.5);
    expect(queries[0].text).toContain('>= pg_snapshot_xmin(pg_current_snapshot())');
  });
});

/** The columns and values an INSERT into "events" bound, by column name. */
function insertedColumns(insert: CapturedQuery): Record<string, unknown> {
  const [, columnList, valueList] =
    /^insert into "events" \(([^)]*)\) values \((.*)\)$/i.exec(insert.text.trim()) ?? [];
  if (!columnList || !valueList) throw new Error(`not an INSERT into events: ${insert.text}`);
  const columns = columnList.split(', ').map((column) => column.replaceAll('"', ''));
  const placeholders = valueList.split(', ');
  return Object.fromEntries(
    columns.flatMap((column, i) => {
      const match = /^\$(\d+)$/.exec(placeholders[i]);
      return match ? [[column, insert.values[Number(match[1]) - 1]]] : [];
    })
  );
}

/**
 * Answer the admin chain's reads: no head (the realm's first admin event),
 * and the read-back of the row as Postgres would store what was inserted.
 * `tamper` changes the stored row before it is returned.
 */
function chainResponder(tamper: (row: Record<string, unknown>) => void = () => undefined) {
  return (query: CapturedQuery, queries: CapturedQuery[]) => {
    if (!query.text.includes('"prev_hash"')) return [];
    const inserted = insertedColumns(insertOf(queries));
    const json = (value: unknown) => (typeof value === 'string' ? JSON.parse(value) : null);
    const row: Record<string, unknown> = {
      seq: '7',
      xid: '900',
      id: inserted['id'],
      realm_id: inserted['realm_id'],
      category: inserted['category'],
      type: inserted['type'],
      time: String(inserted['time']),
      actor_type: inserted['actor_type'] ?? null,
      actor_id: inserted['actor_id'] ?? null,
      actor_delegation_chain: json(inserted['actor_delegation_chain']),
      subject_type: inserted['subject_type'] ?? null,
      subject_id: inserted['subject_id'] ?? null,
      client_id: inserted['client_id'] ?? null,
      request_id: inserted['request_id'] ?? null,
      request_ip: inserted['request_ip'] ?? null,
      request_user_agent: inserted['request_user_agent'] ?? null,
      data: json(inserted['data']),
      schema_version: inserted['schema_version'],
      prev_hash: inserted['prev_hash'],
      hash: inserted['hash'],
    };
    tamper(row);
    return [row];
  };
}

const ADMIN_CHANGE: AdminEventInput = {
  realm: REALM_ID,
  actor: { type: 'user', id: USER_ID },
  operation: 'realms.mail.write',
  target: { type: 'realm', id: REALM_ID },
  before: { smtp: { host: 'mail.example', password: 'hunter2' }, fromName: 'QAuth' },
  after: { smtp: { host: 'mail.example', password: 'hunter3' }, fromName: 'Ops' },
  approvals: [
    {
      approverId: '0192f1c4-5555-7000-8000-000000000005',
      credentialId: 'cred-a',
      approverCreatedBy: { type: 'operator_cli', id: 'root' },
    },
  ],
  request: { traceId: 'req-9' },
};

describe('emitAdminEvent', () => {
  it("takes the realm's chain lock, reads the head, and writes the event as the next link", async () => {
    const { db, queries } = createRecordingDb([], chainResponder());
    const repo = createEventsRepository(db, { now: () => NOW });

    const id = await db.transaction((tx) => repo.emitAdminEvent(tx, ADMIN_CHANGE));

    expect(queries.map((q) => q.text.trim().split(/\s+/).slice(0, 2).join(' '))).toEqual([
      'begin',
      'select pg_advisory_xact_lock(hashtextextended($1::text',
      'select "events_admin_chain_head"($1::uuid)',
      // The insert and its read-back run in a savepoint, undone on a mismatch.
      'savepoint sp1',
      'insert into',
      'select "events"."seq"::text',
      'release savepoint',
      'commit',
    ]);
    expect(queries[1].values).toEqual(['qauth:events:admin-chain:', REALM_ID]);
    const inserted = insertedColumns(insertOf(queries));
    expect(inserted).toMatchObject({
      id,
      category: 'admin',
      type: 'urn:qauth:event:admin.change_applied:v1-rc.0',
      actor_type: 'user',
      actor_id: USER_ID,
      request_id: 'req-9',
    });
    expect(JSON.parse(String(inserted['data']))).toEqual({
      operation: 'realms.mail.write',
      target: { type: 'realm', id: REALM_ID },
      diff: [
        { path: '/fromName', before: 'QAuth', after: 'Ops' },
        { path: '/smtp/password', before: '***', after: '***' },
      ],
      approvals: ADMIN_CHANGE.approvals,
    });
    // The realm's first admin event follows the genesis hash.
    expect(inserted['prev_hash']).toEqual(EVENT_CHAIN_GENESIS_HASH);
    expect((inserted['hash'] as Buffer).length).toBe(32);
    expect(String(inserted['data'])).not.toContain('hunter');
  });

  it('refuses to emit, and undoes the insert, when the stored row does not hash as it was written', async () => {
    const { db, queries } = createRecordingDb(
      [],
      chainResponder((row) => {
        row['data'] = { ...(row['data'] as object), operation: 'realms.delete' };
      })
    );
    const repo = createEventsRepository(db, { now: () => NOW });

    // The caller catches the error and commits: the insert is undone all the same.
    await db.transaction(async (tx) => {
      await expect(repo.emitAdminEvent(tx, ADMIN_CHANGE)).rejects.toThrow(
        /does not hash as it was written; nothing was emitted/
      );
    });
    expect(queries.slice(-2).map((q) => q.text)).toEqual(['rollback to savepoint sp1', 'commit']);
  });

  it('leaves an empty request out, so the stored row hashes as it was written', async () => {
    const { db, queries } = createRecordingDb([], chainResponder());
    const repo = createEventsRepository(db, { now: () => NOW });

    await db.transaction((tx) => repo.emitAdminEvent(tx, { ...ADMIN_CHANGE, request: {} }));

    expect(queries.map((q) => q.text)).toContain('release savepoint sp1');
    expect(insertedColumns(insertOf(queries))['request_id']).toBeNull();
  });

  it('hands a chained admin event to the telemetry sink once it commits, in a transaction or its own', async () => {
    // One recording database per write: the chain's read-back answers with
    // the first INSERT it recorded.
    const inTx = createRecordingDb([], chainResponder());
    const inTxSink = recordingSink(inTx.queries);
    const inTxRepo = createEventsRepository(inTx.db, { now: () => NOW, telemetry: inTxSink.sink });
    const own = createRecordingDb([], chainResponder());
    const ownSink = recordingSink(own.queries);
    const ownRepo = createEventsRepository(own.db, { now: () => NOW, telemetry: ownSink.sink });

    const inTxId = await inTx.db.transaction((tx) => inTxRepo.emitAdminEvent(tx, ADMIN_CHANGE));
    const ownId = await ownRepo.emitInOwnTransaction({
      type: 'urn:qauth:event:client.suspended:v1-rc.0',
      realm: REALM_ID,
      actor: { type: 'operator_cli', id: 'root' },
      subject: { type: 'client', id: 'portal' },
      data: {},
    });

    expect(inTxSink.handed.map((entry) => entry.event.id)).toEqual([inTxId]);
    expect(ownSink.handed.map((entry) => entry.event.id)).toEqual([ownId]);
    for (const entry of [...inTxSink.handed, ...ownSink.handed]) {
      expect(entry.statements.at(-1)).toBe('commit');
    }
  });

  it('chains every admin type that emit writes, not only its own', async () => {
    const { db, queries } = createRecordingDb([], chainResponder());
    const repo = createEventsRepository(db, { now: () => NOW });

    await repo.emit(asTransaction(db), {
      type: 'urn:qauth:event:client.suspended:v1-rc.0',
      realm: REALM_ID,
      actor: { type: 'operator_cli', id: 'root' },
      subject: { type: 'client', id: 'portal' },
      data: {},
    });

    expect(queries[0].text).toContain('pg_advisory_xact_lock');
    expect(insertedColumns(insertOf(queries))['hash']).toBeInstanceOf(Buffer);
  });

  it('refuses an admin change without an actor, or with a target that is not JSON, and writes nothing', async () => {
    const { db, queries } = createRecordingDb();
    const repo = createEventsRepository(db);

    await expect(
      repo.emitAdminEvent(asTransaction(db), { ...ADMIN_CHANGE, actor: undefined } as never)
    ).rejects.toThrow(/needs the actor/);
    await expect(
      repo.emitAdminEvent(asTransaction(db), {
        ...ADMIN_CHANGE,
        after: { at: new Date(0) } as never,
      })
    ).rejects.toThrow(TypeError);
    await expect(
      repo.emitAdminEvent(asTransaction(db), { ...ADMIN_CHANGE, operation: 'Not An Id' })
    ).rejects.toThrow(EventValidationError);
    expect(queries).toHaveLength(0);
  });

  it('stores only the members an approval names', async () => {
    const { db, queries } = createRecordingDb([], chainResponder());
    const repo = createEventsRepository(db, { now: () => NOW });
    const [first] = ADMIN_CHANGE.approvals ?? [];
    const approval = { ...first, note: 'from a decoded token' };

    await repo.emitAdminEvent(asTransaction(db), { ...ADMIN_CHANGE, approvals: [approval] });

    const data = JSON.parse(String(insertedColumns(insertOf(queries))['data']));
    expect(data.approvals).toEqual(ADMIN_CHANGE.approvals);
  });
});

describe('verifyChain', () => {
  const genesis = EVENT_CHAIN_GENESIS_HASH.toString('hex');

  it('refuses a realm id that is no UUID and a point that is not one, before it reads', async () => {
    const { db, queries } = createRecordingDb();
    const repo = createEventsRepository(db);

    await expect(repo.verifyChain('master')).rejects.toThrow(TypeError);
    await expect(repo.verifyChain(REALM_ID, { seq: 0n, hash: 'abc' })).rejects.toThrow(
      /64 hex digits/
    );
    await expect(repo.verifyChain(REALM_ID, { seq: -1n, hash: genesis })).rejects.toThrow(/seq/);
    await expect(
      repo.verifyChain(REALM_ID, { seq: 1 as unknown as bigint, hash: genesis })
    ).rejects.toThrow(/bigint/);
    expect(queries).toHaveLength(0);
  });

  it('refuses a batch size that is not a positive integer', () => {
    const { db } = createRecordingDb();
    expect(() => createEventsRepository(db, { verifyBatchSize: 0 })).toThrow(TypeError);
    expect(() => createEventsRepository(db, { verifyBatchSize: 1.5 })).toThrow(TypeError);
  });

  it('hashes what a reader gets back, so the stored envelope is what the chain covers', () => {
    const envelope = {
      id: '0192f1c4-9999-7000-8000-000000000009',
      type: 'urn:qauth:event:client.suspended:v1-rc.0',
      time: new Date(NOW).toISOString(),
      realm: REALM_ID,
      category: 'admin' as const,
      data: {},
    };
    const { data, category, ...rest } = envelope;
    const reordered = { data, category, ...rest };
    expect(eventChainHash(EVENT_CHAIN_GENESIS_HASH, reordered)).toEqual(
      eventChainHash(EVENT_CHAIN_GENESIS_HASH, envelope)
    );
  });
});

describe('types', () => {
  it('needs a realm id on every read, and a transaction to emit in', () => {
    const { db } = createRecordingDb();
    const repo: EventsRepository = createEventsRepository(db);
    const start = eventStreamStart(REALM_ID);

    // Type-checked by the `typecheck` target, never called.
    const misuses = () => {
      // @ts-expect-error a read without a realm id
      void repo.readAfter(start, 10);
      // @ts-expect-error a realm id that may be missing
      void repo.readAfter(undefined, start, 10);
      // @ts-expect-error a position is made by the store, not spelled by hand
      void repo.readAfter(REALM_ID, 'p1:anything', 10);
      // @ts-expect-error the root database is not the transaction of a change
      void repo.emit(db, SIGNED_IN);
      void repo.emit(asTransaction(db), {
        ...SIGNED_IN,
        // @ts-expect-error data of another type
        data: { method: 'password', reason: 'invalid_credentials' },
      });
    };

    expect(misuses).toBeTypeOf('function');
    expectTypeOf<Parameters<EventsRepository['readAfter']>[0]>().toEqualTypeOf<string>();
    expectTypeOf<Parameters<EventsRepository['emit']>[0]>().toEqualTypeOf<DbTransaction>();
  });
});
