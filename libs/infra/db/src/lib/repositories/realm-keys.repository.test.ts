import { drizzle } from 'drizzle-orm/node-postgres';
import type { Pool } from 'pg';
import { describe, expect, it } from 'vitest';

import type { RealmKeysRepository } from '../../types';
import type { DbClient } from '../db';
import { createRealmKeysRepository } from './realm-keys.repository';

/**
 * SQL-shape tests for the realm keys repository (issue #461).
 *
 * ADR-019 Decision 9 lets only the signer read wrapped key material. In code
 * that is one rule: `getWrappedForSigner` is the only method whose statements
 * read `ciphertext`, `iv` or `wrapped_dek`. These tests run every method
 * against a client that records the SQL instead of executing it, so the rule
 * is checked without Docker. The container-backed suite
 * (`realm-keys.integration.test.ts`) covers the constraints.
 */

interface CapturedQuery {
  readonly text: string;
  readonly values: readonly unknown[];
}

/** The columns that hold wrapped key material, as Postgres names them. */
const WRAPPED_COLUMNS = ['ciphertext', 'iv', 'wrapped_dek'] as const;

const REALM_ID = '0190a000-0000-7000-8000-000000000001';
const KID = 'kid-1';

/**
 * A `pg` client that records queries instead of running them. Every query
 * answers with `rows`; `create` needs one row back from its first insert.
 */
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

/**
 * The part of a statement that reads data back: the select list of a
 * `SELECT`, or the `RETURNING` list of a write. An insert NAMES the wrapped
 * columns in order to write them, which is not reading them. A statement
 * that opens with a CTE is taken whole, so a read hidden in it still counts.
 */
function readList(statement: string): string {
  const text = statement.toLowerCase().trim();
  if (text.startsWith('with ')) {
    return text;
  }
  if (text.startsWith('select ')) {
    return text.slice('select '.length, text.indexOf(' from '));
  }
  const returning = text.indexOf(' returning ');
  return returning === -1 ? '' : text.slice(returning + ' returning '.length);
}

/** Wrapped columns read by any of the statements. A `*` reads all of them. */
function wrappedColumnsRead(queries: readonly CapturedQuery[]): string[] {
  return WRAPPED_COLUMNS.filter((column) =>
    queries.some((query) => {
      const list = readList(query.text);
      return list.includes(`"${column}"`) || /(^|[\s,.])\*/.test(list);
    })
  );
}

/**
 * A row in the shape `create`'s first insert reads back (the metadata columns,
 * in order). Its mirror values differ from {@link NEW_KEY}'s on purpose, so a
 * test can tell copying from the stored row apart from copying the input.
 */
const STORED = {
  realmId: '0190a000-0000-7000-8000-0000000000bb',
  purpose: 'stored-purpose',
  algorithm: 'stored-alg',
  kid: 'stored-kid',
  status: 'next',
  unpublishAt: 1_800_000_000_999,
} as const;
const CREATED_ROW = [
  '0190a000-0000-7000-8000-0000000000aa', // id
  STORED.realmId, // realm_id
  STORED.purpose, // purpose
  null, // scope_id
  STORED.algorithm, // algorithm
  STORED.kid, // kid
  STORED.status, // status
  null, // pair_id
  'kek-ref', // kek_ref
  1, // aad_version
  1_800_000_000_000, // created_at
  1_800_000_000_000, // publish_at
  1_800_000_000_000, // activate_at
  null, // retire_at
  STORED.unpublishAt, // unpublish_at
  null, // compromised_at
];

const NEW_KEY = {
  realmId: REALM_ID,
  purpose: 'token_signing',
  algorithm: 'EdDSA',
  kid: KID,
  status: 'active',
  ciphertext: Buffer.from('ciphertext'),
  iv: Buffer.from('iv-iv-iv-iv-'),
  wrappedDek: Buffer.from('wrapped-dek'),
  kekRef: 'kek-ref',
  aadVersion: 1,
  publishAt: 1_800_000_000_000,
} as const;

/**
 * One call per repository method. Typed over `keyof RealmKeysRepository`, so a
 * new method does not compile until it is listed here, and the test below
 * fails if the factory returns one this map does not know.
 */
const CALLS: Record<keyof RealmKeysRepository, (repo: RealmKeysRepository) => Promise<unknown>> = {
  create: (repo) =>
    repo.create({ key: NEW_KEY, publicJwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAA' } }),
  findByKid: (repo) => repo.findByKid(REALM_ID, KID),
  listByRealm: (repo) =>
    repo.listByRealm(REALM_ID, { purpose: 'token_signing', scopeId: null, status: 'active' }),
  listPublicByRealm: (repo) => repo.listPublicByRealm(REALM_ID),
  getWrappedForSigner: (repo) => repo.getWrappedForSigner(REALM_ID, KID),
  updateStatus: (repo) =>
    repo.updateStatus(REALM_ID, KID, {
      status: 'retired',
      retireAt: 1_800_000_000_000,
      unpublishAt: 1_801_209_600_000,
    }),
  deleteByScope: (repo) => repo.deleteByScope(REALM_ID, 'webhook_signing', 'subscription-1'),
};

async function run(method: keyof RealmKeysRepository): Promise<CapturedQuery[]> {
  const { db, queries } = createRecordingDb([CREATED_ROW]);
  await CALLS[method](createRealmKeysRepository(db));
  return queries;
}

describe('createRealmKeysRepository — wrapped material', () => {
  it('lists every method the factory returns', () => {
    const { db } = createRecordingDb();
    const methods = Object.keys(createRealmKeysRepository(db)).sort();

    expect(methods).toEqual(Object.keys(CALLS).sort());
  });

  const others = (Object.keys(CALLS) as (keyof RealmKeysRepository)[]).filter(
    (method) => method !== 'getWrappedForSigner'
  );

  it.each(others)('%s never selects ciphertext, iv or wrapped_dek', async (method) => {
    const queries = await run(method);

    // The method must have read something, or the check below proves nothing.
    expect(queries.some((query) => readList(query.text).length > 0)).toBe(true);
    expect(wrappedColumnsRead(queries)).toEqual([]);
  });

  it('getWrappedForSigner selects all three wrapped columns', async () => {
    // Also proves the detection above works: the same check finds them here.
    const queries = await run('getWrappedForSigner');

    expect(wrappedColumnsRead(queries)).toEqual([...WRAPPED_COLUMNS]);
  });
});

describe('createRealmKeysRepository — statements', () => {
  it('create writes the key and its public row inside one transaction', async () => {
    const queries = (await run('create')).map((query) => query.text.toLowerCase());

    expect(queries).toHaveLength(4);
    expect(queries[0]).toBe('begin');
    expect(queries[1]).toContain('insert into "realm_keys"');
    expect(queries[2]).toContain('insert into "realm_public_keys"');
    expect(queries[3]).toBe('commit');
  });

  it('create copies the mirror columns from the stored key row', async () => {
    const queries = await run('create');
    const publicInsert = queries[2];

    expect(publicInsert.values).toEqual(
      expect.arrayContaining([
        STORED.kid,
        STORED.realmId,
        STORED.purpose,
        STORED.algorithm,
        STORED.status,
        STORED.unpublishAt,
        NEW_KEY.publishAt,
        JSON.stringify({ kty: 'OKP', crv: 'Ed25519', x: 'AAAA' }),
      ])
    );
    for (const input of [KID, REALM_ID, NEW_KEY.purpose, NEW_KEY.algorithm, NEW_KEY.status]) {
      expect(publicInsert.values).not.toContain(input);
    }
  });

  it('create writes no public row for a key without a public JWK', async () => {
    const { db, queries } = createRecordingDb([CREATED_ROW]);

    await createRealmKeysRepository(db).create({
      key: { ...NEW_KEY, purpose: 'cookie_hmac', algorithm: 'HS256', publishAt: undefined },
    });

    const texts = queries.map((query) => query.text.toLowerCase());
    expect(texts.some((text) => text.includes('"realm_public_keys"'))).toBe(false);
    expect(texts.filter((text) => text.includes('insert into "realm_keys"'))).toHaveLength(1);
  });

  it.each(['findByKid', 'getWrappedForSigner'] as const)(
    '%s looks a kid up inside the given realm only',
    async (method) => {
      const [query] = await run(method);
      const text = query.text.toLowerCase();

      expect(text).toContain('"realm_keys"."realm_id" = $1');
      expect(text).toContain('"realm_keys"."kid" = $2');
      expect(query.values.slice(0, 2)).toEqual([REALM_ID, KID]);
    }
  );

  it('listByRealm narrows by purpose, unscoped and status', async () => {
    const [query] = await run('listByRealm');
    const text = query.text.toLowerCase();

    expect(text).toContain('"realm_keys"."purpose" = $2');
    expect(text).toContain('"realm_keys"."scope_id" is null');
    expect(text).toContain('"realm_keys"."status" = $3');
    expect(query.values).toEqual([REALM_ID, 'token_signing', 'active']);
  });

  it('listPublicByRealm reads realm_public_keys of the given realm only, in a fixed order', async () => {
    const [query] = await run('listPublicByRealm');
    const text = query.text.toLowerCase();

    expect(text).toContain('from "realm_public_keys"');
    expect(text).not.toContain('"realm_keys"');
    expect(text).toContain('"realm_public_keys"."realm_id" = $1');
    expect(text).toMatch(
      /order by "realm_public_keys"\."purpose" asc, "realm_public_keys"\."publish_at" asc, "realm_public_keys"\."kid" asc/
    );
    expect(query.values).toEqual([REALM_ID]);
  });

  it('updateStatus retires the key and closes its public window inside one transaction', async () => {
    const queries = await run('updateStatus');
    const texts = queries.map((query) => query.text.toLowerCase());

    expect(texts).toHaveLength(4);
    expect(texts[0]).toBe('begin');
    expect(texts[1]).toContain(
      'update "realm_keys" set "status" = $1, "retire_at" = $2, "unpublish_at" = $3'
    );
    expect(texts[1]).toContain('"realm_keys"."status" = $6');
    expect(queries[1].values).toEqual([
      'retired',
      1_800_000_000_000,
      1_801_209_600_000,
      REALM_ID,
      KID,
      'active',
    ]);
    // The status reaches the public row through the foreign key; only the
    // window is written there.
    expect(texts[2]).toContain('update "realm_public_keys" set "unpublish_at" = $1');
    expect(texts[2]).not.toContain('"status"');
    expect(queries[2].values).toEqual([1_801_209_600_000, REALM_ID, KID]);
    expect(texts[3]).toBe('commit');
  });

  it('updateStatus activates only a next key and leaves the public row to its foreign key', async () => {
    const { db, queries } = createRecordingDb([CREATED_ROW]);

    await createRealmKeysRepository(db).updateStatus(REALM_ID, KID, {
      status: 'active',
      activateAt: 1_800_000_000_000,
    });

    const texts = queries.map((query) => query.text.toLowerCase());
    expect(texts.filter((text) => text.startsWith('update'))).toHaveLength(1);
    expect(texts[1]).toContain('update "realm_keys" set "status" = $1, "activate_at" = $2');
    expect(queries[1].values).toEqual(['active', 1_800_000_000_000, REALM_ID, KID, 'next']);
  });

  it('updateStatus writes no public row for an unpublished key, nor for a key it did not move', async () => {
    for (const rows of [[CREATED_ROW], []]) {
      const { db, queries } = createRecordingDb(rows);

      await createRealmKeysRepository(db).updateStatus(REALM_ID, KID, {
        status: 'retired',
        retireAt: 1_800_000_000_000,
        unpublishAt: rows.length === 0 ? 1_801_209_600_000 : null,
      });

      expect(queries.some((query) => query.text.includes('"realm_public_keys"'))).toBe(false);
    }
  });

  it('deleteByScope deletes the keys of one realm, purpose and scope only', async () => {
    const [query] = await run('deleteByScope');
    const text = query.text.toLowerCase();

    expect(text).toContain('delete from "realm_keys"');
    expect(text).toContain('"realm_keys"."realm_id" = $1');
    expect(text).toContain('"realm_keys"."purpose" = $2');
    expect(text).toContain('"realm_keys"."scope_id" = $3');
    expect(query.values).toEqual([REALM_ID, 'webhook_signing', 'subscription-1']);
  });

  it('listByRealm without a filter narrows by realm only', async () => {
    const { db, queries } = createRecordingDb();

    await createRealmKeysRepository(db).listByRealm(REALM_ID);

    expect(queries[0].values).toEqual([REALM_ID]);
  });
});
