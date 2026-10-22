import { drizzle } from 'drizzle-orm/node-postgres';
import type { Pool } from 'pg';
import { describe, expect, it, vi } from 'vitest';

import type { AdminAuditEntry, Database, DbTransaction } from '../../types';
import { ADMIN_AUDIT_SECRET_MARKER } from '../admin-audit/mask-secrets';
import { ADMIN_AUDIT_GENESIS_HASH } from '../admin-audit/row-hash';
import type { AdminAuditActChain } from '../admin-audit/types';
import { createAdminAuditLogRepository } from './admin-audit-log.repository';

/**
 * Statement-level tests for `appendAdminAudit` (issue #448), without Docker:
 * what it locks, in which order, and what it binds into the INSERT. The
 * container suite (`admin-audit-log.integration.test.ts`) runs the chain,
 * the triggers and the grants against Postgres.
 */

interface CapturedQuery {
  readonly text: string;
  readonly values: readonly unknown[];
}

/**
 * A `pg` client that records queries instead of running them. Reads find no
 * row; an INSERT ... RETURNING gives back the values it bound, in column
 * order, the way Postgres returns a row it stored unchanged. `stored` can
 * alter that row, the way Postgres would by cutting a value.
 */
function createRecordingDb(stored: (row: unknown[]) => unknown[] = (row) => row): {
  db: Database;
  queries: CapturedQuery[];
} {
  const queries: CapturedQuery[] = [];
  const client = {
    query: (config: { text?: string; values?: unknown[] } | string, values?: unknown[]) => {
      const text = typeof config === 'string' ? config : (config.text ?? '');
      const params = typeof config === 'string' ? (values ?? []) : (config.values ?? values ?? []);
      queries.push({ text, values: params });
      const rows = text.toLowerCase().startsWith('insert into') ? [stored([...params])] : [];
      return Promise.resolve({ rows, rowCount: rows.length, fields: [], command: '', oid: 0 });
    },
  };
  return { db: drizzle(client as unknown as Pool) as unknown as Database, queries };
}

const REALM_ID = '0192f1c4-1111-7000-8000-000000000001';
const ADMIN_ID = '0192f1c4-2222-7000-8000-000000000002';
const OPERATOR_REALM_ID = '0192f1c4-3333-7000-8000-000000000003';
const USER_ID = '0192f1c4-4444-7000-8000-000000000004';

const ENTRY: AdminAuditEntry = {
  realmId: REALM_ID,
  actorKind: 'human_admin',
  actorId: ADMIN_ID,
  actorRealmId: OPERATOR_REALM_ID,
  operationId: 'realms.policies.write',
  operationClass: 'write',
  outcome: 'succeeded',
};

/** The bound values that are JSON text, parsed. */
function jsonValues(query: CapturedQuery): unknown[] {
  return query.values.flatMap((value) => {
    if (typeof value !== 'string' || !/^[[{]/.test(value)) return [];
    return [JSON.parse(value)];
  });
}

function insertQuery(queries: CapturedQuery[]): CapturedQuery {
  const insert = queries.find((q) =>
    q.text.toLowerCase().startsWith('insert into "admin_audit_log"')
  );
  if (!insert) throw new Error('no INSERT into admin_audit_log');
  return insert;
}

describe('appendAdminAudit', () => {
  it('takes the realm chain lock before it reads the chain head and inserts', async () => {
    const { db, queries } = createRecordingDb();

    await createAdminAuditLogRepository(db).appendAdminAudit(db as unknown as DbTransaction, ENTRY);

    const texts = queries.map((q) => q.text.toLowerCase());
    const lock = texts.findIndex((t) => t.includes('pg_advisory_xact_lock('));
    const head = texts.findIndex((t) => t.startsWith('select') && t.includes('"admin_audit_log"'));
    const insert = texts.findIndex((t) => t.startsWith('insert into "admin_audit_log"'));
    expect(lock).toBe(0);
    expect(head).toBeGreaterThan(lock);
    expect(insert).toBeGreaterThan(head);
    expect(texts[lock]).toContain("hashtextextended('qauth:admin-audit:'");
    expect(queries[lock].values).toEqual([REALM_ID]);
  });

  it('starts an empty chain at seq 1 on the genesis hash', async () => {
    const { db, queries } = createRecordingDb();

    await createAdminAuditLogRepository(db, { now: () => 1_800_000_000_000 }).appendAdminAudit(
      db as unknown as DbTransaction,
      ENTRY
    );

    const insert = insertQuery(queries);
    expect(insert.values).toContain(1);
    expect(insert.values).toContain(1_800_000_000_000);
    expect(
      insert.values.some(
        (value) => Buffer.isBuffer(value) && value.equals(ADMIN_AUDIT_GENESIS_HASH)
      )
    ).toBe(true);
  });

  it('stores a secret field of the diff as the marker, never as its value', async () => {
    const { db, queries } = createRecordingDb();
    const oldHash = '$argon2id$v=19$m=19456,t=2,p=1$old-salt$old-hash';
    const newHash = '$argon2id$v=19$m=19456,t=2,p=1$new-salt$new-hash';

    await createAdminAuditLogRepository(db).appendAdminAudit(db as unknown as DbTransaction, {
      ...ENTRY,
      operationId: 'clients.secret.rotate',
      operationClass: 'security',
      diff: {
        change: {
          before: { clientId: 'portal', clientSecretHash: oldHash },
          after: { clientId: 'portal', clientSecretHash: newHash },
        },
        annotations: { clientSecretHash: 'secret' },
      },
    });

    const insert = insertQuery(queries);
    expect(jsonValues(insert)).toContainEqual({
      before: { clientId: 'portal', clientSecretHash: ADMIN_AUDIT_SECRET_MARKER },
      after: { clientId: 'portal', clientSecretHash: ADMIN_AUDIT_SECRET_MARKER },
    });
    const bound = JSON.stringify(insert.values);
    expect(bound).not.toContain('old-hash');
    expect(bound).not.toContain('new-hash');
  });

  it('stores the full act chain, every actor with its identity claims', async () => {
    const { db, queries } = createRecordingDb();
    // Deeper than the four actors QAuth mints, with claims beyond `sub`: none
    // of it may be flattened or cut.
    const actChain: AdminAuditActChain = {
      sub: USER_ID,
      act: {
        sub: ADMIN_ID,
        iss: 'https://operator.example.test',
        act: {
          sub: 'console',
          client_id: 'console',
          act: {
            sub: 'agent-c',
            act: { sub: 'agent-b', act: { sub: 'agent-a', iss: 'https://idp.example.test' } },
          },
        },
      },
    };

    await createAdminAuditLogRepository(db).appendAdminAudit(db as unknown as DbTransaction, {
      ...ENTRY,
      actChain,
    });

    expect(jsonValues(insertQuery(queries))).toContainEqual(actChain);
  });

  it('stores only the members an act claim and an approval name', async () => {
    const { db, queries } = createRecordingDb();
    const approval = {
      approverId: 'admin-2',
      credentialId: 'cred-2',
      approverCreatedBy: 'admin-1',
      approvedAt: 1_800_000_000_000,
      assertion: 'webauthn-assertion-bytes',
    };

    await createAdminAuditLogRepository(db).appendAdminAudit(db as unknown as DbTransaction, {
      ...ENTRY,
      actChain: {
        sub: USER_ID,
        act: { sub: ADMIN_ID, token: 'eyJ.raw.token' } as AdminAuditActChain['act'],
      },
      approvals: [approval],
    });

    const bound = JSON.stringify(insertQuery(queries).values);
    expect(bound).not.toContain('eyJ.raw.token');
    expect(bound).not.toContain('webauthn-assertion-bytes');
    expect(jsonValues(insertQuery(queries))).toContainEqual({
      sub: USER_ID,
      act: { sub: ADMIN_ID },
    });
  });

  it('refuses a row that Postgres stored differently from what it hashed', async () => {
    // Postgres cuts trailing spaces past a varchar limit; any such change to
    // the stored row must fail the append, not break the chain later.
    const { db } = createRecordingDb((row) =>
      row.map((value) => (value === 'trace-1' ? 'trace-' : value))
    );

    await expect(
      createAdminAuditLogRepository(db).appendAdminAudit(db as unknown as DbTransaction, {
        ...ENTRY,
        traceId: 'trace-1',
      })
    ).rejects.toThrow('does not hash to its row_hash');
  });

  it('calls the outbox hook after the insert, in the same transaction', async () => {
    const { db, queries } = createRecordingDb();
    const afterAppend = vi.fn(async () => {
      expect(queries.some((q) => q.text.toLowerCase().startsWith('insert into'))).toBe(true);
    });
    const tx = db as unknown as DbTransaction;

    await createAdminAuditLogRepository(db, { afterAppend }).appendAdminAudit(tx, ENTRY);

    expect(afterAppend).toHaveBeenCalledOnce();
    expect(afterAppend.mock.calls[0]).toContain(tx);
  });

  it.each<[string, Partial<AdminAuditEntry>]>([
    ['a realm id that is not a UUID', { realmId: 'master' }],
    ['a realm id Postgres would print differently', { realmId: `{${REALM_ID}}` }],
    ['a human admin without an actor realm', { actorRealmId: null }],
    [
      'a host operator with an actor realm',
      { actorKind: 'host_operator', actorRealmId: OPERATOR_REALM_ID },
    ],
    ['a request digest that is not 32 bytes', { requestDigest: Buffer.alloc(31) }],
    ['a trace id longer than its column', { traceId: `${'a'.repeat(128)}   ` }],
    ['an actor id longer than its column', { actorId: 'a'.repeat(256) }],
    ['an operation id longer than its column', { operationId: 'o'.repeat(129) }],
    [
      'an act chain actor without a sub',
      { actChain: { sub: USER_ID, act: {} as AdminAuditActChain['act'] } },
    ],
    [
      'a diff value outside I-JSON',
      { diff: { change: { before: null, after: { n: Number.NaN } }, annotations: {} } },
    ],
  ])('refuses %s and inserts nothing', async (_label, change) => {
    const { db, queries } = createRecordingDb();

    await expect(
      createAdminAuditLogRepository(db).appendAdminAudit(db as unknown as DbTransaction, {
        ...ENTRY,
        ...change,
      })
    ).rejects.toThrow(TypeError);
    expect(queries.filter((q) => q.text.toLowerCase().startsWith('insert'))).toEqual([]);
  });
});
