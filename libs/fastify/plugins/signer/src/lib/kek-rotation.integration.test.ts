/**
 * Real-Postgres integration tests for the KEK rotation's wiring (#545):
 * `rotateKek` and `countKeysPerKek` over the realm keys repository, the path
 * the operator command `auth-server:keys:rewrap` takes, against the migrated
 * schema.
 *
 * Requires Docker; self-skips without it, like the other container suites.
 */
import { randomUUID } from 'node:crypto';

import {
  createDatabase,
  createRealmsRepository,
  type DatabaseInstance,
  type DbClient,
} from '@qauth-labs/infra-db';
import {
  type ApprovedOperation,
  KEK_ROTATE_OPERATION,
  type KekRotateOperation,
  newOperationNonce,
} from '@qauth-labs/server-keys';
import { computeKekRef } from '@qauth-labs/server-keys/custody';
import {
  requireDockerOrSkip,
  type StartedPostgres,
  startPostgresContainer,
  truncateDomainTablesStatement,
} from '@qauth-labs/shared-testing';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { countKeysPerKek, listRealmIdsWithKeys, rotateKek } from './kek-rotation';
import { createRealmKey } from './realm-keys';

const KEK_A = Buffer.alloc(32, 0xa1).toString('base64');
const KEK_B = Buffer.alloc(32, 0xb2).toString('base64');
const REF_A = computeKekRef(Buffer.from(KEK_A, 'base64'));
const REF_B = computeKekRef(Buffer.from(KEK_B, 'base64'));
const REALM = 'master';
const ISSUER = 'https://auth.example.test';

describe('rotateKek integration (real Postgres)', () => {
  let container: StartedPostgres | undefined;
  let database: DatabaseInstance | undefined;
  let dockerUp = false;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    container = await startPostgresContainer({ schema: 'migrated' });
    database = createDatabase({ connectionString: container.connectionString });
  }, 180_000);

  afterAll(async () => {
    await database?.close();
    await container?.stop();
  });

  beforeEach(async (testCtx) => {
    if (!dockerUp || !database) {
      testCtx.skip();
      return;
    }
    await database.pool.query(truncateDomainTablesStatement());
    await createRealmsRepository(database.db).createWithPrimaryHost(
      { name: REALM, issuer: ISSUER },
      'auth.example.test'
    );
  });

  function deps(kekEnv: Record<string, string>) {
    if (!database) throw new Error('no database');
    return {
      db: database.db,
      kekEnv: { NODE_ENV: 'test', ...kekEnv },
      warn: () => undefined,
      enabledSignatureAlgorithms: ['EdDSA'] as const,
      hybridSigning: false,
    };
  }

  it('re-wraps the stored keys to the KEK the host wraps under, and counts them per reference', async () => {
    for (const purpose of ['token_signing', 'event_signing', 'cookie_hmac', 'data_at_rest']) {
      await createRealmKey(deps({ KEK: KEK_A }), { realmName: REALM, purpose });
    }
    const consumed: { digest: Buffer; tx: DbClient }[] = [];
    const audited: DbClient[] = [];
    const approval: ApprovedOperation<KekRotateOperation, DbClient> = {
      id: randomUUID(),
      operation: KEK_ROTATE_OPERATION,
      requester: { kind: 'break_glass', operatingSystemUser: 'qauth-ops' },
      nonce: newOperationNonce(),
      consume: async (digest, tx) => {
        consumed.push({ digest, tx });
      },
    };

    await expect(countKeysPerKek(deps({ KEK: KEK_B, KEK_PREVIOUS: KEK_A }))).resolves.toEqual([
      { kekRef: REF_A, rows: 4, current: false, opens: true },
    ]);

    // `to` is left out: the host's current KEK.
    const report = await rotateKek(deps({ KEK: KEK_B, KEK_PREVIOUS: KEK_A }), {
      from: REF_A,
      approval,
      onAudit: async (_entry, tx) => {
        audited.push(tx);
      },
    });

    expect(report).toMatchObject({ from: REF_A, to: REF_B, rewrapped: 4, complete: true });
    // The realms whose audit log the operator command records the run in.
    if (!database) throw new Error('no database');
    const { db } = database;
    const realm = await createRealmsRepository(db).findByName(REALM);
    await expect(listRealmIdsWithKeys(db, null, 10)).resolves.toEqual([realm?.id]);
    await expect(listRealmIdsWithKeys(db, realm?.id ?? null, 10)).resolves.toEqual([]);
    expect(consumed).toHaveLength(1);
    expect(audited).toEqual([consumed[0].tx]);
    // A host with the new KEK alone opens every key.
    await expect(countKeysPerKek(deps({ KEK: KEK_B }))).resolves.toEqual([
      { kekRef: REF_B, rows: 4, current: true, opens: true },
    ]);
    // And one with the old KEK alone opens none.
    await expect(countKeysPerKek(deps({ KEK: KEK_A }))).resolves.toEqual([
      { kekRef: REF_B, rows: 4, current: false, opens: false, reason: 'KEK_UNKNOWN_REF' },
    ]);
  });

  it('refuses a source KEK the host does not hold, with nothing consumed or moved', async () => {
    await createRealmKey(deps({ KEK: KEK_A }), { realmName: REALM, purpose: 'data_at_rest' });
    let consumed = 0;

    await expect(
      rotateKek(deps({ KEK: KEK_B }), {
        from: REF_A,
        approval: {
          id: randomUUID(),
          operation: KEK_ROTATE_OPERATION,
          requester: { kind: 'break_glass', operatingSystemUser: 'qauth-ops' },
          nonce: newOperationNonce(),
          consume: async () => {
            consumed += 1;
          },
        },
        onAudit: async () => undefined,
      })
    ).rejects.toMatchObject({ code: 'KEK_REWRAP_REFUSED', reason: 'FROM_KEK_NOT_HELD' });
    expect(consumed).toBe(0);
    await expect(countKeysPerKek(deps({ KEK: KEK_B, KEK_PREVIOUS: KEK_A }))).resolves.toEqual([
      { kekRef: REF_A, rows: 1, current: false, opens: true },
    ]);
  });
});
