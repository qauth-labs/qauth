/**
 * Real-Postgres integration tests for the KEK rotation (#545, ADR-019
 * Decision 9).
 *
 * Realms are provisioned under one KEK into the migrated `realm_keys` table,
 * then re-wrapped to another through plain SQL of the shape the realm keys
 * repository runs in production. Each check reads the rows back as a node
 * that starts then would: with a provider of the new KEK alone, a signer
 * built for it, or a census of the table.
 *
 * Requires Docker; self-skips without it, like the other container suites.
 */
import { randomUUID } from 'node:crypto';

import type { SignatureAlgorithm } from '@qauth-labs/core-crypto';
import {
  requireDockerOrSkip,
  type StartedPostgres,
  startPostgresContainer,
  truncateDomainTablesStatement,
} from '@qauth-labs/shared-testing';
import { compactVerify, decodeProtectedHeader, importJWK, type JWK } from 'jose';
import { Pool, type PoolClient } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { KEK_A, KEK_B, localProvider, testKek } from '../testing/keks';
import { createPgKekRewrapStore, createPgKeyStore } from '../testing/pg-key-store';
import { createPgSignerStore } from '../testing/pg-signer-store';
import {
  type ApprovedOperation,
  KEK_ROTATE_OPERATION,
  type KekRotateOperation,
  newOperationNonce,
} from './approved-operation';
import { openKeyMaterial } from './envelope';
import { UnknownKekRefError } from './errors';
import { createInProcessSigner } from './in-process-signer';
import type { KekProvider } from './kek-provider';
import { createKekRewrap, type KekRewrapStore, type KekRotationRecord } from './kek-rewrap';
import { computeKekRef } from './kek-sources';
import { createKeyFactory } from './key-factory';
import type { Signer } from './signer';

const ISSUER = 'https://kek-rotation.example.test';
const ED25519_ONLY: readonly SignatureAlgorithm[] = ['EdDSA'];
const OPERATOR = { kind: 'break_glass', operatingSystemUser: 'qauth-ops' } as const;
const KEK_C = testKek(0xc3);
const REF_A = computeKekRef(Buffer.from(KEK_A, 'base64'));
const REF_B = computeKekRef(Buffer.from(KEK_B, 'base64'));
const REF_C = computeKekRef(Buffer.from(KEK_C, 'base64'));

/** A node before the change of KEK. */
const oldNode = (): KekProvider => localProvider({ KEK: KEK_A });
/** A node during it: the new KEK, and the old one as `KEK_PREVIOUS`. */
const rotatingNode = (): KekProvider => localProvider({ KEK: KEK_B, KEK_PREVIOUS: KEK_A });
/** A node after it: the new KEK alone. */
const newNode = (): KekProvider => localProvider({ KEK: KEK_B });

/** A host-made approval of `kek.rotate`, as the operator command makes one. */
function hostApproval(): ApprovedOperation<KekRotateOperation, PoolClient> {
  return {
    id: randomUUID(),
    operation: KEK_ROTATE_OPERATION,
    requester: OPERATOR,
    nonce: newOperationNonce(),
    consume: async () => undefined,
  };
}

/** The audit hook: the operator command prints the record; the tests need nothing of it. */
const noAudit: (entry: KekRotationRecord, tx: PoolClient) => Promise<void> = async () => undefined;

describe('KEK rotation (real Postgres)', () => {
  let container: StartedPostgres | undefined;
  let pool: Pool | undefined;
  let dockerUp = false;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    container = await startPostgresContainer({ schema: 'migrated' });
    pool = new Pool({ connectionString: container.connectionString });
  }, 180_000);

  afterAll(async () => {
    await pool?.end();
    await container?.stop();
  });

  beforeEach(async (testCtx) => {
    if (!dockerUp || !pool) {
      testCtx.skip();
      return;
    }
    await pool.query(truncateDomainTablesStatement());
  });

  function db(): Pool {
    if (!pool) throw new Error('no pool');
    return pool;
  }

  /** `count` realms, each with its standard keys sealed under `provider`'s KEK. */
  async function seedRealms(count: number, provider: KekProvider = oldNode()): Promise<string[]> {
    const factory = createKeyFactory({
      store: createPgKeyStore(db()),
      kekProvider: provider,
      enabledSignatureAlgorithms: ED25519_ONLY,
      hybridSigning: false,
    });
    const realmIds: string[] = [];
    for (let index = 0; index < count; index += 1) {
      const { rows } = await db().query<{ id: string }>(
        'INSERT INTO realms (name, issuer) VALUES ($1, $2) RETURNING id',
        [`realm-${randomUUID()}`, ISSUER]
      );
      await factory.provisionRealmKeys(rows[0].id);
      realmIds.push(rows[0].id);
    }
    return realmIds;
  }

  /** How many keys each `kek_ref` wraps, read straight from the table. */
  async function rowsPerKekRef(): Promise<Record<string, number>> {
    const { rows } = await db().query<{ kek_ref: string; rows: string }>(
      'SELECT kek_ref, count(*) AS rows FROM realm_keys GROUP BY kek_ref'
    );
    return Object.fromEntries(rows.map((row) => [row.kek_ref, Number(row.rows)]));
  }

  /** Every stored key's sealed columns, by realm and `kid`. */
  async function sealedRows() {
    const { rows } = await db().query<{
      realm_id: string;
      kid: string;
      ciphertext: Buffer;
      iv: Buffer;
      aad_version: number;
      kek_ref: string;
    }>('SELECT realm_id, kid, ciphertext, iv, aad_version, kek_ref FROM realm_keys ORDER BY id');
    return rows;
  }

  /** Open every stored key's material with `provider`; the ones that do not open. */
  async function keysThatDoNotOpen(provider: KekProvider): Promise<string[]> {
    const store = createPgKekRewrapStore(db());
    const failed: string[] = [];
    for (const row of await sealedRows()) {
      const sealed = await store.getWrappedKey(row.realm_id, row.kid);
      if (sealed === undefined) throw new Error(`key ${row.kid} vanished`);
      try {
        (await openKeyMaterial(provider, sealed, sealed)).fill(0);
      } catch {
        failed.push(row.kid);
      }
    }
    return failed;
  }

  /** A signer that has read nothing yet, as on a node that starts now. */
  function signer(provider: KekProvider): Signer {
    return createInProcessSigner({
      store: createPgSignerStore(db()),
      kekProvider: provider,
      enabledSignatureAlgorithms: ED25519_ONLY,
      hybridSigning: false,
    });
  }

  async function sign(by: Signer, realmId: string): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    return by.signJws('local', {
      realmId,
      purpose: 'token_signing',
      typ: 'at+jwt',
      claims: { sub: 'user-1', aud: 'client-1', iat: now, exp: now + 300 },
    });
  }

  /** Whether `token` verifies against the realm's published keys, as a fresh node reads them. */
  async function verifies(by: Signer, realmId: string, token: string): Promise<boolean> {
    const { kid, alg } = decodeProtectedHeader(token);
    const keys = await by.getVerificationKeys('local', realmId, 'token_signing');
    const found = keys.find((key) => key.kid === kid);
    if (found === undefined) return false;
    await compactVerify(token, await importJWK(found.publicJwk as JWK, alg));
    return true;
  }

  it('re-wraps 100 stored keys, after which every key opens with the new KEK alone', async () => {
    const realmIds = await seedRealms(25);
    const before = await sealedRows();
    expect(before.length).toBeGreaterThanOrEqual(100);
    expect(await rowsPerKekRef()).toEqual({ [REF_A]: before.length });

    const report = await createKekRewrap({
      store: createPgKekRewrapStore(db()),
      kekProvider: rotatingNode(),
    }).rewrapAll({ from: REF_A, to: REF_B, approval: hostApproval(), onAudit: noAudit });

    expect(report).toMatchObject({
      rows: before.length,
      rewrapped: before.length,
      moved: 0,
      failures: [],
      complete: true,
    });
    expect(report.kekRefs).toEqual([
      { kekRef: REF_B, rows: before.length, current: true, opens: true },
    ]);
    expect(await rowsPerKekRef()).toEqual({ [REF_B]: before.length });

    // The material was not touched: same ciphertext, IV and associated-data format.
    const after = await sealedRows();
    const material = (rows: typeof before) =>
      rows.map((row) => [row.realm_id, row.kid, row.ciphertext, row.iv, row.aad_version]);
    expect(material(after)).toEqual(material(before));

    // Every key opens with the new KEK alone, and none with the old KEK alone.
    expect(await keysThatDoNotOpen(newNode())).toEqual([]);
    expect(await keysThatDoNotOpen(oldNode())).toHaveLength(before.length);
    const store = createPgKekRewrapStore(db());
    const first = await store.getWrappedKey(after[0].realm_id, after[0].kid);
    if (first === undefined) throw new Error('the first key vanished');
    await expect(openKeyMaterial(oldNode(), first, first)).rejects.toBeInstanceOf(
      UnknownKekRefError
    );

    // A node with the new KEK alone signs, and its tokens verify.
    const node = signer(newNode());
    for (const realmId of realmIds.slice(0, 3)) {
      expect(await verifies(node, realmId, await sign(node, realmId))).toBe(true);
    }
  });

  it('resumes after the job is killed midway, and ends with no key on the old kek_ref', async () => {
    await seedRealms(10);
    const total = (await sealedRows()).length;
    const base = createPgKekRewrapStore(db());
    let writes = 0;
    // The process dies before its 15th write reaches the database.
    const killed: KekRewrapStore<PoolClient> = {
      ...base,
      replaceWrappedDek: async (realmId, kid, change) => {
        writes += 1;
        if (writes === 15) throw new Error('terminating connection due to administrator command');
        return base.replaceWrappedDek(realmId, kid, change);
      },
    };

    await expect(
      createKekRewrap({ store: killed, kekProvider: rotatingNode() }).rewrapAll({
        from: REF_A,
        to: REF_B,
        approval: hostApproval(),
        onAudit: noAudit,
      })
    ).rejects.toThrow('terminating connection');

    // One key per transaction: 14 moved, the rest are as they were, none is half-written.
    expect(await rowsPerKekRef()).toEqual({ [REF_A]: total - 14, [REF_B]: 14 });
    expect(await keysThatDoNotOpen(rotatingNode())).toEqual([]);

    // Run again, on a node started afresh, with a new approval.
    const resumed = await createKekRewrap({
      store: createPgKekRewrapStore(db()),
      kekProvider: rotatingNode(),
    }).rewrapAll({ from: REF_A, to: REF_B, approval: hostApproval(), onAudit: noAudit });

    expect(resumed).toMatchObject({
      rows: total - 14,
      rewrapped: total - 14,
      failures: [],
      complete: true,
    });
    expect(await rowsPerKekRef()).toEqual({ [REF_B]: total });
    expect(await keysThatDoNotOpen(newNode())).toEqual([]);
  });

  it('runs on two hosts at once without either writing over the other', async () => {
    await seedRealms(8);
    const total = (await sealedRows()).length;
    const host = () =>
      createKekRewrap({
        store: createPgKekRewrapStore(db()),
        kekProvider: rotatingNode(),
      }).rewrapAll({ from: REF_A, to: REF_B, approval: hostApproval(), onAudit: noAudit });

    const [one, two] = await Promise.all([host(), host()]);

    expect(one.failures).toEqual([]);
    expect(two.failures).toEqual([]);
    // Each key was moved by exactly one of them; the other found it moved.
    expect(one.rewrapped + two.rewrapped).toBe(total);
    expect(await rowsPerKekRef()).toEqual({ [REF_B]: total });
    expect(await keysThatDoNotOpen(newNode())).toEqual([]);
  });

  it('signs and verifies throughout the job', async () => {
    const realmIds = await seedRealms(3);
    // A node that has run since before the job, with both KEKs, and its token.
    const running = signer(rotatingNode());
    const earlier = await Promise.all(realmIds.map((realmId) => sign(running, realmId)));
    const signedDuring: { realmId: string; token: string }[] = [];
    let checks = 0;

    const report = await createKekRewrap({
      store: createPgKekRewrapStore(db()),
      kekProvider: rotatingNode(),
    }).rewrapAll({
      from: REF_A,
      to: REF_B,
      approval: hostApproval(),
      onAudit: noAudit,
      // After each key moves: a node that starts now, with both KEKs, signs and
      // verifies in every realm, and so does the node that ran all along.
      onKey: async () => {
        for (const realmId of realmIds) {
          const fresh = signer(rotatingNode());
          const token = await sign(fresh, realmId);
          expect(await verifies(fresh, realmId, token)).toBe(true);
          expect(await verifies(running, realmId, await sign(running, realmId))).toBe(true);
          signedDuring.push({ realmId, token });
          checks += 1;
        }
      },
    });

    expect(report.complete).toBe(true);
    expect(checks).toBe(report.rewrapped * realmIds.length);
    expect(checks).toBeGreaterThan(0);
    // Afterwards a node with the new KEK alone signs, and verifies every token
    // signed before and during the job.
    const after = signer(newNode());
    for (const [index, realmId] of realmIds.entries()) {
      expect(await verifies(after, realmId, await sign(after, realmId))).toBe(true);
      expect(await verifies(after, realmId, earlier[index])).toBe(true);
    }
    for (const { realmId, token } of signedDuring) {
      expect(await verifies(after, realmId, token)).toBe(true);
    }
  });

  it('reports a key wrapped by an unknown KEK and does not report success', async () => {
    await seedRealms(2);
    // A realm whose keys a third KEK wrapped: this node holds it neither as KEK nor as KEK_PREVIOUS.
    await seedRealms(1, localProvider({ KEK: KEK_C }));
    const counts = await rowsPerKekRef();
    const rewrap = createKekRewrap({
      store: createPgKekRewrapStore(db()),
      kekProvider: rotatingNode(),
    });

    const report = await rewrap.rewrapAll({
      from: REF_A,
      to: REF_B,
      approval: hostApproval(),
      onAudit: noAudit,
    });

    expect(report.rewrapped).toBe(counts[REF_A]);
    expect(report.complete).toBe(false);
    expect(report.kekRefs).toContainEqual({
      kekRef: REF_C,
      rows: counts[REF_C],
      current: false,
      opens: false,
      reason: 'KEK_UNKNOWN_REF',
    });
    expect(report.kekRefs).toContainEqual({
      kekRef: REF_B,
      rows: counts[REF_A],
      current: true,
      opens: true,
    });
    // The unknown KEK's keys are left as they were.
    expect(await rowsPerKekRef()).toEqual({ [REF_B]: counts[REF_A], [REF_C]: counts[REF_C] });

    // Counting alone says the same, and changes nothing.
    const census = await rewrap.census();
    expect(census).toEqual(report.kekRefs);
    expect(await rowsPerKekRef()).toEqual({ [REF_B]: counts[REF_A], [REF_C]: counts[REF_C] });
  });
});
