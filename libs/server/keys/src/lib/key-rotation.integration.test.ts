/**
 * Real-Postgres integration tests for the scheduled key rotation (#542,
 * ADR-019 Decision 9), over a fake clock.
 *
 * The rotation writes the migrated `realm_keys` and `realm_public_keys`
 * tables through plain SQL of the shape the realm keys repository runs in
 * production, under the realm's advisory lock, inside the real
 * one-active-key index and the tables' checks. The signer reads them back the
 * same way. Each check reads with a signer built for it, as a node that
 * starts then would, so no key cache hides what the database holds.
 *
 * Requires Docker; self-skips without it, like the other container suites.
 */
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

import { randomUUID } from 'node:crypto';

import { KEK_A, localProvider } from '../testing/keks';
import { createPgKeyStore } from '../testing/pg-key-store';
import { createPgSignerStore } from '../testing/pg-signer-store';
import {
  type ApprovedOperation,
  KEY_ROTATE_OPERATION,
  type KeyRotateOperation,
  keyRotationOperation,
  newOperationNonce,
  operationDigest,
} from './approved-operation';
import { createInProcessSigner } from './in-process-signer';
import { createKeyFactory } from './key-factory';
import { KEY_PURPOSES, type KeyPurpose } from './key-purposes';
import {
  createKeyRotation,
  type KeyRotationNowRecord,
  type KeyRotationReport,
  type KeyRotationRunOptions,
} from './key-rotation';
import {
  KEY_ACTIVATION_DELAY_MS,
  type KeyRotationStep,
  type KeysRotatedStep,
} from './key-rotation-plan';
import type { Signer } from './signer';

const DAY = 86_400_000;
const T0 = 1_800_000_000_000;
const ISSUER = 'https://rotation.example.test';
const ED25519_ONLY: readonly SignatureAlgorithm[] = ['EdDSA'];
const HYBRID: readonly SignatureAlgorithm[] = ['EdDSA', 'ML-DSA-65'];

/** A day for published purposes and cookies; a data-at-rest key is kept. */
function lifetime(purpose: KeyPurpose): number | null {
  if (KEY_PURPOSES[purpose].published || purpose === 'cookie_hmac') return DAY;
  return null;
}

/** A `token_signing` row as the database holds it. */
interface TokenKeyRow {
  readonly kid: string;
  readonly algorithm: string;
  readonly status: string;
  readonly pair_id: string | null;
  readonly activate_at: string | null;
  readonly retire_at: string | null;
  readonly unpublish_at: string | null;
  readonly public_unpublish_at: string | null;
}

function rotatedStep(steps: readonly KeyRotationStep[], purpose: KeyPurpose): KeysRotatedStep {
  const step = steps.find((each) => each.purpose === purpose && each.kind === 'rotated');
  if (step === undefined || step.kind !== 'rotated') throw new Error(`no rotation of ${purpose}`);
  return step;
}

function stepsOf(
  steps: readonly KeyRotationStep[],
  purpose: KeyPurpose,
  kind: KeyRotationStep['kind']
): KeyRotationStep[] {
  return steps.filter((step) => step.purpose === purpose && step.kind === kind);
}

describe('scheduled key rotation (real Postgres, fake clock)', () => {
  let container: StartedPostgres | undefined;
  let pool: Pool | undefined;
  let dockerUp = false;
  const kekProvider = localProvider({ KEK: KEK_A });

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

  async function seedRealm(): Promise<string> {
    const { rows } = await db().query<{ id: string }>(
      'INSERT INTO realms (name, issuer) VALUES ($1, $2) RETURNING id',
      [`realm-${Math.random().toString(36).slice(2)}`, ISSUER]
    );
    return rows[0].id;
  }

  /** A realm provisioned at `T0`, and the means to rotate it and read it at the clock's time. */
  async function world(hybrid = false) {
    const enabled = hybrid ? HYBRID : ED25519_ONLY;
    const clock = { now: T0 };
    const realmId = await seedRealm();
    await createKeyFactory({
      store: createPgKeyStore(db()),
      kekProvider,
      enabledSignatureAlgorithms: enabled,
      hybridSigning: hybrid,
      now: () => clock.now,
    }).provisionRealmKeys(realmId);

    /** A node's rotation: a store and a rotation of its own over the same database. */
    const node = () =>
      createKeyRotation({
        store: createPgKeyStore(db()),
        kekProvider,
        enabledSignatureAlgorithms: enabled,
        hybridSigning: hybrid,
      });
    const rotation = node();
    const run = (overrides: Partial<KeyRotationRunOptions<PoolClient>> = {}) =>
      rotation.rotateAll({
        now: () => clock.now,
        lifetimeOf: async (_realmId, purpose) => lifetime(purpose),
        ...overrides,
      });
    /** A signer that has read nothing yet, as on a node that starts now. */
    const signer = (): Signer =>
      createInProcessSigner({
        store: createPgSignerStore(db()),
        kekProvider,
        enabledSignatureAlgorithms: enabled,
        hybridSigning: hybrid,
        now: () => clock.now,
      });
    const sign = async () =>
      signer().signJws('local', {
        realmId,
        purpose: 'token_signing',
        typ: 'at+jwt',
        claims: {
          sub: 'user-1',
          aud: 'client-1',
          iat: Math.floor(clock.now / 1000),
          exp: Math.floor(clock.now / 1000) + 300,
        },
      });
    const jwksKids = async () =>
      (await signer().getJwks('local', realmId)).keys.map((key) => key.kid as string);
    const verifies = async (token: string) => {
      const { kid, alg } = decodeProtectedHeader(token);
      const keys = await signer().getVerificationKeys('local', realmId, 'token_signing');
      const found = keys.find((key) => key.kid === kid);
      if (found === undefined) return false;
      await compactVerify(token, await importJWK(found.publicJwk as JWK, alg));
      return true;
    };
    return { clock, realmId, node, run, signer, sign, jwksKids, verifies };
  }

  async function tokenKeyRows(realmId: string): Promise<TokenKeyRow[]> {
    const { rows } = await db().query<TokenKeyRow>(
      `SELECT k.kid, k.algorithm, k.status, k.pair_id, k.activate_at, k.retire_at, k.unpublish_at,
              p.unpublish_at AS public_unpublish_at
         FROM realm_keys k JOIN realm_public_keys p ON p.realm_id = k.realm_id AND p.kid = k.kid
        WHERE k.realm_id = $1 AND k.purpose = 'token_signing' ORDER BY k.created_at, k.algorithm`,
      [realmId]
    );
    return rows;
  }

  async function kidOf(token: string): Promise<string> {
    return decodeProtectedHeader(token).kid as string;
  }

  it('creates the next key on day 83, switches on day 90 and unpublishes the old key on day 104', async () => {
    const w = await world();
    const oldToken = await w.sign();
    const oldKid = await kidOf(oldToken);

    // Day 83: a next key, in the JWKS, while the old key signs.
    w.clock.now = T0 + 83 * DAY;
    const created = await w.run();
    expect(created.failures).toEqual([]);
    const [next] = stepsOf(created.steps, 'token_signing', 'next_created');
    expect(next).toMatchObject({ activatesAt: T0 + 90 * DAY });
    const newKid = next.kind === 'next_created' ? next.keys[0].kid : '';
    expect(await w.jwksKids()).toEqual(expect.arrayContaining([oldKid, newKid]));
    expect(await kidOf(await w.sign())).toBe(oldKid);
    // The next SET key is in the SSF transmitter's JWKS from now on.
    const [event] = stepsOf(created.steps, 'event_signing', 'next_created');
    const eventKid = event.kind === 'next_created' ? event.keys[0].kid : '';
    const ssf = await w.signer().getJwks('local', w.realmId, 'event_signing');
    expect(ssf.keys.map((key) => key.kid)).toContain(eventKid);
    expect((await tokenKeyRows(w.realmId)).map((row) => row.status)).toEqual(['active', 'next']);

    // Day 90: the switch, written ahead of the signers.
    w.clock.now = T0 + 90 * DAY;
    const step = rotatedStep((await w.run()).steps, 'token_signing');
    const switchAt = T0 + 90 * DAY + KEY_ACTIVATION_DELAY_MS;
    expect(step).toMatchObject({ switchAt, retainedUntil: switchAt + 14 * DAY });
    expect(await tokenKeyRows(w.realmId)).toEqual([
      expect.objectContaining({
        kid: oldKid,
        status: 'retired',
        retire_at: String(switchAt),
        unpublish_at: String(switchAt + 14 * DAY),
        public_unpublish_at: String(switchAt + 14 * DAY),
      }),
      expect.objectContaining({ kid: newKid, status: 'active', activate_at: String(switchAt) }),
    ]);
    expect(await kidOf(await w.sign())).toBe(oldKid);
    w.clock.now = switchAt;
    const newToken = await w.sign();
    expect(await kidOf(newToken)).toBe(newKid);
    expect(await w.verifies(newToken)).toBe(true);
    expect(await w.verifies(oldToken)).toBe(true);

    // Day 104: the old key leaves the JWKS and the verification set.
    w.clock.now = switchAt + 14 * DAY - 1;
    expect(await w.jwksKids()).toContain(oldKid);
    w.clock.now = switchAt + 14 * DAY;
    expect(await w.jwksKids()).not.toContain(oldKid);
    expect(await w.verifies(oldToken)).toBe(false);
    expect(await w.verifies(newToken)).toBe(true);
    // A repeated run changes nothing.
    expect((await w.run()).steps).toEqual([]);
  });

  it('keeps a retired key published as long as its longest token lives', async () => {
    const w = await world();
    w.clock.now = T0 + 83 * DAY;
    await w.run();
    w.clock.now = T0 + 90 * DAY;
    const step = rotatedStep(
      (
        await w.run({
          lifetimeOf: async (_realmId, purpose) =>
            purpose === 'token_signing' ? 30 * DAY : lifetime(purpose),
        })
      ).steps,
      'token_signing'
    );
    expect(step.retainedUntil).toBe(step.switchAt + 30 * DAY);
    const [retired] = await tokenKeyRows(w.realmId);
    expect(retired.public_unpublish_at).toBe(String(step.switchAt + 30 * DAY));
  });

  it('flips a hybrid pair in one transaction: no other connection sees half of it', async () => {
    const w = await world(true);
    w.clock.now = T0 + 83 * DAY;
    await w.run();
    const statuses = async () =>
      (await tokenKeyRows(w.realmId)).map((row) => `${row.algorithm}:${row.status}`);
    const before = await statuses();
    expect(before).toEqual(['EdDSA:active', 'ML-DSA-65:active', 'EdDSA:next', 'ML-DSA-65:next']);

    // Inside the step, before it commits, another connection still reads the old state.
    const seenInside: string[][] = [];
    w.clock.now = T0 + 90 * DAY;
    const report = await w.run({
      onStep: async (step) => {
        if (step.purpose === 'token_signing') seenInside.push(await statuses());
      },
    });
    expect(seenInside).toEqual([before]);
    const step = rotatedStep(report.steps, 'token_signing');
    expect(step.activated.map((key) => key.algorithm)).toEqual(['EdDSA', 'ML-DSA-65']);
    expect(await statuses()).toEqual([
      'EdDSA:retired',
      'ML-DSA-65:retired',
      'EdDSA:active',
      'ML-DSA-65:active',
    ]);
    const rows = await tokenKeyRows(w.realmId);
    // Both halves of each pair share their times.
    expect(new Set(rows.slice(0, 2).map((row) => row.unpublish_at)).size).toBe(1);
    expect(new Set(rows.slice(2).map((row) => row.activate_at)).size).toBe(1);

    // The JWKS shows whole pairs at every point of the rotation.
    const pairs = new Map(rows.map((row) => [row.kid, row.pair_id]));
    for (const at of [
      step.switchAt - 1,
      step.switchAt,
      step.retainedUntil! - 1,
      step.retainedUntil!,
    ]) {
      w.clock.now = at;
      const shown = (await w.jwksKids()).filter((kid) => pairs.has(kid));
      const perPair = new Map<string | null | undefined, number>();
      for (const kid of shown) perPair.set(pairs.get(kid), (perPair.get(pairs.get(kid)) ?? 0) + 1);
      expect(
        [...perPair.values()].every((count) => count === 2),
        `at ${at - T0}`
      ).toBe(true);
    }
  });

  it('rolls the whole pair back when the step fails before it commits', async () => {
    const w = await world(true);
    w.clock.now = T0 + 83 * DAY;
    await w.run();
    const before = await tokenKeyRows(w.realmId);

    w.clock.now = T0 + 90 * DAY;
    const report = await w.run({
      onStep: async (step) => {
        if (step.purpose === 'token_signing') throw new Error('the audit row failed');
      },
    });
    expect(report.failures.map((failure) => failure.purpose)).toEqual(['token_signing']);
    expect(await tokenKeyRows(w.realmId)).toEqual(before);
    // The next run takes the step it missed.
    expect(rotatedStep((await w.run()).steps, 'token_signing').activated).toHaveLength(2);
  });

  it('after 100 days down, creates the next key, waits the whole window, then switches', async () => {
    const w = await world();
    const oldKid = await kidOf(await w.sign());

    w.clock.now = T0 + 100 * DAY;
    const [created] = stepsOf((await w.run()).steps, 'token_signing', 'next_created');
    expect(created).toMatchObject({ activatesAt: T0 + 107 * DAY });

    w.clock.now = T0 + 107 * DAY - 1;
    expect(stepsOf((await w.run()).steps, 'token_signing', 'rotated')).toEqual([]);
    expect(await kidOf(await w.sign())).toBe(oldKid);

    w.clock.now = T0 + 107 * DAY;
    expect(rotatedStep((await w.run()).steps, 'token_signing').retired[0].kid).toBe(oldKid);
  });

  it('rotates once when two nodes run at the same time', async () => {
    const w = await world();
    const nodes = [w.node(), w.node()];
    const runBoth = async (): Promise<KeyRotationStep[]> => {
      const reports: KeyRotationReport[] = await Promise.all(
        nodes.map((node) =>
          node.rotateAll({
            now: () => w.clock.now,
            lifetimeOf: async (_realmId, purpose) => lifetime(purpose),
          })
        )
      );
      for (const report of reports) expect(report.failures).toEqual([]);
      return reports.flatMap((report) => report.steps);
    };

    w.clock.now = T0 + 83 * DAY;
    const created = await runBoth();
    expect(stepsOf(created, 'token_signing', 'next_created')).toHaveLength(1);
    expect(stepsOf(created, 'cookie_hmac', 'next_created')).toHaveLength(1);
    w.clock.now = T0 + 90 * DAY;
    const rotated = await runBoth();
    expect(stepsOf(rotated, 'token_signing', 'rotated')).toHaveLength(1);
    expect(stepsOf(rotated, 'cookie_hmac', 'rotated')).toHaveLength(1);

    const { rows } = await db().query<{ purpose: string; status: string; n: number }>(
      `SELECT purpose, status, count(*)::int AS n FROM realm_keys WHERE realm_id = $1
        GROUP BY purpose, status ORDER BY purpose, status`,
      [w.realmId]
    );
    for (const row of rows) expect(row.n, `${row.purpose} ${row.status}`).toBe(1);
  });

  it('accepts the old cookie key during its retention and not after', async () => {
    const w = await world();
    const first = await w.signer().getCookieSecrets('local', w.realmId);
    w.clock.now = T0 + 83 * DAY;
    await w.run();
    w.clock.now = T0 + 90 * DAY;
    const step = rotatedStep((await w.run()).steps, 'cookie_hmac');

    w.clock.now = step.switchAt;
    const after = await w.signer().getCookieSecrets('local', w.realmId);
    expect(after.current.kid).toBe(step.activated[0].kid);
    expect(after.previous?.kid).toBe(first.current.kid);
    expect(after.previous?.secret.equals(first.current.secret)).toBe(true);

    w.clock.now = step.retainedUntil! - 1;
    expect((await w.signer().getCookieSecrets('local', w.realmId)).previous?.kid).toBe(
      first.current.kid
    );
    w.clock.now = step.retainedUntil!;
    expect((await w.signer().getCookieSecrets('local', w.realmId)).previous).toBeNull();
    // The cookie key is never published.
    const { rows } = await db().query(
      `SELECT 1 FROM realm_public_keys WHERE realm_id = $1 AND purpose = 'cookie_hmac'`,
      [w.realmId]
    );
    expect(rows).toEqual([]);
  });
  describe('rotateNow, a manual rotation under an approval (#544)', () => {
    const ADMIN = Object.freeze({
      kind: 'human' as const,
      realmId: '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e00',
      accountId: '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6eaa',
    });

    /** The id of the transaction `tx` runs, as Postgres names it. */
    async function xactId(tx: PoolClient): Promise<string> {
      const { rows } = await tx.query<{ xid: string }>('SELECT pg_current_xact_id()::text AS xid');
      return rows[0].xid;
    }

    /** A single-use approval of the rotation of `purpose` in `realmId`, which records the transaction it was used in. */
    function approvalOf(realmId: string, purpose: KeyPurpose) {
      const nonce = newOperationNonce();
      const filed = operationDigest(
        keyRotationOperation({ realmId, purpose, requester: ADMIN, nonce })
      );
      const usedIn: string[] = [];
      const approval: ApprovedOperation<KeyRotateOperation, PoolClient> = {
        id: randomUUID(),
        operation: KEY_ROTATE_OPERATION,
        requester: ADMIN,
        nonce,
        async consume(digest, tx) {
          if (usedIn.length > 0 || !digest.equals(filed)) throw new Error('not approved');
          usedIn.push(await xactId(tx));
        },
      };
      return { approval, usedIn };
    }

    async function rotateNow(
      w: Awaited<ReturnType<typeof world>>,
      purpose: KeyPurpose,
      onAudit: (entry: KeyRotationNowRecord, tx: PoolClient) => Promise<void> = async () => {}
    ): Promise<KeyRotationNowRecord> {
      return w.node().rotateNow({
        realmId: w.realmId,
        purpose,
        approval: approvalOf(w.realmId, purpose).approval,
        now: () => w.clock.now,
        onAudit,
      });
    }

    it('publishes the next key at once; it starts to sign only after the pre-publication window', async () => {
      const w = await world();
      w.clock.now = T0 + 10 * DAY;
      const oldKid = await kidOf(await w.sign());

      const record = await rotateNow(w, 'token_signing');
      const [next] = record.next;
      expect(next).toMatchObject({ created: true, activatesAt: T0 + 17 * DAY });
      const newKid = next.keys[0].kid;
      // In the JWKS at once, published from the moment it was stored; it signs nothing yet.
      expect(await w.jwksKids()).toEqual(expect.arrayContaining([oldKid, newKid]));
      expect(await kidOf(await w.sign())).toBe(oldKid);
      expect(await tokenKeyRows(w.realmId)).toEqual([
        expect.objectContaining({ kid: oldKid, status: 'active' }),
        expect.objectContaining({ kid: newKid, status: 'next', activate_at: null }),
      ]);

      // The scheduled rotation switches once the window has run, not on day 90.
      w.clock.now = T0 + 17 * DAY - 1;
      expect(stepsOf((await w.run()).steps, 'token_signing', 'rotated')).toEqual([]);
      expect(await kidOf(await w.sign())).toBe(oldKid);
      w.clock.now = T0 + 17 * DAY;
      const step = rotatedStep((await w.run()).steps, 'token_signing');
      expect(step).toMatchObject({ activated: [{ kid: newKid }], retired: [{ kid: oldKid }] });
      expect(step.switchAt).toBe(T0 + 17 * DAY + KEY_ACTIVATION_DELAY_MS);
      w.clock.now = step.switchAt - 1;
      expect(await kidOf(await w.sign())).toBe(oldKid);
      w.clock.now = step.switchAt;
      const newToken = await w.sign();
      expect(await kidOf(newToken)).toBe(newKid);
      expect(await w.verifies(newToken)).toBe(true);
      // The old key stays published for the retention after the switch.
      expect(step.retainedUntil).toBe(step.switchAt + 14 * DAY);
      w.clock.now = step.retainedUntil! - 1;
      expect(await w.jwksKids()).toContain(oldKid);
    });

    it('returns the same key on a second call while a next key exists', async () => {
      const w = await world();
      w.clock.now = T0 + DAY;
      const first = await rotateNow(w, 'token_signing');
      w.clock.now = T0 + 2 * DAY;
      const second = await rotateNow(w, 'token_signing');
      expect(second.next).toEqual([{ ...first.next[0], created: false }]);
      const { rows } = await db().query<{ n: number }>(
        `SELECT count(*)::int AS n FROM realm_keys
          WHERE realm_id = $1 AND purpose = 'token_signing' AND status = 'next'`,
        [w.realmId]
      );
      expect(rows[0].n).toBe(1);
    });

    it('rotates both halves of a hybrid purpose', async () => {
      const w = await world(true);
      w.clock.now = T0 + DAY;
      const record = await rotateNow(w, 'token_signing');
      expect(record.next[0].keys.map((key) => key.algorithm).sort()).toEqual([
        'EdDSA',
        'ML-DSA-65',
      ]);
      const next = (await tokenKeyRows(w.realmId)).filter((row) => row.status === 'next');
      expect(next.map((row) => row.algorithm)).toEqual(['EdDSA', 'ML-DSA-65']);
      expect(next[0].pair_id).not.toBeNull();
      expect(next[0].pair_id).toBe(next[1].pair_id);
      expect(await w.jwksKids()).toEqual(expect.arrayContaining(next.map((row) => row.kid)));

      w.clock.now = T0 + 8 * DAY;
      const step = rotatedStep((await w.run()).steps, 'token_signing');
      expect(step.activated.map((key) => key.kid).sort()).toEqual(
        next.map((row) => row.kid).sort()
      );
      expect(step.retired.map((key) => key.algorithm).sort()).toEqual(['EdDSA', 'ML-DSA-65']);
    });

    it('consumes the approval, stores the key and calls the audit hook in one transaction', async () => {
      const w = await world();
      const { approval, usedIn } = approvalOf(w.realmId, 'event_signing');
      const audited: string[] = [];
      const record = await w.node().rotateNow({
        realmId: w.realmId,
        purpose: 'event_signing',
        approval,
        now: () => w.clock.now,
        onAudit: async (entry, tx) => {
          audited.push(await xactId(tx));
          // The new key is written in this transaction, and no other
          // connection sees it before the transaction commits.
          const query = 'SELECT kid FROM realm_keys WHERE realm_id = $1 AND kid = $2';
          const params = [w.realmId, entry.next[0].keys[0].kid];
          expect((await tx.query(query, params)).rows).toHaveLength(1);
          expect((await db().query(query, params)).rows).toEqual([]);
        },
      });
      expect(record).toMatchObject({ approvalId: approval.id, actor: ADMIN });
      expect(usedIn).toHaveLength(1);
      expect(audited).toEqual(usedIn);

      // An audit write that fails takes the key back with it.
      const keysOf = 'SELECT kid, status FROM realm_keys WHERE realm_id = $1 ORDER BY kid';
      const before = await db().query(keysOf, [w.realmId]);
      await expect(
        rotateNow(w, 'cookie_hmac', async () => {
          throw new Error('the audit row failed');
        })
      ).rejects.toThrow('the audit row failed');
      const after = await db().query(keysOf, [w.realmId]);
      expect(after.rows).toEqual(before.rows);
    });
  });
});
