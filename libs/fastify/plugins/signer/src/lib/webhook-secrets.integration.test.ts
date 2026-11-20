/**
 * Real-Postgres integration tests for a webhook subscription's signing
 * secrets (issue #537), through the signer plugin's `webhookSecrets`: the
 * secret is handed out once in the Standard Webhooks form, a rotation with an
 * overlap signs with both secrets until the overlap ends, one without
 * replaces the secret at once, and deleting the subscription's secrets stops
 * every signature.
 *
 * Requires Docker; self-skips without it, like the other container suites.
 */
import { createHmac, randomUUID } from 'node:crypto';

import {
  createDatabase,
  createRealmsRepository,
  type DatabaseInstance,
} from '@qauth-labs/infra-db';
import {
  requireDockerOrSkip,
  type StartedPostgres,
  startPostgresContainer,
  truncateDomainTablesStatement,
} from '@qauth-labs/shared-testing';
import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { signerPlugin } from './fastify-plugin-signer';
import type { WebhookSecrets } from './webhook-secrets';

const KEK_ENV = { KEK: Buffer.alloc(32, 0xb2).toString('base64'), NODE_ENV: 'test' };
const MESSAGE = { id: 'msg_2Z7xYq', timestamp: 1_790_000_000, body: '{"type":"webhook.test"}' };

/** The Standard Webhooks signature `secret` gives {@link MESSAGE}, as `v1,<base64>`. */
function expectedSignature(secret: string): string {
  expect(secret).toMatch(/^whsec_[A-Za-z0-9+/]+={0,2}$/);
  const key = Buffer.from(secret.slice('whsec_'.length), 'base64');
  expect(key).toHaveLength(32);
  const mac = createHmac('sha256', key)
    .update(`${MESSAGE.id}.${MESSAGE.timestamp}.${MESSAGE.body}`)
    .digest('base64');
  return `v1,${mac}`;
}

describe('webhook secrets integration (real Postgres)', () => {
  let container: StartedPostgres | undefined;
  let database: DatabaseInstance | undefined;
  let app: FastifyInstance | undefined;
  let dockerUp = false;
  let realmId = '';

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    container = await startPostgresContainer({ schema: 'migrated' });
    database = createDatabase({ connectionString: container.connectionString });
    app = Fastify();
    await app.register(signerPlugin, {
      db: database.db,
      kekEnv: KEK_ENV,
      enabledSignatureAlgorithms: ['EdDSA'],
      hybridSigning: false,
      // Every signature reads the key list afresh, so a change shows at once.
      refreshIntervalMs: 0,
    });
    await app.ready();
  }, 180_000);

  afterAll(async () => {
    await app?.close();
    await database?.close();
    await container?.stop();
  });

  beforeEach(async (testCtx) => {
    if (!dockerUp || database === undefined) {
      testCtx.skip();
      return;
    }
    await database.pool.query(truncateDomainTablesStatement());
    const { realm } = await createRealmsRepository(database.db).createWithPrimaryHost(
      { name: 'master', issuer: 'https://auth.example.test' },
      'auth.example.test'
    );
    realmId = realm.id;
  });

  function secrets(): WebhookSecrets {
    const decorated = app?.webhookSecrets;
    if (decorated === null || decorated === undefined) throw new Error('no webhook secrets');
    return decorated;
  }

  /** The signatures the signer puts in the `webhook-signature` header for the subscription. */
  async function signatures(subscriptionId: string): Promise<string[]> {
    const header = await app!.signer.signWebhook('local', {
      realmId,
      subscriptionId,
      ...MESSAGE,
    });
    return header.split(' ').sort();
  }

  /** The stored keys of the subscription, as `status` by `kid`. */
  async function keyStatuses(subscriptionId: string): Promise<Record<string, string>> {
    const { rows } = await database!.pool.query<{ kid: string; status: string }>(
      `select kid, status from realm_keys where realm_id = $1 and scope_id = $2 and purpose = 'webhook_signing'`,
      [realmId, subscriptionId]
    );
    return Object.fromEntries(rows.map((row) => [row.kid, row.status]));
  }

  it('hands the first secret out once, in the whsec_ form, and signs with it', async () => {
    const subscriptionId = randomUUID();
    const created = await secrets().create({ realmId, subscriptionId });

    expect(await signatures(subscriptionId)).toEqual([expectedSignature(created.secret)]);
    expect(await keyStatuses(subscriptionId)).toEqual({ [created.kid]: 'active' });
    // The stored row holds the secret sealed, never in the clear.
    const { rows } = await database!.pool.query<{ row: string }>(
      `select row_to_json(k)::text as row from realm_keys k where kid = $1`,
      [created.kid]
    );
    expect(rows[0]?.row).not.toContain(created.secret.slice('whsec_'.length));
    // A second first secret is refused: the subscription already has one.
    await expect(secrets().create({ realmId, subscriptionId })).rejects.toThrow();
  });

  it('signs with both secrets during an overlap, then with the new one alone', async () => {
    const subscriptionId = randomUUID();
    const first = await secrets().create({ realmId, subscriptionId });
    const rotated = await secrets().rotate({ realmId, subscriptionId, overlap: true });

    expect(rotated.kid).not.toBe(first.kid);
    expect(rotated.secret).not.toBe(first.secret);
    expect(rotated.retiredKids).toEqual([]);
    expect(await signatures(subscriptionId)).toEqual(
      [expectedSignature(first.secret), expectedSignature(rotated.secret)].sort()
    );

    expect(await secrets().endOverlap({ realmId, subscriptionId })).toEqual({
      retiredKid: first.kid,
    });
    expect(await signatures(subscriptionId)).toEqual([expectedSignature(rotated.secret)]);
    expect(await keyStatuses(subscriptionId)).toEqual({
      [first.kid]: 'retired',
      [rotated.kid]: 'active',
    });
    // Nothing is left to end.
    expect(await secrets().endOverlap({ realmId, subscriptionId })).toBeNull();
  });

  it('ends an open overlap before a second rotation, so at most two secrets sign', async () => {
    const subscriptionId = randomUUID();
    const first = await secrets().create({ realmId, subscriptionId });
    const second = await secrets().rotate({ realmId, subscriptionId, overlap: true });
    const third = await secrets().rotate({ realmId, subscriptionId, overlap: true });

    expect(third.retiredKids).toEqual([first.kid]);
    expect(await signatures(subscriptionId)).toEqual(
      [expectedSignature(second.secret), expectedSignature(third.secret)].sort()
    );
  });

  it('replaces the secret at once when the rotation has no overlap', async () => {
    const subscriptionId = randomUUID();
    const first = await secrets().create({ realmId, subscriptionId });
    const rotated = await secrets().rotate({ realmId, subscriptionId, overlap: false });

    expect(rotated.retiredKids).toEqual([first.kid]);
    expect(await signatures(subscriptionId)).toEqual([expectedSignature(rotated.secret)]);
  });

  it("deletes every secret of the subscription and leaves another subscription's", async () => {
    const subscriptionId = randomUUID();
    const other = randomUUID();
    const first = await secrets().create({ realmId, subscriptionId });
    const rotated = await secrets().rotate({ realmId, subscriptionId, overlap: true });
    const kept = await secrets().create({ realmId, subscriptionId: other });

    expect([...(await secrets().delete({ realmId, subscriptionId }))].sort()).toEqual(
      [first.kid, rotated.kid].sort()
    );
    expect(await keyStatuses(subscriptionId)).toEqual({});
    await expect(signatures(subscriptionId)).rejects.toThrow();
    expect(await signatures(other)).toEqual([expectedSignature(kept.secret)]);
  });
});
