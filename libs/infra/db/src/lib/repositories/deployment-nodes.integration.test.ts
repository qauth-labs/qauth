/**
 * Real-DB integration tests for the node list repository (#499).
 *
 * Exercises what a unit test cannot: the database's clock deciding which
 * nodes are live, the removal of the stale ones at a registration, the
 * advisory lock that makes two registrations at once run one after the other,
 * the heartbeat that writes a removed row again, and the CHECKs that keep a
 * value out of the digest columns.
 *
 * Requires Docker; self-skips without it and fails on CI
 * (`requireDockerOrSkip`).
 */
import { randomUUID } from 'node:crypto';

import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  createDeploymentNodesRepository,
  type DeploymentNode,
  type DeploymentNodesRepository,
  type NewDeploymentNode,
} from './deployment-nodes.repository';
import { type IntegrationDb, setupIntegrationDb } from './integration-setup';

const WINDOW_MS = 120_000;
const DIGEST = 'a'.repeat(64);

function node(extra: Partial<NewDeploymentNode> = {}): NewDeploymentNode {
  return {
    nodeId: randomUUID(),
    roles: ['web', 'api'],
    version: '0.3.0',
    configDigest: DIGEST,
    configKeys: { JWT_ISSUER: 'b'.repeat(64) },
    ...extra,
  };
}

describe('deployment nodes repository integration (real Postgres, #499)', () => {
  let ctx: IntegrationDb | undefined;
  let dockerUp = false;
  let repository: DeploymentNodesRepository;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    ctx = await setupIntegrationDb();
    repository = createDeploymentNodesRepository(ctx.database.db);
  }, 180_000);

  afterAll(async () => {
    await ctx?.teardown();
  });

  beforeEach(async (testCtx) => {
    if (!dockerUp || !ctx) {
      testCtx.skip();
      return;
    }
    await ctx.database.pool.query('DELETE FROM deployment_nodes');
  });

  function pool() {
    if (!ctx) throw new Error('integration db not initialised');
    return ctx.database.pool;
  }

  /** Move a node's last sighting `ms` into the past, as a node that stopped would leave it. */
  async function age(nodeId: string, ms: number): Promise<void> {
    await pool().query(
      'UPDATE deployment_nodes SET last_seen_at = last_seen_at - $2::bigint WHERE node_id = $1',
      [nodeId, ms]
    );
  }

  it('registers a node after the check saw the live ones, and lists it', async () => {
    const first = node();
    const seen: (readonly DeploymentNode[])[] = [];
    const stored = await repository.register(first, WINDOW_MS, (live) => seen.push(live));
    expect(seen).toEqual([[]]);
    expect(stored).toMatchObject({ ...first, startedAt: expect.any(Number) });
    expect(stored.lastSeenAt).toBe(stored.startedAt);

    const second = node({ roles: ['signer'] });
    await repository.register(second, WINDOW_MS, (live) => seen.push(live));
    expect(seen[1]?.map((entry) => entry.nodeId)).toEqual([first.nodeId]);
    expect((await repository.listLive(WINDOW_MS)).map((entry) => entry.nodeId)).toEqual([
      first.nodeId,
      second.nodeId,
    ]);
  });

  it('writes nothing when the check refuses', async () => {
    const running = node();
    await repository.register(running, WINDOW_MS, () => undefined);
    await expect(
      repository.register(node(), WINDOW_MS, () => {
        throw new Error('refused');
      })
    ).rejects.toThrow('refused');
    expect((await repository.listLive(WINDOW_MS)).map((entry) => entry.nodeId)).toEqual([
      running.nodeId,
    ]);
  });

  it('leaves a node unseen for the window out, and removes it at the next registration', async () => {
    const stopped = node();
    await repository.register(stopped, WINDOW_MS, () => undefined);
    await age(stopped.nodeId, WINDOW_MS + 5_000);
    expect(await repository.listLive(WINDOW_MS)).toEqual([]);

    const seen: (readonly DeploymentNode[])[] = [];
    await repository.register(node(), WINDOW_MS, (live) => seen.push(live));
    expect(seen).toEqual([[]]);
    const { rows } = await pool().query('SELECT node_id FROM deployment_nodes WHERE node_id = $1', [
      stopped.nodeId,
    ]);
    expect(rows).toEqual([]);
  });

  it('runs two registrations at once one after the other, so the second sees the first', async () => {
    const seen: string[][] = [];
    await Promise.all(
      [node(), node()].map((entry) =>
        repository.register(entry, WINDOW_MS, (live) =>
          seen.push(live.map((other) => other.nodeId))
        )
      )
    );
    expect(seen.map((ids) => ids.length).sort()).toEqual([0, 1]);
  });

  it('marks a node seen, and writes its row again, with its start, once it is gone', async () => {
    const stored = await repository.register(node(), WINDOW_MS, () => undefined);
    await age(stored.nodeId, 60_000);
    await expect(repository.heartbeat(stored)).resolves.toBe('seen');
    const [live] = await repository.listLive(WINDOW_MS);
    expect(live?.lastSeenAt).toBeGreaterThanOrEqual(stored.lastSeenAt);

    await repository.remove(stored.nodeId);
    expect(await repository.listLive(WINDOW_MS)).toEqual([]);
    await expect(repository.heartbeat(stored)).resolves.toBe('restored');
    const [restored] = await repository.listLive(WINDOW_MS);
    expect(restored).toMatchObject({ nodeId: stored.nodeId, startedAt: stored.startedAt });
  });

  it('refuses a digest that is not one, an array of key digests, and an empty role list', async () => {
    for (const bad of [
      node({ configDigest: 'not-a-digest' }),
      node({ configKeys: ['a'] as unknown as Record<string, string> }),
      node({ roles: [] }),
    ]) {
      await expect(repository.register(bad, WINDOW_MS, () => undefined)).rejects.toThrow();
    }
    expect(await repository.listLive(WINDOW_MS)).toEqual([]);
  });

  it('refuses a window that is not a positive whole number of ms', async () => {
    await expect(repository.listLive(0)).rejects.toThrow(RangeError);
    await expect(repository.listLive(1.5)).rejects.toThrow(RangeError);
  });
});
