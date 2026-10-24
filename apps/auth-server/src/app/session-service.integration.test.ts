import { cachePlugin } from '@qauth-labs/fastify-plugin-cache';
import { databasePlugin } from '@qauth-labs/fastify-plugin-db';
import { sessionCacheKey, sessionServicePlugin } from '@qauth-labs/fastify-plugin-sessions';
import {
  applyQauthMigrations,
  requireDockerOrSkip,
  type StartedPostgres,
  type StartedRedis,
  startPostgresContainer,
  startRedisContainer,
} from '@qauth-labs/shared-testing';
import Fastify, { type FastifyInstance } from 'fastify';
import type { Counter } from 'prom-client';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { type E2eInfrastructure, startE2eInfrastructure } from '../testing/e2e-harness';
import { metricsPlugin } from './plugins/metrics';

/**
 * THE BROWSER SESSION SERVICE ON A REAL POSTGRES AND REDIS (ADR-019 Decision
 * 3, issue #469).
 *
 * Each "node" is a Fastify instance with its own pool and its own Redis
 * client, the database, cache and metrics plugins and the session service
 * plugin, as the auth-server registers them. What only real servers show: the
 * conditional `UPDATE` that lets one of two nodes write `last_seen_at`, the
 * Redis tombstone a revocation leaves for the other nodes, and what the
 * service does when the Redis or the Postgres container is stopped under it.
 *
 * `last_seen_at` writes are counted by a trigger this suite adds to its own
 * database, so "one write" means one row version, not one call that claimed to
 * write.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const MINUTE = 60_000;
const SID_UNKNOWN = '0199a000-0000-7000-8000-000000000999';

interface NodeSettings {
  readonly databaseUrl: string;
  readonly redisUrl: string;
  /** Seconds; the service's default (60) when absent. */
  readonly cacheTtlSeconds?: number;
}

/** A node, as the auth-server builds the service. */
async function startNode(settings: NodeSettings): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });
  await app.register(databasePlugin, {
    config: {
      connectionString: settings.databaseUrl,
      pool: { max: 20, connectionTimeoutMillis: 2_000 },
    },
  });
  await app.register(cachePlugin, {
    // Fail a command fast once the server is gone, as the deployment's
    // REDIS_MAX_RETRIES and REDIS_COMMAND_TIMEOUT would.
    config: {
      url: settings.redisUrl,
      maxRetriesPerRequest: 1,
      connectTimeout: 1_000,
      commandTimeout: 1_000,
      lazyConnect: true,
    },
  });
  await app.register(metricsPlugin);
  await app.register(sessionServicePlugin, {
    metrics: {
      cacheLookups: app.metrics.sessionCacheLookups,
      storeReads: app.metrics.sessionPostgresReads,
      lastSeenWrites: app.metrics.sessionLastSeenWrites,
    },
    settings: {
      defaultMaxLifespanSeconds: 86_400,
      lastSeenIntervalSeconds: 60,
      ...(settings.cacheTtlSeconds === undefined
        ? {}
        : { cacheTtlSeconds: settings.cacheTtlSeconds }),
    },
  });
  await app.ready();
  return app;
}

/** Close a node whose Redis or Postgres may already be gone. */
async function stopNode(app: FastifyInstance | undefined): Promise<void> {
  if (app === undefined) return;
  app.redis.disconnect();
  await app.close().catch(() => undefined);
}

/** The total of a session counter's `result`, as the node's /metrics reports it. */
async function counted(counter: Counter<'result'>, result: string): Promise<number> {
  const { values } = await counter.get();
  return values
    .filter((value) => value.labels.result === result)
    .reduce((sum, value) => sum + value.value, 0);
}

async function seedRealm(
  app: FastifyInstance,
  lifetimes: { maxLifespan?: number; idleTimeout?: number } = {}
): Promise<string> {
  const { rows } = await app.dbPool.query<{ id: string }>(
    `INSERT INTO realms (name, sso_max_lifespan, sso_idle_timeout)
     VALUES ($1, $2, $3) RETURNING id`,
    [
      `realm-${Math.random().toString(36).slice(2)}`,
      lifetimes.maxLifespan ?? null,
      lifetimes.idleTimeout ?? null,
    ]
  );
  return rows[0].id;
}

async function seedUser(app: FastifyInstance, realmId: string): Promise<string> {
  const { rows } = await app.dbPool.query<{ id: string }>(
    `INSERT INTO users (realm_id) VALUES ($1) RETURNING id`,
    [realmId]
  );
  return rows[0].id;
}

/** Counts every change of `last_seen_at` in this suite's database. */
async function countLastSeenWrites(app: FastifyInstance): Promise<void> {
  await app.dbPool.query(`
    CREATE TABLE test_last_seen_writes (session_id uuid NOT NULL, last_seen_at bigint NOT NULL);
    CREATE FUNCTION test_record_last_seen_write() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF NEW.last_seen_at IS DISTINCT FROM OLD.last_seen_at THEN
        INSERT INTO test_last_seen_writes VALUES (NEW.id, NEW.last_seen_at);
      END IF;
      RETURN NEW;
    END $$;
    CREATE TRIGGER test_record_last_seen_write AFTER UPDATE ON sessions
      FOR EACH ROW EXECUTE FUNCTION test_record_last_seen_write();
  `);
}

async function lastSeenWrites(app: FastifyInstance, sid: string): Promise<number> {
  const { rows } = await app.dbPool.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM test_last_seen_writes WHERE session_id = $1`,
    [sid]
  );
  return rows[0].n;
}

describe('the session service on a real Postgres and Redis', () => {
  let dockerUp = false;
  let infra: E2eInfrastructure | undefined;
  /** Two nodes sharing Postgres and Redis. */
  let nodeA: FastifyInstance | undefined;
  let nodeB: FastifyInstance | undefined;
  /** A third node with Redis of its own (another database index) and a 1 s cache time. */
  let nodeC: FastifyInstance | undefined;
  let realmId = '';
  let userId = '';

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    const shared = {
      databaseUrl: infra.postgres.connectionString,
      redisUrl: infra.redis.connectionUrl,
    };
    nodeA = await startNode(shared);
    nodeB = await startNode(shared);
    nodeC = await startNode({
      ...shared,
      redisUrl: infra.redis.connectionUrl.replace(/\/0$/, '/1'),
      cacheTtlSeconds: 1,
    });
    await countLastSeenWrites(nodeA);
    realmId = await seedRealm(nodeA);
    userId = await seedUser(nodeA, realmId);
  }, 240_000);

  afterAll(async () => {
    await Promise.all([stopNode(nodeA), stopNode(nodeB), stopNode(nodeC)]);
    await infra?.teardown();
  });

  function nodes(): { a: FastifyInstance; b: FastifyInstance; c: FastifyInstance } {
    if (!nodeA || !nodeB || !nodeC) throw new Error('nodes not started');
    return { a: nodeA, b: nodeB, c: nodeC };
  }

  it('creates a row in Postgres and an entry in Redis, and a read after a cache miss reads Postgres and fills the cache', async (ctx) => {
    if (!dockerUp) return ctx.skip();
    const { a, b } = nodes();

    const session = await a.sessionService.create({
      realmId,
      userId,
      authTime: Date.now(),
      amr: ['pwd'],
      ipAddress: '203.0.113.7',
      userAgent: 'Agent/1.0',
    });
    const { rows } = await a.dbPool.query(
      `SELECT realm_id, user_id, amr, ip_address, user_agent FROM sessions WHERE id = $1`,
      [session.sid]
    );
    expect(rows).toEqual([
      {
        realm_id: realmId,
        user_id: userId,
        amr: ['pwd'],
        ip_address: '203.0.113.7',
        user_agent: 'Agent/1.0',
      },
    ]);
    const key = sessionCacheKey(realmId, session.sid);
    expect(await a.redis.exists(key)).toBe(1);

    await a.redis.del(key);
    const readsBefore = await counted(b.metrics.sessionPostgresReads, 'ok');
    expect(await b.sessionService.get({ realmId, sid: session.sid })).toMatchObject({
      sid: session.sid,
      userId,
    });
    expect(await counted(b.metrics.sessionPostgresReads, 'ok')).toBe(readsBefore + 1);
    const ttl = await a.redis.pttl(key);
    expect(ttl).toBeGreaterThan(0);
    expect(ttl).toBeLessThanOrEqual(MINUTE);

    // The next read is a hit, on either node.
    await a.sessionService.get({ realmId, sid: session.sid });
    expect(await counted(b.metrics.sessionPostgresReads, 'ok')).toBe(readsBefore + 1);
    expect(await counted(a.metrics.sessionCacheLookups, 'hit')).toBeGreaterThanOrEqual(1);
  });

  it('answers absent for a session of another realm', async (ctx) => {
    if (!dockerUp) return ctx.skip();
    const { a, b } = nodes();
    const otherRealm = await seedRealm(a);
    const { sid } = await a.sessionService.create({ realmId, userId, authTime: Date.now() });

    expect(await b.sessionService.get({ realmId: otherRealm, sid })).toBeNull();
    await a.redis.del(sessionCacheKey(realmId, sid));
    expect(await b.sessionService.get({ realmId: otherRealm, sid })).toBeNull();
    expect(await b.sessionService.get({ realmId, sid })).not.toBeNull();
  });

  it('two nodes touching one session in the same interval cause one write', async (ctx) => {
    if (!dockerUp) return ctx.skip();
    const { a, b } = nodes();
    const { sid } = await a.sessionService.create({ realmId, userId, authTime: Date.now() });
    // Last seen two minutes ago, and not in the cache: both nodes go to
    // Postgres, and both find the write due.
    await a.dbPool.query(
      `UPDATE sessions SET last_seen_at = last_seen_at - $2::bigint WHERE id = $1`,
      [sid, 2 * MINUTE]
    );
    await a.dbPool.query(`DELETE FROM test_last_seen_writes WHERE session_id = $1`, [sid]);
    await a.redis.del(sessionCacheKey(realmId, sid));
    const writtenBefore =
      (await counted(a.metrics.sessionLastSeenWrites, 'written')) +
      (await counted(b.metrics.sessionLastSeenWrites, 'written'));

    const reads = await Promise.all(
      Array.from({ length: 20 }, (_, i) =>
        (i % 2 === 0 ? a : b).sessionService.get({ realmId, sid })
      )
    );

    expect(reads.every((read) => read?.sid === sid)).toBe(true);
    expect(await lastSeenWrites(a, sid)).toBe(1);
    const writtenAfter =
      (await counted(a.metrics.sessionLastSeenWrites, 'written')) +
      (await counted(b.metrics.sessionLastSeenWrites, 'written'));
    expect(writtenAfter - writtenBefore).toBe(1);

    // And the reads that follow, inside the interval, write nothing more.
    for (let i = 0; i < 10; i++) {
      await (i % 2 === 0 ? a : b).sessionService.get({ realmId, sid });
    }
    expect(await lastSeenWrites(a, sid)).toBe(1);
  });

  it('a revoked session is absent on the next read on the same node, and within the cache time on another node', async (ctx) => {
    if (!dockerUp) return ctx.skip();
    const { a, b, c } = nodes();
    const { sid } = await a.sessionService.create({ realmId, userId, authTime: Date.now() });
    // Each node has the session cached: A and B in the shared Redis, C in its own.
    expect(await b.sessionService.get({ realmId, sid })).not.toBeNull();
    expect(await c.sessionService.get({ realmId, sid })).not.toBeNull();

    const ended = await a.sessionService.revoke({ realmId, sid, reason: 'sign_out' });
    const revokedAt = Date.now();

    expect(ended).toMatchObject({ id: sid, revokedReason: 'sign_out' });
    expect(await a.sessionService.get({ realmId, sid })).toBeNull();
    // B shares A's Redis: the tombstone is there at once.
    expect(await b.sessionService.get({ realmId, sid })).toBeNull();
    expect(await a.redis.exists(sessionCacheKey(realmId, sid))).toBe(0);
    const tombstoneTtl = await a.redis.pttl(`${sessionCacheKey(realmId, sid)}:revoked`);
    expect(tombstoneTtl).toBeGreaterThan(0);
    expect(tombstoneTtl).toBeLessThanOrEqual(MINUTE);

    // C's own cache never saw the tombstone; its entry lapses within its
    // cache time (1 s), and Postgres then says the session ended.
    let absent = false;
    while (!absent && Date.now() - revokedAt < 3_000) {
      absent = (await c.sessionService.get({ realmId, sid })) === null;
      if (!absent) await new Promise((resolve) => setTimeout(resolve, 100));
    }
    expect(absent).toBe(true);
    expect(Date.now() - revokedAt).toBeLessThanOrEqual(1_500);
  });

  it('applies the realm row’s lifetimes', async (ctx) => {
    if (!dockerUp) return ctx.skip();
    const { a, b } = nodes();
    const shortRealm = await seedRealm(a, { maxLifespan: 3600, idleTimeout: 600 });
    const shortUser = await seedUser(a, shortRealm);
    const before = Date.now();

    const session = await a.sessionService.create({
      realmId: shortRealm,
      userId: shortUser,
      authTime: before,
    });

    const { rows } = await a.dbPool.query<{ expires_at: string }>(
      `SELECT expires_at FROM sessions WHERE id = $1`,
      [session.sid]
    );
    const expiresAt = Number(rows[0].expires_at);
    expect(expiresAt).toBeGreaterThanOrEqual(before + 3600 * 1000);
    expect(expiresAt).toBeLessThanOrEqual(Date.now() + 3600 * 1000);
    expect(session.idleExpiresAt).toBe(session.lastSeenAt + 600 * 1000);

    // Unused for longer than the idle limit, as Postgres records it.
    await a.dbPool.query(
      `UPDATE sessions SET last_seen_at = last_seen_at - $2::bigint WHERE id = $1`,
      [session.sid, 601 * 1000]
    );
    await a.redis.del(sessionCacheKey(shortRealm, session.sid));
    expect(await b.sessionService.get({ realmId: shortRealm, sid: session.sid })).toBeNull();
  });
});

describe('the session service with Redis stopped', () => {
  let dockerUp = false;
  let postgres: StartedPostgres | undefined;
  let redis: StartedRedis | undefined;
  let node: FastifyInstance | undefined;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    [postgres, redis] = await Promise.all([startPostgresContainer(), startRedisContainer()]);
    await applyQauthMigrations(postgres.connectionString);
    node = await startNode({
      databaseUrl: postgres.connectionString,
      redisUrl: redis.connectionUrl,
    });
  }, 240_000);

  afterAll(async () => {
    await stopNode(node);
    await postgres?.stop();
  });

  it('still signs in, reads sessions from Postgres and ends them', async (ctx) => {
    if (!dockerUp || !node || !redis) return ctx.skip();
    const realmId = await seedRealm(node);
    const userId = await seedUser(node, realmId);
    const before = await node.sessionService.create({ realmId, userId, authTime: Date.now() });

    await redis.stop();

    // Sign-in: the row is written, the cache write fails quietly.
    const after = await node.sessionService.create({ realmId, userId, authTime: Date.now() });
    const { rows } = await node.dbPool.query(`SELECT id FROM sessions WHERE id = $1`, [after.sid]);
    expect(rows).toHaveLength(1);

    // Reads: both sessions, the one cached before Redis stopped too.
    expect(await node.sessionService.get({ realmId, sid: after.sid })).toMatchObject({
      sid: after.sid,
      userId,
    });
    expect(await node.sessionService.get({ realmId, sid: before.sid })).toMatchObject({
      sid: before.sid,
    });
    expect(await node.sessionService.get({ realmId, sid: SID_UNKNOWN })).toBeNull();
    expect(await counted(node.metrics.sessionCacheLookups, 'error')).toBe(3);
    expect(await counted(node.metrics.sessionPostgresReads, 'ok')).toBe(3);

    // An end is still stored, and the next read sees it.
    expect(
      await node.sessionService.revoke({ realmId, sid: after.sid, reason: 'sign_out' })
    ).toMatchObject({ id: after.sid });
    expect(await node.sessionService.get({ realmId, sid: after.sid })).toBeNull();
  });
});

describe('the session service with Postgres stopped', () => {
  let dockerUp = false;
  let postgres: StartedPostgres | undefined;
  let redis: StartedRedis | undefined;
  let node: FastifyInstance | undefined;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    [postgres, redis] = await Promise.all([startPostgresContainer(), startRedisContainer()]);
    await applyQauthMigrations(postgres.connectionString);
    node = await startNode({
      databaseUrl: postgres.connectionString,
      redisUrl: redis.connectionUrl,
      cacheTtlSeconds: 1,
    });
  }, 240_000);

  afterAll(async () => {
    await stopNode(node);
    await redis?.stop();
  });

  it('resolves no session: an uncached one at once, a cached one once the cache time has passed', async (ctx) => {
    if (!dockerUp || !node || !postgres) return ctx.skip();
    const realmId = await seedRealm(node);
    const userId = await seedUser(node, realmId);
    const cached = await node.sessionService.create({ realmId, userId, authTime: Date.now() });
    const uncached = await node.sessionService.create({ realmId, userId, authTime: Date.now() });
    await node.redis.del(sessionCacheKey(realmId, uncached.sid));
    const cachedAt = Date.now();

    await postgres.stop();

    expect(await node.sessionService.get({ realmId, sid: uncached.sid })).toBeNull();
    expect(await counted(node.metrics.sessionPostgresReads, 'error')).toBe(1);
    await expect(
      node.sessionService.create({ realmId, userId, authTime: Date.now() })
    ).rejects.toThrow();
    await expect(
      node.sessionService.revoke({ realmId, sid: cached.sid, reason: 'sign_out' })
    ).rejects.toThrow();

    // The cache alone vouches for a session no longer than the cache time.
    await new Promise((resolve) =>
      setTimeout(resolve, Math.max(0, 1_000 - (Date.now() - cachedAt)))
    );
    expect(await node.sessionService.get({ realmId, sid: cached.sid })).toBeNull();
    expect(await node.sessionService.get({ realmId, sid: uncached.sid })).toBeNull();
  });
});
