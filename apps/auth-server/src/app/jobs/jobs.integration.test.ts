import { randomBytes, randomUUID } from 'node:crypto';

import { databasePlugin } from '@qauth-labs/fastify-plugin-db';
import {
  applyQauthMigrations,
  requireDockerOrSkip,
  type StartedPostgres,
  startPostgresContainer,
  truncateDomainTablesStatement,
} from '@qauth-labs/shared-testing';
import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { createManualClock, type ManualClock } from '../../testing/manual-clock';
import { jobsPlugin } from '../plugins/jobs';
import { metricsPlugin } from '../plugins/metrics';
import { defineJob, jitterWindowMs, type JobSpec } from './job-runner';
import { createPurgeExpiredJob } from './purge-expired';

/**
 * THE JOB RUNNER AGAINST A REAL POSTGRES (ADR-019 Decision 8).
 *
 * Two properties only a real database can show: that Postgres advisory locks
 * keep a job to one node per interval when two nodes share the database, and
 * that a node whose session dies frees the job, with nobody releasing the lock.
 * Each "node" is a Fastify instance with its own connection pool, its own job
 * runner and the same manual clock, so the nodes agree on time as synchronised
 * clocks would. And `purge-expired` against the real tables and the real
 * `deleteExpired` statements.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const INTERVAL = 60_000;
const WINDOW = jitterWindowMs(INTERVAL);
const SKIPPED = 'job run skipped: another node holds its lock';
const WAIT = { timeout: 10_000, interval: 25 };

interface LogLine {
  readonly msg: string;
  readonly job?: string;
}

interface Node {
  readonly app: FastifyInstance;
  readonly lines: LogLine[];
}

describe('job runner on a real Postgres', () => {
  let postgres: StartedPostgres | undefined;
  let admin: FastifyInstance | undefined;
  let dockerUp = false;
  const nodes: Node[] = [];

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    postgres = await startPostgresContainer();
    await applyQauthMigrations(postgres.connectionString);
    admin = Fastify({ logger: false });
    await admin.register(databasePlugin, {
      config: { connectionString: postgres.connectionString },
    });
    await admin.ready();
  }, 240_000);

  afterAll(async () => {
    await Promise.all(nodes.map((node) => node.app.close()));
    await admin?.close();
    await postgres?.stop();
  });

  beforeEach(async (ctx) => {
    if (!dockerUp) {
      ctx.skip();
      return;
    }
    await Promise.all(nodes.splice(0).map((node) => node.app.close()));
    await database().dbPool.query(truncateDomainTablesStatement());
  });

  function database(): FastifyInstance {
    if (!admin) throw new Error('database not started');
    return admin;
  }

  /** A node of the deployment: its own pool, its own runner, the shared clock. */
  async function startNode(
    clock: ManualClock,
    jobs: JobSpec[],
    random: () => number
  ): Promise<Node> {
    if (!postgres) throw new Error('database not started');
    const lines: LogLine[] = [];
    const app = Fastify({
      logger: {
        level: 'debug',
        stream: {
          write(chunk: string) {
            lines.push(JSON.parse(chunk) as LogLine);
          },
        },
      },
    });
    await app.register(databasePlugin, {
      config: { connectionString: postgres.connectionString, pool: { max: 4, min: 0 } },
    });
    await app.register(metricsPlugin);
    await app.register(jobsPlugin, { jobs: jobs.map(defineJob), clock, random });
    await app.ready();
    const node = { app, lines };
    nodes.push(node);
    return node;
  }

  /** The sessions holding an advisory lock right now. */
  async function lockHolders(): Promise<number[]> {
    const { rows } = await database().dbPool.query<{ pid: number }>(
      "SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND granted"
    );
    return rows.map((row) => row.pid);
  }

  function count(node: Node, msg: string): number {
    return node.lines.filter((line) => line.msg === msg).length;
  }

  /** Waker offsets that alternate between two nodes, slot by slot. */
  function alternating(first: number, second: number): () => number {
    let slot = 0;
    return () => (slot++ % 2 === 0 ? first : second);
  }

  it('runs a job once per interval when two nodes share the database', async () => {
    const clock = createManualClock();
    const runs: string[] = [];
    const recorder = (name: string): JobSpec => ({
      name: 'integration-job',
      role: 'api',
      intervalMs: INTERVAL,
      run: async () => {
        runs.push(name);
      },
    });
    // A wakes first in odd slots, at 10% of the wake window; B in even ones.
    const a = await startNode(clock, [recorder('a')], alternating(0.1, 0.7));
    const b = await startNode(clock, [recorder('b')], alternating(0.7, 0.1));

    for (let slot = 1; slot <= 4; slot++) {
      const start = slot * INTERVAL;
      const [first, second] = slot % 2 === 1 ? [a, b] : [b, a];

      await clock.advanceTo(start + 0.1 * WINDOW);
      await vi.waitFor(() => expect(runs).toHaveLength(slot), WAIT);
      expect((await lockHolders()).length).toBe(1);

      // The second node wakes after the first run has ended, and still skips.
      await clock.advanceTo(start + 0.7 * WINDOW);
      await vi.waitFor(() => expect(count(second, SKIPPED)).toBe(Math.ceil(slot / 2)), WAIT);
      expect(runs).toHaveLength(slot);

      await clock.advanceTo(start + 2 * WINDOW);
      await vi.waitFor(async () => expect(await lockHolders()).toEqual([]), WAIT);
      expect(count(first, 'job run finished')).toBe(Math.ceil(slot / 2));
    }

    expect(runs).toEqual(['a', 'b', 'a', 'b']);
  });

  it('gives the job to another node at its next interval when the holding node dies', async () => {
    const clock = createManualClock();
    const runs: string[] = [];
    const a = await startNode(
      clock,
      [
        {
          name: 'integration-job',
          role: 'api',
          intervalMs: INTERVAL,
          // A long run: it ends only when told to.
          run: ({ signal }) =>
            new Promise<void>((resolve) => {
              runs.push('a');
              signal.addEventListener('abort', () => resolve());
            }),
        },
      ],
      () => 0.1
    );
    const b = await startNode(
      clock,
      [
        {
          name: 'integration-job',
          role: 'api',
          intervalMs: INTERVAL,
          run: async () => {
            runs.push('b');
          },
        },
      ],
      () => 0.7
    );

    await clock.advanceTo(INTERVAL + 0.1 * WINDOW);
    await vi.waitFor(() => expect(runs).toEqual(['a']), WAIT);
    const [holder] = await lockHolders();

    await clock.advanceTo(INTERVAL + 0.7 * WINDOW);
    await vi.waitFor(() => expect(count(b, SKIPPED)).toBe(1), WAIT);

    // Node A dies: its session ends without releasing anything, and its timers
    // go with it.
    await database().dbPool.query('SELECT pg_terminate_backend($1)', [holder]);
    await vi.waitFor(async () => expect(await lockHolders()).toEqual([]), WAIT);
    await vi.waitFor(
      () => expect(count(a, 'job lock was lost during the run; the run was stopped')).toBe(1),
      WAIT
    );
    await a.app.close();

    await clock.advanceTo(2 * INTERVAL + 0.7 * WINDOW);
    await vi.waitFor(() => expect(runs).toEqual(['a', 'b']), WAIT);
    await vi.waitFor(() => expect(count(b, 'job run finished')).toBe(1), WAIT);
  });

  describe('purge-expired', () => {
    const hash = () => randomBytes(32).toString('hex');

    async function seed() {
      const { repositories } = database();
      const realm = await repositories.realms.create({ name: `realm-${hash().slice(0, 8)}` });
      const user = await repositories.users.create({ realmId: realm.id });
      const credential = await repositories.userCredentials.create({
        userId: user.id,
        realmId: realm.id,
        providerType: 'password',
        externalSub: 'user@example.com',
        credentialData: { password_hash: 'argon2-hash', email_verified: false },
      });
      const client = await repositories.oauthClients.create({
        realmId: realm.id,
        clientId: 'purge-client',
        clientSecretHash: 'secret-hash',
        name: 'Purge Client',
        redirectUris: ['https://app.example.com/cb'],
        scopes: ['openid'],
        grantTypes: ['authorization_code', 'refresh_token'],
      });
      return { realm, user, credential, client };
    }

    it('removes the expired rows of the four tables, keeping each refresh-token family that has a live token', async () => {
      const { repositories, dbPool } = database();
      const { realm, user, credential, client } = await seed();
      const now = Date.now();
      const past = now - 60_000;
      const future = now + 60 * 60_000;

      for (const [code, expiresAt] of [
        ['expired-code', past],
        ['live-code', future],
      ] as const) {
        await repositories.authorizationCodes.create({
          code,
          oauthClientId: client.id,
          userId: user.id,
          redirectUri: 'https://app.example.com/cb',
          codeChallenge: 'challenge',
          codeChallengeMethod: 'S256',
          scopes: ['openid'],
          expiresAt,
        });
      }
      // Refresh tokens are purged by family: a family goes whole once its
      // newest token has expired, and a rotated token stays while its family
      // has a live token, so replaying it still revokes the family.
      const family = { ended: randomUUID(), live: randomUUID(), revoked: randomUUID() };
      const refresh = {
        endedRotated: hash(),
        endedNewest: hash(),
        liveRotated: hash(),
        liveNewest: hash(),
        revokedRotated: hash(),
        revokedNewest: hash(),
      };
      for (const [tokenHash, familyId, expiresAt, revoked] of [
        [refresh.endedRotated, family.ended, past - 60_000, true],
        [refresh.endedNewest, family.ended, past, false],
        [refresh.liveRotated, family.live, past, true],
        [refresh.liveNewest, family.live, future, false],
        [refresh.revokedRotated, family.revoked, past, true],
        [refresh.revokedNewest, family.revoked, future, true],
      ] as const) {
        await repositories.refreshTokens.create({
          tokenHash,
          familyId,
          userId: user.id,
          oauthClientId: client.id,
          expiresAt,
          revoked,
        });
      }
      const verification = { expired: hash(), live: hash() };
      for (const [tokenHash, expiresAt] of [
        [verification.expired, past],
        [verification.live, future],
      ] as const) {
        await repositories.emailVerificationTokens.create({
          tokenHash,
          credentialId: credential.id,
          expiresAt,
        });
      }
      const state = { expired: hash(), live: hash(), liveCode: hash() };
      for (const [stateHash, expiresAt, codeExpiresAt] of [
        [state.expired, past, undefined],
        [state.live, future, undefined],
        // Expired request whose Response Code is still live: kept (#405).
        [state.liveCode, past, future],
      ] as const) {
        await repositories.oid4vpRequestStates.create({
          realmId: realm.id,
          stateHash,
          nonce: 'nonce-value',
          verifierProfile: 'oid4vp-1.0-base',
          responseMode: 'direct_post',
          dcqlQuery: { credentials: [{ id: 'pid', format: 'dc+sd-jwt' }] },
          expiresAt,
          ...(codeExpiresAt === undefined
            ? {}
            : { redeemedAt: past, responseCodeHash: hash(), responseCodeExpiresAt: codeExpiresAt }),
        });
      }

      const info = vi.fn();
      await createPurgeExpiredJob(repositories).run({
        signal: new AbortController().signal,
        now: () => Date.now(),
        log: { info } as unknown as FastifyInstance['log'],
      });

      expect(info).toHaveBeenCalledWith(
        {
          deleted: {
            authorization_codes: 1,
            refresh_tokens: 2,
            email_verification_tokens: 1,
            oid4vp_request_states: 1,
          },
        },
        'expired rows purged'
      );
      const column = async (sql: string) =>
        (await dbPool.query<{ value: string }>(sql)).rows.map((row) => row.value).sort();
      expect(await column('SELECT code AS value FROM authorization_codes')).toEqual(['live-code']);
      expect(await column('SELECT token_hash AS value FROM refresh_tokens')).toEqual(
        [
          refresh.liveRotated,
          refresh.liveNewest,
          refresh.revokedRotated,
          refresh.revokedNewest,
        ].sort()
      );
      expect(await column('SELECT token_hash AS value FROM email_verification_tokens')).toEqual([
        verification.live,
      ]);
      expect(await column('SELECT state_hash AS value FROM oid4vp_request_states')).toEqual(
        [state.live, state.liveCode].sort()
      );
    });

    it('runs on the job runner under its lock', async () => {
      const clock = createManualClock();
      const { repositories, dbPool } = database();
      const { user, client } = await seed();
      await repositories.authorizationCodes.create({
        code: 'expired-code',
        oauthClientId: client.id,
        userId: user.id,
        redirectUri: 'https://app.example.com/cb',
        codeChallenge: 'challenge',
        codeChallengeMethod: 'S256',
        scopes: ['openid'],
        expiresAt: Date.now() - 60_000,
      });

      if (!postgres) throw new Error('database not started');
      const lines: LogLine[] = [];
      const app = Fastify({
        logger: {
          level: 'info',
          stream: {
            write(chunk: string) {
              lines.push(JSON.parse(chunk) as LogLine);
            },
          },
        },
      });
      await app.register(databasePlugin, {
        config: { connectionString: postgres.connectionString },
      });
      await app.register(metricsPlugin);
      // The server's own job list and lock: only the clock is injected.
      await app.register(jobsPlugin, { clock, random: () => 0 });
      await app.ready();
      nodes.push({ app, lines });

      await clock.advanceTo(60 * 60_000);
      await vi.waitFor(
        () => expect(lines.some((line) => line.msg === 'job run finished')).toBe(true),
        WAIT
      );

      expect(lines.find((line) => line.msg === 'expired rows purged')?.job).toBe('purge-expired');
      const { rows } = await dbPool.query('SELECT id FROM authorization_codes');
      expect(rows).toEqual([]);
    });
  });
});
