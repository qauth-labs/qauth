/**
 * THE CONFIGURATION DIGEST CHECK AT BOOT, against a real Postgres and Redis
 * (ADR-019 Decision 8, issue #499).
 *
 * Each node is a real auth server booted by the harness on the suite's one
 * database, so every node sees the others in the node list:
 *
 * - two nodes with equal settings both boot, both are listed and ready, and
 *   a node that closes leaves the list;
 * - a second node whose HYBRID_SIGNING_ENABLED differs refuses to boot, and
 *   the refusal names the key, never a value;
 * - a node of another release boots with a warning, with or without
 *   different settings;
 * - with CONFIG_DIGEST_ROLLOUT=true the mismatch is a warning;
 * - a node last seen more than two minutes ago no longer blocks a boot, and
 *   the boot removes its row; one seen a minute ago still does.
 *
 * Every node runs `ed25519+ml-dsa-65` and generates the realm's keys, so the
 * hybrid switch is the one setting a node changes: the deployment signs
 * hybrid tokens, and the node that turns it off differs in that key alone.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import type { DeploymentNodeList } from './helpers/deployment-nodes';
import { UNRELEASED_VERSION } from './helpers/release-version';

interface LogLine {
  readonly level: number;
  readonly msg: string;
  readonly component?: string;
  readonly [field: string]: unknown;
}

interface Node {
  readonly server: BootedAuthServer;
  readonly app: FastifyInstance;
  readonly nodes: DeploymentNodeList;
  /** What it logged at `warn` and up. */
  readonly lines: LogLine[];
}

/** pino's `warn`. */
const WARN = 40;

/** The deployment's signing settings: hybrid signing on. */
const HYBRID = { SIGNING_ALGORITHM_MODE: 'ed25519+ml-dsa-65', HYBRID_SIGNING_ENABLED: 'true' };

/** The one setting a node changes: hybrid signing off, on the same algorithm mode. */
const HYBRID_OFF = { HYBRID_SIGNING_ENABLED: 'false' };

/** Another release than the harness's, which names none. */
const OTHER_RELEASE = '9.9.9';

/** A 64-hex digest, which no refusal or warning may carry. */
const HEX_DIGEST = /[0-9a-f]{64}/;

describe('the configuration digest check at boot (#499)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let dockerUp = false;
  const running: Node[] = [];

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
  }, 240_000);

  afterAll(async () => {
    await infra?.teardown();
  });

  beforeEach((ctx) => {
    if (!dockerUp) ctx.skip();
  });

  afterEach(async () => {
    // Rows a test wrote by hand go with the nodes; each node removes its own.
    await running[0]?.app.dbPool.query('DELETE FROM deployment_nodes');
    await Promise.all(running.splice(0).map(async (node) => node.server.close()));
  });

  /** The deployment's settings, plus `extra`; the key boot step generates the keys. */
  function variables(extra: Record<string, string> = {}): Record<string, string> {
    if (!infra || !jwt) throw new Error('infrastructure not started');
    const environment: Record<string, string> = {
      ...baseEnvironment(infra, jwt),
      ...HYBRID,
      ...extra,
    };
    delete environment['JWT_PRIVATE_KEY'];
    delete environment['JWT_PUBLIC_KEY'];
    return environment;
  }

  async function boot(environment: Record<string, string> = variables()): Promise<Node> {
    const lines: LogLine[] = [];
    const server = await bootAuthServer(environment, {
      logStream: { write: (line) => void lines.push(JSON.parse(line) as LogLine) },
    });
    const { app } = server;
    const nodes = app.deploymentNodes;
    if (nodes === null) throw new Error('the node list is off');
    const node = { server, app, nodes, lines };
    running.push(node);
    return node;
  }

  /** The error a boot that must fail rejects with. */
  async function refusal(environment: Record<string, string>): Promise<Error> {
    const outcome = await boot(environment).then(
      () => undefined,
      (error: unknown) => error
    );
    if (!(outcome instanceof Error)) throw new Error('the boot did not fail');
    return outcome;
  }

  async function stop(node: Node): Promise<void> {
    running.splice(running.indexOf(node), 1);
    await node.server.close();
  }

  async function listed(node: Node): Promise<string[]> {
    return (await node.nodes.list()).map((entry) => entry.nodeId);
  }

  /** The node list's own warnings. */
  function nodeListWarnings(node: Node): LogLine[] {
    return node.lines.filter((line) => line.level >= WARN && line.component === 'deployment-nodes');
  }

  async function configDigestCheck(node: Node) {
    const response = await node.app.inject({ method: 'GET', url: '/ready' });
    return response.json<{ checks: Record<string, unknown> }>().checks['config_digest'];
  }

  /** Move a row's last sighting `ms` before the database's clock. */
  async function lastSeen(owner: Node, nodeId: string, ms: number): Promise<void> {
    await owner.app.dbPool.query(
      `UPDATE deployment_nodes
          SET last_seen_at = (extract(epoch FROM clock_timestamp()) * 1000)::bigint - $2::bigint
        WHERE node_id = $1`,
      [nodeId, ms]
    );
  }

  it('boots two nodes with equal settings, lists both as ready, and drops a node that closes', async () => {
    const first = await boot();
    const second = await boot();

    expect(new Set(await listed(second))).toEqual(
      new Set([first.nodes.nodeId, second.nodes.nodeId])
    );
    for (const node of [first, second]) {
      expect(await configDigestCheck(node)).toEqual({ status: 'ok' });
      expect(nodeListWarnings(node)).toEqual([]);
    }

    // A clean shutdown removes the node's row.
    await stop(first);
    expect(await listed(second)).toEqual([second.nodes.nodeId]);

    // A node missing from the list is not ready: a booting node would not
    // compare its settings with it.
    await second.app.dbPool.query('DELETE FROM deployment_nodes WHERE node_id = $1', [
      second.nodes.nodeId,
    ]);
    expect(await configDigestCheck(second)).toEqual({ status: 'fail', reason: 'error' });
  }, 180_000);

  it('refuses a second node whose HYBRID_SIGNING_ENABLED differs, naming the key and no value', async () => {
    const first = await boot();

    const error = await refusal(variables(HYBRID_OFF));
    expect(error.name).toBe('ConfigDigestMismatchError');
    expect(error.message).toContain(
      `differs from a running node of release ${UNRELEASED_VERSION} in HYBRID_SIGNING_ENABLED:`
    );
    expect(error.message).toContain(first.nodes.nodeId);
    expect(error.message).toContain('CONFIG_DIGEST_ROLLOUT=true');
    // Only the key that differs, and neither node's value of it: the one
    // `true` is the advice to set the rollout switch.
    expect(error.message).not.toContain('SIGNING_ALGORITHM_MODE');
    expect(error.message).not.toMatch(/HYBRID_SIGNING_ENABLED\s*=/);
    expect(error.message.replace('CONFIG_DIGEST_ROLLOUT=true', '')).not.toMatch(
      /\b(true|false)\b|ml-dsa|ed25519/i
    );
    expect(error.message).not.toMatch(HEX_DIGEST);

    // The refused node wrote no row, and the running one was not disturbed.
    expect(await listed(first)).toEqual([first.nodes.nodeId]);
    expect(await configDigestCheck(first)).toEqual({ status: 'ok' });
  }, 180_000);

  it('boots a node of another release with a warning, whether or not its settings differ', async () => {
    const first = await boot();

    const sameSettings = await boot(variables({ QAUTH_VERSION: OTHER_RELEASE }));
    expect(nodeListWarnings(sameSettings)).toEqual([
      expect.objectContaining({
        version: UNRELEASED_VERSION,
        ownVersion: OTHER_RELEASE,
        keys: [],
        nodes: [first.nodes.nodeId],
      }),
    ]);
    expect(new Set(await listed(first))).toEqual(
      new Set([first.nodes.nodeId, sameSettings.nodes.nodeId])
    );
    await stop(sameSettings);

    const otherSettings = await boot(variables({ ...HYBRID_OFF, QAUTH_VERSION: OTHER_RELEASE }));
    const [warning] = nodeListWarnings(otherSettings);
    expect(warning).toMatchObject({
      version: UNRELEASED_VERSION,
      ownVersion: OTHER_RELEASE,
      keys: ['HYBRID_SIGNING_ENABLED'],
    });
    expect(warning?.msg).toContain('HYBRID_SIGNING_ENABLED');
    expect(JSON.stringify(warning)).not.toMatch(HEX_DIGEST);
    expect(await configDigestCheck(otherSettings)).toEqual({ status: 'ok' });
  }, 240_000);

  it('turns the refusal into a warning with CONFIG_DIGEST_ROLLOUT=true', async () => {
    const first = await boot();

    const rolling = await boot(variables({ ...HYBRID_OFF, CONFIG_DIGEST_ROLLOUT: 'true' }));
    const warnings = nodeListWarnings(rolling);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatchObject({
      variable: 'CONFIG_DIGEST_ROLLOUT',
      keys: ['HYBRID_SIGNING_ENABLED'],
      nodes: [first.nodes.nodeId],
      version: UNRELEASED_VERSION,
    });
    expect(JSON.stringify(warnings[0])).not.toMatch(HEX_DIGEST);
    expect(new Set(await listed(first))).toEqual(
      new Set([first.nodes.nodeId, rolling.nodes.nodeId])
    );
    expect(await configDigestCheck(rolling)).toEqual({ status: 'ok' });
  }, 180_000);

  it('no longer blocks a boot with a node last seen more than two minutes ago, and removes its row', async () => {
    const owner = await boot();

    // A node with hybrid signing off, which stops without closing: its row
    // stays as it was, and nothing marks it seen any more.
    const stopped = await boot(variables({ ...HYBRID_OFF, CONFIG_DIGEST_ROLLOUT: 'true' }));
    const { rows } = await owner.app.dbPool.query<{
      node_id: string;
      roles: string[];
      version: string;
      config_digest: string;
      config_keys: Record<string, string>;
      started_at: string;
    }>(
      'SELECT node_id, roles, version, config_digest, config_keys, started_at FROM deployment_nodes WHERE node_id = $1',
      [stopped.nodes.nodeId]
    );
    const [row] = rows;
    if (row === undefined) throw new Error('the node is not listed');
    await stop(stopped);
    await owner.app.dbPool.query(
      `INSERT INTO deployment_nodes
         (node_id, roles, version, config_digest, config_keys, started_at, last_seen_at)
       VALUES ($1, $2, $3, $4, $5::jsonb, $6, $6)`,
      [
        row.node_id,
        row.roles,
        row.version,
        row.config_digest,
        JSON.stringify(row.config_keys),
        row.started_at,
      ]
    );

    // Seen a minute ago, it still counts: a node of the deployment's settings
    // differs from it, and refuses.
    await lastSeen(owner, row.node_id, 60_000);
    const error = await refusal(variables());
    expect(error.message).toContain('in HYBRID_SIGNING_ENABLED:');
    expect(error.message).toContain(row.node_id);

    // Seen more than two minutes ago, it no longer does; the boot removes it.
    await lastSeen(owner, row.node_id, 125_000);
    const next = await boot();
    expect(nodeListWarnings(next)).toEqual([]);
    expect(new Set(await listed(next))).toEqual(new Set([owner.nodes.nodeId, next.nodes.nodeId]));
    const left = await owner.app.dbPool.query('SELECT 1 FROM deployment_nodes WHERE node_id = $1', [
      row.node_id,
    ]);
    expect(left.rows).toEqual([]);
  }, 240_000);
});
