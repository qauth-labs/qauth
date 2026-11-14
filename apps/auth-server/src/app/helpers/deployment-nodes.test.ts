/**
 * The node list and the configuration digest check (ADR-019 Decision 8,
 * issue #499), against an in-memory list: which running nodes refuse a boot,
 * which only warn, what the refusal names, and the heartbeat's life cycle.
 * `deployment-nodes.integration.test.ts` boots real servers against Postgres.
 */
import type { DeploymentNode, DeploymentNodesRepository } from '@qauth-labs/fastify-plugin-db';
import {
  AUTH_SERVER_KEYS,
  configurationDigest,
  cryptoEnvSchema,
  jwtEnvSchema,
  SERVER_CONFIG_KEYS,
  SERVICE_ROLE_NAMES,
} from '@qauth-labs/server-config';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { envSchema } from '../../config/env-schema';
import {
  compareWithLiveNodes,
  ConfigDigestMismatchError,
  createDeploymentNodeList,
  DEPLOYMENT_NODE_HEARTBEAT_MS,
  DEPLOYMENT_NODE_LIVE_WINDOW_MS,
} from './deployment-nodes';

const SELF = {
  nodeId: '00000000-0000-4000-8000-000000000001',
  roles: ['web', 'api', 'admin', 'signer', 'delivery'],
  version: '0.3.0',
  configDigest: 'a'.repeat(64),
  configKeys: { HYBRID_SIGNING_ENABLED: 'h1', JWT_ISSUER: 'i1', KEK_PROVIDER: 'k1' },
};

let counter = 1;
function peer(extra: Partial<DeploymentNode> = {}): DeploymentNode {
  counter += 1;
  return {
    nodeId: `00000000-0000-4000-8000-${String(counter).padStart(12, '0')}`,
    roles: ['web', 'api'],
    version: SELF.version,
    configDigest: 'b'.repeat(64),
    configKeys: { HYBRID_SIGNING_ENABLED: 'h1', JWT_ISSUER: 'i1' },
    startedAt: 1,
    lastSeenAt: 1,
    ...extra,
  };
}

/** An in-memory node list, with the calls the helper makes. */
function memoryList(initial: readonly DeploymentNode[] = []) {
  let rows = [...initial];
  const calls: string[] = [];
  const repository: DeploymentNodesRepository = {
    async listLive(windowMs) {
      calls.push(`listLive:${windowMs}`);
      return [...rows];
    },
    async register(node, windowMs, check) {
      calls.push(`register:${windowMs}`);
      check([...rows]);
      const stored = { ...node, startedAt: 10, lastSeenAt: 10 };
      rows.push(stored);
      return stored;
    },
    async heartbeat(node) {
      calls.push('heartbeat');
      if (rows.some((row) => row.nodeId === node.nodeId)) return 'seen';
      rows.push(node);
      return 'restored';
    },
    async remove(nodeId) {
      calls.push('remove');
      rows = rows.filter((row) => row.nodeId !== nodeId);
    },
  };
  return {
    repository,
    calls,
    rows: () => rows,
    set: (next: DeploymentNode[]) => {
      rows = next;
    },
  };
}

function recordingLog() {
  const warnings: { details: Record<string, unknown>; message: string }[] = [];
  const infos: string[] = [];
  return {
    warnings,
    infos,
    log: {
      warn: (details: Record<string, unknown>, message: string) =>
        warnings.push({ details, message }),
      info: (_details: Record<string, unknown>, message: string) => infos.push(message),
    },
  };
}

afterEach(() => {
  vi.useRealTimers();
});

describe('compareWithLiveNodes', () => {
  it('finds nothing among nodes of the release with the same digest, and skips its own row', () => {
    const same = peer({ configDigest: SELF.configDigest, configKeys: SELF.configKeys });
    const own = peer({ nodeId: SELF.nodeId, configKeys: {} });
    expect(compareWithLiveNodes(SELF, [same, own])).toEqual({ mismatched: [], otherReleases: [] });
  });

  it('names the keys a node of the release differs in, and leaves out a key it does not compare', () => {
    const other = peer({ configKeys: { HYBRID_SIGNING_ENABLED: 'h2', JWT_ISSUER: 'i1' } });
    expect(compareWithLiveNodes(SELF, [other])).toEqual({
      mismatched: [
        {
          nodeId: other.nodeId,
          roles: ['web', 'api'],
          version: '0.3.0',
          keys: ['HYBRID_SIGNING_ENABLED'],
        },
      ],
      otherReleases: [],
    });
    // A node without the signer compares no KEK_PROVIDER: only its digest differs.
    expect(compareWithLiveNodes(SELF, [peer()]).mismatched).toEqual([]);
  });

  it('puts a node of another release apart, whether or not it differs', () => {
    const same = peer({ version: '0.2.0', configKeys: SELF.configKeys });
    const differs = peer({ version: '0.4.0', configKeys: { JWT_ISSUER: 'i2' } });
    const { mismatched, otherReleases } = compareWithLiveNodes(SELF, [same, differs]);
    expect(mismatched).toEqual([]);
    expect(otherReleases.map((node) => [node.version, node.keys])).toEqual([
      ['0.2.0', []],
      ['0.4.0', ['JWT_ISSUER']],
    ]);
  });
});

describe('the node list of a booting node', () => {
  it('refuses a node of the release whose settings differ, naming the keys and the node', async () => {
    const other = peer({ configKeys: { HYBRID_SIGNING_ENABLED: 'h2', JWT_ISSUER: 'i2' } });
    const memory = memoryList([other]);
    const { log } = recordingLog();
    const list = createDeploymentNodeList({
      repository: memory.repository,
      log,
      node: SELF,
      rollout: false,
    });

    const refusal = await list.check().catch((error: unknown) => error);
    expect(refusal).toBeInstanceOf(ConfigDigestMismatchError);
    const error = refusal as ConfigDigestMismatchError;
    expect(error.keys).toEqual(['HYBRID_SIGNING_ENABLED', 'JWT_ISSUER']);
    expect(error.message).toContain('in HYBRID_SIGNING_ENABLED, JWT_ISSUER');
    expect(error.message).toContain(`${other.nodeId} (web,api)`);
    expect(error.message).toContain('CONFIG_DIGEST_ROLLOUT=true');
    // The digests are no values, and are not printed either.
    expect(error.message).not.toMatch(/\bh[12]\b|\bi[12]\b/);
    expect(memory.calls).toEqual([`listLive:${DEPLOYMENT_NODE_LIVE_WINDOW_MS}`]);

    // The registration compares again, under the lock, and writes nothing.
    await expect(list.register()).rejects.toBeInstanceOf(ConfigDigestMismatchError);
    expect(memory.rows()).toEqual([other]);
  });

  it('boots with a warning while CONFIG_DIGEST_ROLLOUT is on', async () => {
    const other = peer({ configKeys: { HYBRID_SIGNING_ENABLED: 'h2', JWT_ISSUER: 'i1' } });
    const memory = memoryList([other]);
    const { log, warnings } = recordingLog();
    const list = createDeploymentNodeList({
      repository: memory.repository,
      log,
      node: SELF,
      rollout: true,
    });

    await list.check();
    await list.register();
    expect(warnings).toHaveLength(1);
    expect(warnings[0]?.details).toMatchObject({
      variable: 'CONFIG_DIGEST_ROLLOUT',
      keys: ['HYBRID_SIGNING_ENABLED'],
      nodes: [other.nodeId],
    });
    expect(warnings[0]?.message).toMatch(/^CONFIG_DIGEST_ROLLOUT is on/);
    expect(memory.rows().map((row) => row.nodeId)).toEqual([other.nodeId, SELF.nodeId]);
    await list.stop();
  });

  it('reminds of CONFIG_DIGEST_ROLLOUT when it is on and nothing differs', async () => {
    const { log, warnings } = recordingLog();
    const list = createDeploymentNodeList({
      repository: memoryList().repository,
      log,
      node: SELF,
      rollout: true,
    });
    await list.check();
    expect(warnings.map((warning) => warning.details['variable'])).toEqual([
      'CONFIG_DIGEST_ROLLOUT',
    ]);
  });

  it('only warns of nodes of another release, once per release', async () => {
    const memory = memoryList([
      peer({ version: '0.2.0', configKeys: SELF.configKeys }),
      peer({ version: '0.2.0', configKeys: { JWT_ISSUER: 'i2' } }),
      peer({ version: '0.4.0', configKeys: SELF.configKeys }),
    ]);
    const { log, warnings } = recordingLog();
    const list = createDeploymentNodeList({
      repository: memory.repository,
      log,
      node: SELF,
      rollout: false,
    });
    await list.check();
    await list.register();
    expect(
      warnings.map((warning) => [warning.details['version'], warning.details['keys']])
    ).toEqual([
      ['0.2.0', ['JWT_ISSUER']],
      ['0.4.0', []],
    ]);
    expect(warnings[0]?.message).toMatch(/release 0\.2\.0 run beside this node of release 0\.3\.0/);
    await list.stop();
  });

  it('marks itself seen every 30 seconds once registered, and leaves the list when it stops', async () => {
    vi.useFakeTimers();
    const memory = memoryList();
    const { log, warnings } = recordingLog();
    const list = createDeploymentNodeList({
      repository: memory.repository,
      log,
      node: SELF,
      rollout: false,
    });

    await list.check();
    await list.register();
    await expect(list.assertListed()).resolves.toBeUndefined();
    expect((await list.list()).map((row) => row.nodeId)).toEqual([SELF.nodeId]);

    await vi.advanceTimersByTimeAsync(DEPLOYMENT_NODE_HEARTBEAT_MS);
    expect(memory.calls.filter((call) => call === 'heartbeat')).toHaveLength(1);

    // A row removed while the node could not reach the list is written again.
    memory.set([]);
    await expect(list.assertListed()).rejects.toThrow('not in the node list');
    await vi.advanceTimersByTimeAsync(DEPLOYMENT_NODE_HEARTBEAT_MS);
    expect(memory.rows().map((row) => row.nodeId)).toEqual([SELF.nodeId]);
    expect(warnings.map((warning) => warning.message)).toEqual([
      expect.stringMatching(/missing from the node list/),
    ]);

    await list.stop();
    expect(memory.rows()).toEqual([]);
    await vi.advanceTimersByTimeAsync(DEPLOYMENT_NODE_HEARTBEAT_MS * 3);
    expect(memory.calls.filter((call) => call === 'heartbeat')).toHaveLength(2);
  });

  it('warns once while it cannot mark itself seen, and says when it can again', async () => {
    vi.useFakeTimers();
    const memory = memoryList();
    let down = false;
    const repository: DeploymentNodesRepository = {
      ...memory.repository,
      heartbeat: async (node) => {
        if (down) throw new Error('connection refused');
        return memory.repository.heartbeat(node);
      },
    };
    const { log, warnings, infos } = recordingLog();
    const list = createDeploymentNodeList({ repository, log, node: SELF, rollout: false });
    await list.register();

    down = true;
    await vi.advanceTimersByTimeAsync(DEPLOYMENT_NODE_HEARTBEAT_MS * 3);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]?.message).toMatch(/cannot mark itself seen/);

    down = false;
    await vi.advanceTimersByTimeAsync(DEPLOYMENT_NODE_HEARTBEAT_MS);
    expect(infos).toContain('This node marks itself seen in the node list again');
    await list.stop();
  });

  it('removes nothing when it stops before it registered', async () => {
    const memory = memoryList([peer()]);
    const list = createDeploymentNodeList({
      repository: memory.repository,
      log: recordingLog().log,
      node: SELF,
      rollout: false,
    });
    await list.stop();
    expect(memory.calls).toEqual([]);
    expect(memory.rows()).toHaveLength(1);
  });

  it('never rejects on stop, though the row cannot be removed', async () => {
    const memory = memoryList();
    const { log, warnings } = recordingLog();
    const list = createDeploymentNodeList({
      repository: {
        ...memory.repository,
        remove: async () => {
          throw new Error('database closed');
        },
      },
      log,
      node: SELF,
      rollout: false,
    });
    await list.register();
    await expect(list.stop()).resolves.toBeUndefined();
    expect(warnings[0]?.message).toMatch(/could not remove itself/);
  });
});

describe("the auth server's configuration digest", () => {
  const environment = {
    DATABASE_URL: 'postgresql://qauth@127.0.0.1:5432/qauth',
    JWT_ISSUER: 'https://auth.example.com',
    EMAIL_FROM_ADDRESS: 'no-reply@auth.example.com',
    TRUST_PROXY: '10.0.0.0/8,loopback',
    ID_JAG_TRUSTED_ISSUERS: 'https://idp.example.com',
  };
  const parsed = (extra: Record<string, string> = {}) => ({
    ...envSchema.parse({ ...environment, ...extra }),
    ...jwtEnvSchema.parse({ ...environment, ...extra }),
    ...cryptoEnvSchema.parse({ ...environment, ...extra }),
  });
  const KEYS = [...SERVER_CONFIG_KEYS, ...AUTH_SERVER_KEYS];

  it('builds from the parsed environment, a key left unset equal to its default', () => {
    const unset = configurationDigest(KEYS, parsed(), SERVICE_ROLE_NAMES);
    const explicit = configurationDigest(
      KEYS,
      parsed({ HYBRID_SIGNING_ENABLED: 'false', DEFAULT_REALM_NAME: 'master', PORT: '4000' }),
      SERVICE_ROLE_NAMES
    );
    expect(explicit).toEqual(unset);
    expect(unset.keys).toHaveProperty('JWT_ISSUER');
    expect(unset.keys).toHaveProperty('TRUST_PROXY');
    expect(unset.keys).not.toHaveProperty('DATABASE_URL');
  });

  it('changes with a deployment-wide setting', () => {
    const before = configurationDigest(KEYS, parsed(), SERVICE_ROLE_NAMES);
    const after = configurationDigest(
      KEYS,
      parsed({ JWT_ISSUER: 'https://other.example.com' }),
      SERVICE_ROLE_NAMES
    );
    expect(after.digest).not.toBe(before.digest);
    expect(
      Object.keys(after.keys).filter((name) => after.keys[name] !== before.keys[name])
    ).toEqual(['JWT_ISSUER']);
  });
});
