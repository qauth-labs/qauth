import type {
  DeploymentNode,
  DeploymentNodesRepository,
  NewDeploymentNode,
} from '@qauth-labs/fastify-plugin-db';
import { differingKeys } from '@qauth-labs/server-config';

/**
 * THE NODE LIST AND THE CONFIGURATION DIGEST CHECK (ADR-019 Decision 8,
 * issue #499).
 *
 * Every node fingerprints its deployment-wide settings at boot: the
 * configuration digest, built from the keys the configuration key registry
 * classes `shared` (`configurationDigest` in `@qauth-labs/server-config`).
 * It compares the digest with every node of the list seen in the last two
 * minutes:
 *
 * - a node of the same release whose digest differs in a key both compare
 *   stops the boot, naming the keys, never their values, unless
 *   `CONFIG_DIGEST_ROLLOUT` is on, which turns the refusal into a warning for
 *   the window of a planned settings change;
 * - a node of another release, as during a rolling upgrade, is only warned
 *   of, with the keys that differ if any.
 *
 * The comparison runs twice. Once read-only, before any other boot step
 * writes to the database: a node with another `DEFAULT_REALM_NAME` must not
 * create a realm before it refuses a running node. And once more when the
 * node registers, after every boot step succeeded, in one transaction under
 * the list's lock that also inserts the row: two nodes that boot at once
 * register one after the other, so the second compares with the first and
 * refuses then, though its boot steps have already run; and a node whose
 * boot steps fail leaves no row behind to block the next attempt.
 *
 * Once registered, the node marks itself seen every 30 seconds, and removes
 * its row when it closes. A row that is gone, removed as stale while the
 * node could not reach the database, is written again and compared once
 * more: when a node of the release that registered meanwhile differs, the
 * node logs an error and stays unready (`config_digest`) until it restarts.
 * A node that stops without closing leaves a row that stops counting two
 * minutes later; the next registration removes it. The list is the readiness
 * check `config_digest`, and the admin console's role health will read it.
 */

/** How often a node marks itself seen. */
export const DEPLOYMENT_NODE_HEARTBEAT_MS = 30_000;

/** How long a node counts as running after it was last seen. */
export const DEPLOYMENT_NODE_LIVE_WINDOW_MS = 120_000;

/** A running node the digest check names: by id, roles and release, never by a value. */
export interface ComparedNode {
  readonly nodeId: string;
  readonly roles: readonly string[];
  readonly version: string;
  /** The keys whose digests differ from this node's, sorted. */
  readonly keys: readonly string[];
}

/** What the comparison with the running nodes found. */
export interface NodeComparison {
  /** The nodes of this node's release whose digests differ from its own. */
  readonly mismatched: readonly ComparedNode[];
  /** The nodes of other releases, whether or not their digests differ. */
  readonly otherReleases: readonly ComparedNode[];
}

/**
 * Compare `self` with the `live` nodes, leaving out its own row: a node of
 * the same release counts when a key both compare has another digest; one of
 * another release always counts.
 */
export function compareWithLiveNodes(
  self: NewDeploymentNode,
  live: readonly DeploymentNode[]
): NodeComparison {
  const mismatched: ComparedNode[] = [];
  const otherReleases: ComparedNode[] = [];
  for (const peer of live) {
    if (peer.nodeId === self.nodeId) continue;
    const keys =
      peer.configDigest === self.configDigest
        ? []
        : differingKeys(self.configKeys, peer.configKeys);
    const compared = { nodeId: peer.nodeId, roles: peer.roles, version: peer.version, keys };
    if (peer.version !== self.version) otherReleases.push(compared);
    else if (keys.length > 0) mismatched.push(compared);
  }
  return { mismatched, otherReleases };
}

/** The keys any of `nodes` differs in, sorted, each once. */
function keysOf(nodes: readonly ComparedNode[]): string[] {
  return [...new Set(nodes.flatMap((node) => node.keys))].sort();
}

/** `nodes` as the log and the refusal name them: id and roles. */
function describeNodes(nodes: readonly ComparedNode[]): string {
  return nodes.map((node) => `${node.nodeId} (${node.roles.join(',')})`).join(', ');
}

/**
 * A boot refused because its configuration digest differs from a running
 * node's of the same release. The message and {@link keys} name the keys,
 * never a value.
 */
export class ConfigDigestMismatchError extends Error {
  readonly keys: readonly string[];
  readonly nodes: readonly ComparedNode[];

  constructor(version: string, nodes: readonly ComparedNode[]) {
    const keys = keysOf(nodes);
    const count = nodes.length === 1 ? 'a running node' : `${nodes.length} running nodes`;
    super(
      `The configuration of this node differs from ${count} of release ${version} in ${keys.join(', ')}: give every node the same value of ${keys.length === 1 ? 'this key' : 'these keys'}, or, for the window of a planned change, set CONFIG_DIGEST_ROLLOUT=true on the nodes that start with the new value (running: ${describeNodes(nodes)})`
    );
    this.name = 'ConfigDigestMismatchError';
    this.keys = keys;
    this.nodes = nodes;
  }
}

/** Where the node list logs: the app's logger. */
export interface DeploymentNodeLog {
  error(details: Record<string, unknown>, message: string): void;
  warn(details: Record<string, unknown>, message: string): void;
  info(details: Record<string, unknown>, message: string): void;
}

/** What {@link createDeploymentNodeList} needs. */
export interface DeploymentNodeListOptions {
  /** The node list's storage: `fastify.repositories.deploymentNodes`. */
  readonly repository: DeploymentNodesRepository;
  readonly log: DeploymentNodeLog;
  /** This node: a fresh id, its roles, its release and its configuration digest. */
  readonly node: NewDeploymentNode;
  /** `CONFIG_DIGEST_ROLLOUT`: a mismatch is a warning, not a refusal. */
  readonly rollout: boolean;
  /** How often the node marks itself seen; {@link DEPLOYMENT_NODE_HEARTBEAT_MS} when unset. */
  readonly heartbeatMs?: number;
}

/** This node's view of the node list: `fastify.deploymentNodes`. */
export interface DeploymentNodeList {
  /** This node's id in the list, new at each boot. */
  readonly nodeId: string;
  /**
   * Compare with the running nodes, writing nothing: log what only warns,
   * and refuse a mismatch with a node of the same release.
   *
   * @throws ConfigDigestMismatchError unless the rollout switch is on
   */
  check(): Promise<void>;
  /**
   * Compare once more and register this node, in one transaction, then mark
   * it seen every 30 seconds until {@link stop}.
   *
   * @throws ConfigDigestMismatchError unless the rollout switch is on
   */
  register(): Promise<void>;
  /** The nodes seen in the last two minutes, this one too once registered. */
  list(): Promise<readonly DeploymentNode[]>;
  /**
   * Resolve while this node is in the list, so that a booting node compares
   * its settings with this one's; reject when it is not, or when it was
   * listed again beside a node of its release whose settings differ. The
   * readiness check `config_digest`.
   */
  assertListed(): Promise<void>;
  /** Stop marking this node seen and remove its row. Never rejects. */
  stop(): Promise<void>;
}

/** A short, bounded description of what a call threw, for the log. */
function describeError(error: unknown): { name: string; message: string } {
  if (error instanceof Error) return { name: error.name, message: error.message.slice(0, 512) };
  return { name: typeof error, message: String(error).slice(0, 512) };
}

/** Build this node's view of the node list (#499). It reads nothing until called. */
export function createDeploymentNodeList(options: DeploymentNodeListOptions): DeploymentNodeList {
  const { repository, log, node, rollout } = options;
  const heartbeatMs = options.heartbeatMs ?? DEPLOYMENT_NODE_HEARTBEAT_MS;
  let stored: DeploymentNode | undefined;
  let timer: NodeJS.Timeout | undefined;
  let beating: Promise<void> | undefined;
  let failing = false;
  let stopped = false;
  /** The keys a node of the release differs in, found when the row was written again. */
  let conflict: readonly string[] | undefined;
  // A comparison owed since the row was written again, until one succeeds: a
  // failed list leaves it owed, and the next heartbeats try it again.
  let recheckPending = false;
  let recheckFailing = false;

  /**
   * Refuse a mismatch with a node of this release, or with the rollout
   * switch on, warn of it where `warn` says to: the read-only check warns,
   * and the registration that repeats it does not again.
   */
  function judge(comparison: NodeComparison, warn: boolean): void {
    if (comparison.mismatched.length === 0) return;
    if (!rollout) throw new ConfigDigestMismatchError(node.version, comparison.mismatched);
    if (!warn) return;
    log.warn(
      {
        variable: 'CONFIG_DIGEST_ROLLOUT',
        keys: keysOf(comparison.mismatched),
        nodes: comparison.mismatched.map((peer) => peer.nodeId),
        version: node.version,
      },
      `CONFIG_DIGEST_ROLLOUT is on, so this node boots although its configuration differs from running nodes of release ${node.version} in ${keysOf(comparison.mismatched).join(', ')}; turn it off once every node runs the same values`
    );
  }

  /** Warn of the nodes of other releases, once per release. */
  function warnOfOtherReleases(comparison: NodeComparison): void {
    const releases = new Map<string, ComparedNode[]>();
    for (const peer of comparison.otherReleases) {
      releases.set(peer.version, [...(releases.get(peer.version) ?? []), peer]);
    }
    for (const [version, peers] of releases) {
      const keys = keysOf(peers);
      log.warn(
        { version, ownVersion: node.version, keys, nodes: peers.map((peer) => peer.nodeId) },
        `Nodes of release ${version} run beside this node of release ${node.version}, as during a rolling upgrade: their configuration is not enforced on this node${keys.length === 0 ? ', and does not differ from it' : `, and differs from it in ${keys.join(', ')}`}`
      );
    }
  }

  /**
   * Compare once more with the running nodes, once the row was written again
   * after it was removed as stale: a node of the release may have registered
   * meanwhile with other settings, without this one to compare with.
   */
  async function recheck(): Promise<void> {
    const comparison = compareWithLiveNodes(
      node,
      await repository.listLive(DEPLOYMENT_NODE_LIVE_WINDOW_MS)
    );
    if (comparison.mismatched.length === 0 || rollout) {
      conflict = undefined;
      return;
    }
    conflict = keysOf(comparison.mismatched);
    log.error(
      {
        nodeId: node.nodeId,
        keys: conflict,
        nodes: comparison.mismatched.map((peer) => peer.nodeId),
        version: node.version,
      },
      `This node is listed again after it could not mark itself seen, and its configuration differs from running nodes of release ${node.version} that registered meanwhile in ${conflict.join(', ')}: the config_digest readiness check fails until it restarts with the same values`
    );
  }

  async function heartbeat(): Promise<void> {
    if (stored === undefined || stopped) return;
    try {
      const result = await repository.heartbeat(stored);
      if (result === 'foreign') {
        throw new Error("Another database user's node holds this node's id in the node list");
      }
      if (result === 'restored') {
        log.warn(
          { nodeId: node.nodeId },
          'This node was missing from the node list, removed while it could not mark itself seen, and is listed again'
        );
        recheckPending = true;
      } else if (failing) {
        log.info({ nodeId: node.nodeId }, 'This node marks itself seen in the node list again');
      }
      failing = false;
    } catch (error) {
      if (!failing) {
        log.warn(
          { nodeId: node.nodeId, err: describeError(error) },
          'This node cannot mark itself seen in the node list: two minutes after its last sighting, a booting node no longer compares its configuration with this one, and the config_digest readiness check fails'
        );
      }
      failing = true;
      return;
    }
    if (!recheckPending) return;
    try {
      await recheck();
      recheckPending = false;
      recheckFailing = false;
    } catch (error) {
      if (!recheckFailing) {
        log.warn(
          { nodeId: node.nodeId, err: describeError(error) },
          'This node is listed again but cannot compare its configuration with the running nodes: the config_digest readiness check fails until a later heartbeat compares'
        );
      }
      recheckFailing = true;
    }
  }

  return Object.freeze({
    nodeId: node.nodeId,

    async check(): Promise<void> {
      const comparison = compareWithLiveNodes(
        node,
        await repository.listLive(DEPLOYMENT_NODE_LIVE_WINDOW_MS)
      );
      judge(comparison, true);
      warnOfOtherReleases(comparison);
      if (rollout && comparison.mismatched.length === 0) {
        log.warn(
          { variable: 'CONFIG_DIGEST_ROLLOUT' },
          'CONFIG_DIGEST_ROLLOUT is on: turn it off once the planned settings change is over, so that a node whose configuration differs from the running nodes refuses to boot again'
        );
      }
    },

    async register(): Promise<void> {
      if (stored !== undefined) throw new Error('This node is already in the node list');
      stored = await repository.register(node, DEPLOYMENT_NODE_LIVE_WINDOW_MS, (live) =>
        judge(compareWithLiveNodes(node, live), false)
      );
      log.info(
        {
          nodeId: node.nodeId,
          roles: node.roles,
          version: node.version,
          configDigest: node.configDigest,
        },
        'This node is in the node list'
      );
      timer = setInterval(() => {
        // One heartbeat at a time: a slow database never stacks them up.
        beating ??= heartbeat().finally(() => {
          beating = undefined;
        });
      }, heartbeatMs);
      timer.unref();
    },

    list(): Promise<readonly DeploymentNode[]> {
      return repository.listLive(DEPLOYMENT_NODE_LIVE_WINDOW_MS);
    },

    async assertListed(): Promise<void> {
      if (conflict !== undefined) {
        throw new Error(
          `This node's configuration differs from a running node of its release in ${conflict.join(', ')}`
        );
      }
      if (recheckPending) {
        throw new Error(
          'This node has not compared its configuration with the running nodes since its row was written again'
        );
      }
      if (!(await repository.isLive(node.nodeId, DEPLOYMENT_NODE_LIVE_WINDOW_MS))) {
        throw new Error('This node is not in the node list');
      }
    },

    async stop(): Promise<void> {
      stopped = true;
      clearInterval(timer);
      await beating;
      if (stored === undefined) return;
      try {
        await repository.remove(node.nodeId);
      } catch (error) {
        log.warn(
          { nodeId: node.nodeId, err: describeError(error) },
          'This node could not remove itself from the node list: its row stops counting two minutes after its last sighting'
        );
      }
    },
  });
}
