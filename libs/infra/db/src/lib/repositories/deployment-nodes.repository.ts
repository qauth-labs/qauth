import { asc, eq, gte, lt, sql } from 'drizzle-orm';

import type { DbClient } from '../../types';
import { deploymentNodes } from '../schema/deployment-nodes';
import { EPOCH_MS_NOW } from '../schema/sql-helpers';

/**
 * The node list (`deployment_nodes`, ADR-019 Decision 8, #499): every auth
 * server node registers itself once its boot steps succeeded, compares its
 * configuration digest with the nodes already running, marks itself seen
 * every 30 seconds and removes itself when it closes.
 *
 * Every time is the database's clock, in epoch ms, so the nodes' own clocks
 * never decide whether a node is live.
 */

/**
 * The advisory lock the registrations take: two nodes that boot at once
 * register one after the other, so the second compares with the first.
 */
export const DEPLOYMENT_NODES_LOCK_NAME = 'qauth:deployment-nodes';

/** A node of the list. */
export interface DeploymentNode {
  readonly nodeId: string;
  /** The service roles it runs. */
  readonly roles: readonly string[];
  /** The QAuth release it runs. */
  readonly version: string;
  /** The digest over every compared key. */
  readonly configDigest: string;
  /** The digest of each compared key, by key name. */
  readonly configKeys: Readonly<Record<string, string>>;
  /** When it registered, in epoch ms on the database's clock. */
  readonly startedAt: number;
  /** When it was last seen, in epoch ms on the database's clock. */
  readonly lastSeenAt: number;
}

/** What a node registers: the list sets its times. */
export type NewDeploymentNode = Omit<DeploymentNode, 'startedAt' | 'lastSeenAt'>;

/** What a heartbeat found: the node's row, or none, which it wrote again. */
export type DeploymentNodeHeartbeat = 'seen' | 'restored';

/** The node list repository (#499). */
export interface DeploymentNodesRepository {
  /** The nodes seen within the last `windowMs`, oldest registration first. */
  listLive(windowMs: number, tx?: DbClient): Promise<DeploymentNode[]>;
  /**
   * Register `node`, in one transaction under {@link DEPLOYMENT_NODES_LOCK_NAME}:
   * remove the rows unseen for `windowMs`, hand the live ones to `check`,
   * and insert the node once `check` returned. A `check` that throws refuses
   * the registration and writes nothing.
   *
   * @returns the node as stored, with its times
   */
  register(
    node: NewDeploymentNode,
    windowMs: number,
    check: (live: readonly DeploymentNode[]) => void
  ): Promise<DeploymentNode>;
  /**
   * Mark the node seen now. A node whose row is gone, removed as stale while
   * it could not reach the database or by hand, is written again with its
   * registration time.
   */
  heartbeat(node: DeploymentNode, tx?: DbClient): Promise<DeploymentNodeHeartbeat>;
  /** Remove the node's row; nothing when it has none. */
  remove(nodeId: string, tx?: DbClient): Promise<void>;
}

const COLUMNS = {
  nodeId: deploymentNodes.nodeId,
  roles: deploymentNodes.roles,
  version: deploymentNodes.version,
  configDigest: deploymentNodes.configDigest,
  configKeys: deploymentNodes.configKeys,
  startedAt: deploymentNodes.startedAt,
  lastSeenAt: deploymentNodes.lastSeenAt,
};

/** `now - windowMs` on the database's clock, in epoch ms. */
function seenSince(windowMs: number) {
  if (!Number.isSafeInteger(windowMs) || windowMs <= 0) {
    throw new RangeError('The window of the node list is a positive whole number of ms');
  }
  return sql`(${EPOCH_MS_NOW} - ${windowMs}::bigint)`;
}

/**
 * Factory for the node list repository (#499).
 *
 * @param defaultDb - The database a call without a transaction runs on.
 */
export function createDeploymentNodesRepository(defaultDb: DbClient): DeploymentNodesRepository {
  async function listLive(windowMs: number, tx?: DbClient): Promise<DeploymentNode[]> {
    return (tx ?? defaultDb)
      .select(COLUMNS)
      .from(deploymentNodes)
      .where(gte(deploymentNodes.lastSeenAt, seenSince(windowMs)))
      .orderBy(asc(deploymentNodes.startedAt), asc(deploymentNodes.nodeId));
  }

  return {
    listLive,

    async register(node, windowMs, check) {
      return defaultDb.transaction(async (tx) => {
        await tx.execute(
          sql`select pg_advisory_xact_lock(hashtextextended(${DEPLOYMENT_NODES_LOCK_NAME}, 0))`
        );
        await tx.delete(deploymentNodes).where(lt(deploymentNodes.lastSeenAt, seenSince(windowMs)));
        check(await listLive(windowMs, tx));
        const [stored] = await tx
          .insert(deploymentNodes)
          .values({
            nodeId: node.nodeId,
            roles: [...node.roles],
            version: node.version,
            configDigest: node.configDigest,
            configKeys: { ...node.configKeys },
          })
          .returning(COLUMNS);
        if (stored === undefined) throw new Error('The node list stored no row for the node');
        return stored;
      });
    },

    async heartbeat(node, tx) {
      const [row] = await (tx ?? defaultDb)
        .insert(deploymentNodes)
        .values({
          nodeId: node.nodeId,
          roles: [...node.roles],
          version: node.version,
          configDigest: node.configDigest,
          configKeys: { ...node.configKeys },
          startedAt: node.startedAt,
        })
        .onConflictDoUpdate({ target: deploymentNodes.nodeId, set: { lastSeenAt: EPOCH_MS_NOW } })
        // `xmax` is 0 on a row the statement inserted, and set on one it updated.
        .returning({ inserted: sql<boolean>`(xmax = 0)` });
      return row?.inserted === true ? 'restored' : 'seen';
    },

    async remove(nodeId, tx) {
      await (tx ?? defaultDb).delete(deploymentNodes).where(eq(deploymentNodes.nodeId, nodeId));
    },
  };
}
