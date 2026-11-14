import { sql } from 'drizzle-orm';

import type { DbClient } from '../../types';

/**
 * The node list (`deployment_nodes`, ADR-019 Decision 8, #499): every auth
 * server node registers itself once its boot steps succeeded, compares its
 * configuration digest with the nodes already running, marks itself seen
 * every 30 seconds and removes itself when it closes.
 *
 * Every time is the database's clock, in epoch ms, so the nodes' own clocks
 * never decide whether a node is live. The repository reads and writes the
 * list through the functions of migration 0076 alone, since no role's
 * database user holds anything on the table: they set the times, check
 * every value, and mark seen or remove only the rows the caller's own
 * database user registered.
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

/**
 * What a heartbeat found: the node's row (`seen`); none, so it wrote it again
 * (`restored`); or a row another database user registered under the node's
 * id, which it left as it is (`foreign`).
 */
export type DeploymentNodeHeartbeat = 'seen' | 'restored' | 'foreign';

/** The node list repository (#499). */
export interface DeploymentNodesRepository {
  /** The nodes seen within the last `windowMs`, oldest registration first. */
  listLive(windowMs: number, tx?: DbClient): Promise<DeploymentNode[]>;
  /** Whether the node was seen within the last `windowMs`. */
  isLive(nodeId: string, windowMs: number, tx?: DbClient): Promise<boolean>;
  /**
   * Register `node`, in one transaction under {@link DEPLOYMENT_NODES_LOCK_NAME}:
   * hand the live nodes to `check`, then, once `check` returned, remove the
   * rows unseen for `windowMs` (never less than two minutes) and insert the
   * node. A `check` that throws refuses the registration and writes nothing.
   * The lock is waited for 5 seconds at most.
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
  /** Remove the node's row; nothing when it has none, or another database user registered it. */
  remove(nodeId: string, tx?: DbClient): Promise<void>;
}

/** A row of the list's functions, as node-postgres reads it: `bigint` as text. */
type NodeRow = {
  readonly node_id: string;
  readonly roles: string[];
  readonly version: string;
  readonly config_digest: string;
  readonly config_keys: Record<string, string>;
  readonly started_at: string | number;
  readonly last_seen_at: string | number;
};

function nodeOf(row: NodeRow): DeploymentNode {
  return {
    nodeId: row.node_id,
    roles: row.roles,
    version: row.version,
    configDigest: row.config_digest,
    configKeys: row.config_keys,
    startedAt: Number(row.started_at),
    lastSeenAt: Number(row.last_seen_at),
  };
}

/** The window of the list, checked: a positive whole number of ms. */
function windowOf(windowMs: number): number {
  if (!Number.isSafeInteger(windowMs) || windowMs <= 0) {
    throw new RangeError('The window of the node list is a positive whole number of ms');
  }
  return windowMs;
}

/** What the functions take of a node: its id, roles, release and digests. */
function nodeArguments(node: NewDeploymentNode) {
  return sql`${node.nodeId}::uuid, ${sql.param([...node.roles])}::text[], ${node.version}::text,
    ${node.configDigest}::text, ${JSON.stringify(node.configKeys)}::jsonb`;
}

/**
 * Factory for the node list repository (#499).
 *
 * @param defaultDb - The database a call without a transaction runs on.
 */
export function createDeploymentNodesRepository(defaultDb: DbClient): DeploymentNodesRepository {
  async function listLive(windowMs: number, tx?: DbClient): Promise<DeploymentNode[]> {
    const { rows } = await (tx ?? defaultDb).execute<NodeRow>(
      sql`select * from "deployment_nodes_live"(${windowOf(windowMs)}::bigint)`
    );
    return rows.map(nodeOf);
  }

  return {
    listLive,

    async isLive(nodeId, windowMs, tx) {
      const { rows } = await (tx ?? defaultDb).execute(
        sql`select 1 from "deployment_nodes_live"(${windowOf(windowMs)}::bigint) where "node_id" = ${nodeId}::uuid`
      );
      return rows.length > 0;
    },

    async register(node, windowMs, check) {
      const window = windowOf(windowMs);
      return defaultDb.transaction(async (tx) => {
        // A registration that stalls holding the lock, on a node that froze
        // or lost its network mid-transaction, fails the next boots after 5
        // seconds instead of holding them until their own timeout.
        await tx.execute(sql`select set_config('lock_timeout', '5s', true)`);
        await tx.execute(
          sql`select pg_advisory_xact_lock(hashtextextended(${DEPLOYMENT_NODES_LOCK_NAME}, 0))`
        );
        check(await listLive(window, tx));
        const { rows } = await tx.execute<NodeRow>(
          sql`select * from "deployment_nodes_register"(${nodeArguments(node)}, ${window}::bigint)`
        );
        const [stored] = rows;
        if (stored === undefined) throw new Error('The node list stored no row for the node');
        return nodeOf(stored);
      });
    },

    async heartbeat(node, tx) {
      const { rows } = await (tx ?? defaultDb).execute<{ seen: string | null }>(
        sql`select "deployment_nodes_heartbeat"(${nodeArguments(node)}, ${node.startedAt}::bigint) as "seen"`
      );
      const seen = rows[0]?.seen;
      return seen === 'seen' || seen === 'restored' ? seen : 'foreign';
    },

    async remove(nodeId, tx) {
      await (tx ?? defaultDb).execute(sql`select "deployment_nodes_remove"(${nodeId}::uuid)`);
    },
  };
}
