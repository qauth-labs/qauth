import type { Stats } from 'node:fs';

import {
  createEgressClient,
  type EgressAllowlist,
  EgressAllowlistError,
  type EgressClient,
  type EgressClientOptions,
  EMPTY_EGRESS_ALLOWLIST,
  loadEgressAllowlist,
} from '@qauth-labs/server-egress';
import type { FastifyInstance, FastifyPluginOptions } from 'fastify';
import fp from 'fastify-plugin';

import packageJson from '../../package.json';

/** Options of {@link egressPlugin}. */
export interface EgressPluginOptions extends FastifyPluginOptions {
  /**
   * `EGRESS_ALLOWLIST_PATH`: the deployment's allowlist file, read once here.
   * Unset, the list is empty and every non-public address is refused.
   */
  allowlistPath?: string;
  /**
   * TEST SUPPORT — builds the client instead of `createEgressClient`: a test
   * passes `createTestEgressClient` to reach a local fixture server. Refused
   * unless `NODE_ENV` is `test`, so no deployment can hand the server a
   * client of its own.
   */
  createClient?: (options: EgressClientOptions) => EgressClient;
}

declare module 'fastify' {
  interface FastifyInstance {
    /**
     * The SSRF-safe egress client (ADR-019 Decision 8, #481), with the
     * deployment allowlist. Every outbound call the server makes for a
     * configuration value or a request goes through it.
     */
    egress: EgressClient;
  }
}

/** Write permission for others. */
const WRITABLE_BY_OTHERS = 0o002;
/** Write permission for the group. */
const WRITABLE_BY_GROUP = 0o020;

/** What {@link allowlistFileProblems} finds wrong with the allowlist file. */
export interface AllowlistFileProblems {
  /** Why the boot is refused, or `undefined`. */
  readonly refusal: string | undefined;
  /** What the server warns about. */
  readonly warnings: readonly string[];
}

/**
 * Judge the allowlist file's owner and mode: whoever can write it decides
 * which private addresses the server reaches for each realm. A file others
 * can write refuses the boot; one its group can write, or that neither root
 * nor the server's own user owns, is warned about.
 *
 * @param stats - the status of the descriptor the file is read through
 * @param processUid - the server's user id; `undefined` where there is none
 */
export function allowlistFileProblems(
  stats: Pick<Stats, 'mode' | 'uid'>,
  processUid: number | undefined
): AllowlistFileProblems {
  const mode = (stats.mode & 0o777).toString(8);
  if ((stats.mode & WRITABLE_BY_OTHERS) !== 0) {
    return {
      refusal: `others can write the file (mode ${mode}); whoever can write it decides which private addresses the server reaches. Restrict it, for example with \`chmod 644\``,
      warnings: [],
    };
  }
  const warnings: string[] = [];
  if ((stats.mode & WRITABLE_BY_GROUP) !== 0) {
    warnings.push(
      'EGRESS_ALLOWLIST_PATH names a file that its group can write; whoever can write it decides which private addresses the server reaches. Restrict it to its owner, for example with `chmod 644`.'
    );
  }
  if (processUid !== undefined && stats.uid !== 0 && stats.uid !== processUid) {
    warnings.push(
      "EGRESS_ALLOWLIST_PATH names a file that neither root nor the server's user owns; its owner decides which private addresses the server reaches."
    );
  }
  return { refusal: undefined, warnings };
}

/** Refuse or warn about the allowlist file, as {@link allowlistFileProblems} finds. */
function checkAllowlistFile(fastify: FastifyInstance, stats: Stats, what: string): void {
  if (process.platform === 'win32') return;
  const { refusal, warnings } = allowlistFileProblems(stats, process.getuid?.());
  if (refusal !== undefined) throw new EgressAllowlistError(`${what}: ${refusal}`);
  for (const warning of warnings) {
    fastify.log.warn(
      { variable: 'EGRESS_ALLOWLIST_PATH', mode: (stats.mode & 0o777).toString(8), uid: stats.uid },
      warning
    );
  }
}

/**
 * The egress client's wiring (issue #481). Reads the allowlist file
 * `EGRESS_ALLOWLIST_PATH` names, once, and decorates `fastify.egress` with
 * the client over it and the server's logger. A file that cannot be read,
 * does not validate or others can write fails the boot, naming the variable,
 * the file and the mistake. The list lives only in that file: not in the
 * database, and no route reads or edits it.
 *
 * @example
 * ```typescript
 * await fastify.register(egressPlugin, { allowlistPath: env.EGRESS_ALLOWLIST_PATH });
 * const res = await fastify.egress.request({
 *   method: 'GET',
 *   url,
 *   purpose: 'cimd',
 *   source: 'client',
 * });
 * ```
 */
export const egressPlugin = fp<EgressPluginOptions>(
  async (fastify: FastifyInstance, options: EgressPluginOptions) => {
    if (options.createClient !== undefined && process.env['NODE_ENV'] !== 'test') {
      throw new Error('egressPlugin: createClient is a test seam and needs NODE_ENV=test');
    }

    let allowlist: EgressAllowlist = EMPTY_EGRESS_ALLOWLIST;
    if (options.allowlistPath !== undefined) {
      allowlist = loadEgressAllowlist(options.allowlistPath, (stats, what) =>
        checkAllowlistFile(fastify, stats, what)
      );
      fastify.log.info(
        { variable: 'EGRESS_ALLOWLIST_PATH', entries: allowlist.entries.length },
        'egress allowlist loaded'
      );
    }

    const create = options.createClient ?? createEgressClient;
    fastify.decorate('egress', create({ logger: fastify.log, allowlist }));
  },
  { name: packageJson.name }
);

/** The plugin's name, for another plugin's fastify-plugin `dependencies`. */
export const EGRESS_PLUGIN_NAME = packageJson.name;

export default egressPlugin;
