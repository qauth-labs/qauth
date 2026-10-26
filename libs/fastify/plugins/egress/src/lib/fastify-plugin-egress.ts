import { statSync } from 'node:fs';

import {
  createEgressClient,
  type EgressAllowlist,
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

/** Write permission for group or others. */
const WRITABLE_BY_OTHERS = 0o022;

/**
 * Warn when group or others can write the allowlist file: whoever can write it
 * decides which private addresses the server reaches for each realm.
 */
function warnIfWritableByOthers(fastify: FastifyInstance, path: string): void {
  if (process.platform === 'win32') return;
  const { mode } = statSync(path);
  if ((mode & WRITABLE_BY_OTHERS) !== 0) {
    fastify.log.warn(
      { variable: 'EGRESS_ALLOWLIST_PATH', mode: (mode & 0o777).toString(8) },
      'EGRESS_ALLOWLIST_PATH names a file that group or others can write; whoever can write it decides which private addresses the server reaches. Restrict it to its owner, for example with `chmod 644`.'
    );
  }
}

/**
 * The egress client's wiring (issue #481). Reads the allowlist file
 * `EGRESS_ALLOWLIST_PATH` names, once, and decorates `fastify.egress` with
 * the client over it and the server's logger. A file that cannot be read or
 * does not validate fails the boot, naming the variable, the file and the
 * mistake. The list lives only in that file: not in the database, and no
 * route reads or edits it.
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
      allowlist = loadEgressAllowlist(options.allowlistPath);
      warnIfWritableByOthers(fastify, options.allowlistPath);
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
