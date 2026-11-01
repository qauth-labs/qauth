import type { FastifyInstance, FastifyPluginOptions } from 'fastify';
import fp from 'fastify-plugin';

import { bootDefaultRealm, type DefaultRealmBootSettings } from '../helpers/default-realm-boot';

/** Options for {@link defaultRealmPlugin}: the settings the boot step reads. */
export interface DefaultRealmPluginOptions extends FastifyPluginOptions, DefaultRealmBootSettings {}

export const DEFAULT_REALM_PLUGIN_NAME = '@qauth-labs/default-realm';

/**
 * The default realm's boot step (ADR-019 Decision 1, issue #484).
 *
 * Runs `bootDefaultRealm` in an `onReady` hook. `listen()` runs `ready()`
 * before it accepts a connection, so the step runs after the migrations, which
 * the migration runner applies before the server starts, and before the server
 * listens. A refusal rejects `ready()`, and `main.ts` exits.
 */
export const defaultRealmPlugin = fp<DefaultRealmPluginOptions>(
  async (fastify: FastifyInstance, options: DefaultRealmPluginOptions) => {
    for (const [decorator, plugin] of [
      ['db', 'database'],
      ['repositories', 'database'],
      ['policyStore', 'realm policy'],
    ]) {
      if (!fastify.hasDecorator(decorator)) {
        throw new Error(
          `The default realm plugin needs \`fastify.${decorator}\`: register the ${plugin} plugin first`
        );
      }
    }

    const settings: DefaultRealmBootSettings = {
      realmName: options.realmName,
      jwtIssuer: options.jwtIssuer,
      endpointHosts: options.endpointHosts,
      ...(options.passkeys === undefined ? {} : { passkeys: options.passkeys }),
      ...(options.seedKeysSet === undefined ? {} : { seedKeysSet: options.seedKeysSet }),
      ...(options.environmentSeeds === undefined
        ? {}
        : { environmentSeeds: options.environmentSeeds }),
    };
    fastify.addHook('onReady', async () => {
      await bootDefaultRealm(
        {
          db: fastify.db,
          realms: fastify.repositories.realms,
          policies: fastify.policyStore,
          log: fastify.log,
        },
        settings
      );
    });
  },
  { name: DEFAULT_REALM_PLUGIN_NAME }
);

export default defaultRealmPlugin;
