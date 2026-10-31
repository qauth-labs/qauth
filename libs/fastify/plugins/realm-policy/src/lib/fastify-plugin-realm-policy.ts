import { DATABASE_PLUGIN_NAME } from '@qauth-labs/fastify-plugin-db';
import type { DbClient, Realm, RealmsRepository } from '@qauth-labs/infra-db';
import {
  createPolicyStore,
  type RealmPolicies,
  type RealmPolicyStore,
  type RealmSecretStore,
} from '@qauth-labs/server-realm-policy';
import type { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';

import packageJson from '../../package.json';
import { createRealmPolicyStorage } from './storage';

/** The plugin's name, for another plugin's `dependencies`. */
export const REALM_POLICY_PLUGIN_NAME = packageJson.name;

/** The policy store as the auth server holds it: realm rows of the realms table. */
export type RealmPolicyStoreOfRealms = RealmPolicyStore<Realm, DbClient>;

declare module 'fastify' {
  interface FastifyInstance {
    /**
     * The realm policies (ADR-019 Decision 10, #516): `ofRealm(row)` for the
     * realm row a flow already loaded, `get`, `update` with the expected
     * counter, and `seedRealms` for the boot step.
     */
    policyStore: RealmPolicyStoreOfRealms;
  }
}

/** Options of {@link realmPolicyPlugin}. */
export interface RealmPolicyPluginOptions {
  /**
   * The policies the environment seeds (`defaultsFromEnv` of the environment
   * the server runs with): what a realm with no policies is filled with, and
   * what a field missing from a stored document reads as. The database
   * plugin's `realmPolicySeeds.policies` gives a new realm the same document.
   */
  readonly seeds: RealmPolicies;
  /**
   * The realms repository the store reads and writes through: the database
   * plugin's `fastify.repositories.realms`, which every service role builds.
   */
  readonly realms: Pick<RealmsRepository, 'findById' | 'listPolicyRecords' | 'writePolicies'>;
  /** Where secret fields are kept (#529). Absent, every write of a secret is refused. */
  readonly secrets?: RealmSecretStore<DbClient>;
}

/**
 * Decorate `fastify.policyStore`: the realm policy store over the realms
 * table. Registered after the database plugin, whose `fastify.db` it writes
 * in.
 *
 * @throws PolicyValidationError at registration when the seeds are not a
 *   valid policy document
 */
export const realmPolicyPlugin = fp(
  async (fastify: FastifyInstance, options: RealmPolicyPluginOptions) => {
    fastify.decorate(
      'policyStore',
      createPolicyStore({
        storage: createRealmPolicyStorage(fastify.db, options.realms),
        seeds: options.seeds,
        ...(options.secrets === undefined ? {} : { secrets: options.secrets }),
      })
    );
  },
  {
    name: REALM_POLICY_PLUGIN_NAME,
    fastify: '5.x',
    dependencies: [DATABASE_PLUGIN_NAME],
  }
);

export default realmPolicyPlugin;
