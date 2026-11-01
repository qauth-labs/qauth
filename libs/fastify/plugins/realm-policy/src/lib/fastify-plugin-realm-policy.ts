import { DATABASE_PLUGIN_NAME } from '@qauth-labs/fastify-plugin-db';
import type {
  DbClient,
  Realm,
  RealmSecretsRepository,
  RealmsRepository,
} from '@qauth-labs/infra-db';
import {
  createPolicyStore,
  createRealmSecretStore,
  type RealmPolicies,
  type RealmPolicyStore,
  type RealmSecretCipher,
  type RealmSecretStoreWithSeed,
} from '@qauth-labs/server-realm-policy';
import type { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';

import packageJson from '../../package.json';
import { createRealmSecretStorage } from './secret-storage';
import { createRealmPolicyStorage } from './storage';

/** The plugin's name, for another plugin's `dependencies`. */
export const REALM_POLICY_PLUGIN_NAME = packageJson.name;

/** The policy store as the auth server holds it: realm rows of the realms table. */
export type RealmPolicyStoreOfRealms = RealmPolicyStore<Realm, DbClient>;

/**
 * The realm secret store as the auth server's decorator holds it, over
 * `realm_secrets` (#529): whether a secret is set, and the boot's seed.
 * Writing a secret is the policy update's alone (`put` is not here): it runs
 * the rules and raises the policy counter in the same transaction, which is
 * what tells every node's mail sender to read the secret again. Reading a
 * value is not here either: only the mail sender holds a
 * {@link RealmSecretReader}, handed to it where it is registered.
 */
export type RealmSecretStoreOfRealms = Pick<RealmSecretStoreWithSeed<DbClient>, 'isSet' | 'seed'>;

/** The one reader of a realm secret's value (#529): the realm's mail sender. */
export type RealmSecretReader = Pick<RealmSecretStoreWithSeed<DbClient>, 'getForUse'>;

/** The realm secret store over `realm_secrets`, whole: what {@link createRealmSecretStoreOfRealms} gives. */
export type FullRealmSecretStoreOfRealms = RealmSecretStoreWithSeed<DbClient>;

declare module 'fastify' {
  interface FastifyInstance {
    /**
     * The realm policies (ADR-019 Decision 10, #516): `ofRealm(row)` for the
     * realm row a flow already loaded, `get`, `update` with the expected
     * counter, and `seedRealms` for the boot step.
     */
    policyStore: RealmPolicyStoreOfRealms;
    /**
     * The realm secret store (#529): whether a realm's secret policy field
     * holds a value, and the boot's seed. No value is read through it: the
     * realm's mail sender alone holds the reader. `null` in a process that
     * was given none, where the policy store refuses every write of a secret.
     */
    realmSecretStore: RealmSecretStoreOfRealms | null;
  }
}

/** What the realm secret store is built from (#529). */
export interface RealmSecretStoreSettings {
  /** The database plugin's `fastify.repositories.realmSecrets`. */
  readonly repository: Pick<RealmSecretsRepository, 'find' | 'write' | 'insertIfAbsent'>;
  /** The signer's data-at-rest operations, under the role of the component that calls. */
  readonly cipher: RealmSecretCipher;
}

/**
 * Build the realm secret store over `realm_secrets` (#529). The caller passes
 * it to {@link realmPolicyPlugin}, which decorates only `isSet` and `seed`,
 * and hands its `getForUse` to the realm's mail sender alone.
 */
export function createRealmSecretStoreOfRealms(
  settings: RealmSecretStoreSettings
): FullRealmSecretStoreOfRealms {
  return createRealmSecretStore<DbClient>({
    storage: createRealmSecretStorage(settings.repository),
    cipher: settings.cipher,
  });
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
  readonly realms: Pick<
    RealmsRepository,
    'findById' | 'listPolicyRecords' | 'lockPolicyRecord' | 'writePolicies'
  >;
  /**
   * The realm secret store (#529), from
   * {@link createRealmSecretStoreOfRealms}. Absent, the process has no secret
   * store (`fastify.realmSecretStore` is `null`) and the policy store refuses
   * every write of a secret.
   */
  readonly secrets?: FullRealmSecretStoreOfRealms;
}

/**
 * Decorate `fastify.policyStore`: the realm policy store over the realms
 * table, and `fastify.realmSecretStore`, the store of the realms' secret
 * values that the policy store hands every secret a write sets or clears.
 * Registered after the database plugin, whose `fastify.db` it writes in.
 *
 * @throws PolicyValidationError at registration when the seeds are not a
 *   valid policy document
 */
export const realmPolicyPlugin = fp(
  async (fastify: FastifyInstance, options: RealmPolicyPluginOptions) => {
    const secrets = options.secrets ?? null;
    fastify.decorate(
      'realmSecretStore',
      secrets === null ? null : Object.freeze({ isSet: secrets.isSet, seed: secrets.seed })
    );
    fastify.decorate(
      'policyStore',
      createPolicyStore({
        storage: createRealmPolicyStorage(fastify.db, options.realms),
        seeds: options.seeds,
        ...(secrets === null ? {} : { secrets }),
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
