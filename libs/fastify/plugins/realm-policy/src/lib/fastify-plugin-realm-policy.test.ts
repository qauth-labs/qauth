import { DATABASE_PLUGIN_NAME } from '@qauth-labs/fastify-plugin-db';
import type { Realm, RealmsRepository } from '@qauth-labs/infra-db';
import { defaultsFromEnv, PolicyValidationError } from '@qauth-labs/server-realm-policy';
import Fastify, { type FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';
import { describe, expect, it, vi } from 'vitest';

import { realmPolicyPlugin } from './fastify-plugin-realm-policy';

const SEEDS = defaultsFromEnv({ ACCESS_TOKEN_LIFESPAN: '600' });

/** A realm row as the realms table returns it, with policies. */
const REALM = {
  id: 'realm-1',
  name: 'master',
  accessTokenLifespan: 300,
  refreshTokenLifespan: 3600,
  dynamicRegistrationAllowedScopes: ['openid'],
  maxEnvironmentLaxity: 'staging',
  policies: { password: { minScore: 4 } },
  policySchemaVersion: '1-rc.0',
  policiesVersion: 5,
} as unknown as Realm;

/** The database plugin's `fastify.db`, as far as the policy store writes in it. */
function fakeDatabasePlugin() {
  return fp(
    async (fastify: FastifyInstance) => {
      fastify.decorate('db', {
        transaction: (work: (tx: unknown) => Promise<unknown>) => work({}),
      } as unknown as FastifyInstance['db']);
    },
    { name: DATABASE_PLUGIN_NAME }
  );
}

/** A realms repository, as far as the policy store reads it. */
function fakeRealms(overrides: Partial<RealmsRepository> = {}): RealmsRepository {
  return overrides as RealmsRepository;
}

describe('realmPolicyPlugin', () => {
  it('decorates fastify.policyStore over the realms repository it is given', async () => {
    const findById = vi.fn(async () => REALM);
    const app = Fastify();
    await app.register(fakeDatabasePlugin());
    await app.register(realmPolicyPlugin, { seeds: SEEDS, realms: fakeRealms({ findById }) });
    await app.ready();

    const snapshot = await app.policyStore.get('realm-1');

    expect(findById).toHaveBeenCalledWith('realm-1', undefined);
    expect(snapshot).toMatchObject({ version: 5, hasPolicies: true });
    expect(snapshot?.policies.tokens.accessTokenLifespanSeconds).toBe(300);
    expect(snapshot?.policies.password.minScore).toBe(4);
    expect(snapshot?.policies.posture.maxEnvironmentLaxity).toBe('staging');
    expect(snapshot?.policies.mail).toEqual(SEEDS.mail);
    await app.close();
  });

  it('reads a realm row a flow already loaded with no query', async () => {
    const findById = vi.fn();
    const app = Fastify();
    await app.register(fakeDatabasePlugin());
    await app.register(realmPolicyPlugin, { seeds: SEEDS, realms: fakeRealms({ findById }) });
    await app.ready();

    expect(app.policyStore.ofRealm(REALM).version).toBe(5);
    expect(findById).not.toHaveBeenCalled();
    await app.close();
  });

  it('refuses seeds the policy schema refuses, at registration', async () => {
    const app = Fastify();
    await app.register(fakeDatabasePlugin());

    await expect(
      app.register(realmPolicyPlugin, {
        seeds: { ...SEEDS, password: { minScore: 9 } } as typeof SEEDS,
        realms: fakeRealms(),
      })
    ).rejects.toBeInstanceOf(PolicyValidationError);
    await app.close();
  });

  it('needs the database plugin', async () => {
    const app = Fastify();

    await expect(
      (async () => {
        await app.register(realmPolicyPlugin, { seeds: SEEDS, realms: fakeRealms() });
        await app.ready();
      })()
    ).rejects.toThrow(DATABASE_PLUGIN_NAME);
    await app.close();
  });
});
