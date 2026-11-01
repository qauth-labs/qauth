import { DATABASE_PLUGIN_NAME } from '@qauth-labs/fastify-plugin-db';
import { type Realm, realmPolicyRecord, type RealmsRepository } from '@qauth-labs/infra-db';
import {
  defaultsFromEnv,
  PolicySecretStoreUnavailableError,
  PolicyValidationError,
} from '@qauth-labs/server-realm-policy';
import Fastify, { type FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';
import { describe, expect, it, vi } from 'vitest';

import { createRealmSecretStoreOfRealms, realmPolicyPlugin } from './fastify-plugin-realm-policy';

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

  it('has no secret store unless given one, and then refuses every write of a secret', async () => {
    const app = Fastify();
    await app.register(fakeDatabasePlugin());
    await app.register(realmPolicyPlugin, { seeds: SEEDS, realms: fakeRealms() });
    await app.ready();

    expect(app.realmSecretStore).toBeNull();
    await expect(
      app.policyStore.update(
        'realm-1',
        { mail: { smtp: { password: 'a-password' } } },
        { expectedVersion: 5 }
      )
    ).rejects.toBeInstanceOf(PolicySecretStoreUnavailableError);
    await app.close();
  });

  it('takes the secret store built over a repository and cipher, and decorates no reader of a value (#529)', async () => {
    const PASSWORD = 'the-smtp-password';
    const rows = new Map<string, { ciphertext: string | null; keyId: string | null }>();
    const repository = {
      find: vi.fn(async (realmId: string, name: string) => {
        const row = rows.get(`${realmId} ${name}`);
        return row === undefined ? undefined : { realmId, name, updatedAt: 0, ...row };
      }),
      write: vi.fn(
        async (
          realmId: string,
          name: string,
          value: { ciphertext: string; keyId: string } | null
        ) => {
          rows.set(`${realmId} ${name}`, value ?? { ciphertext: null, keyId: null });
        }
      ),
      insertIfAbsent: vi.fn(async () => true),
    };
    const cipher = {
      encrypt: vi.fn(async () => `v1.kid-7.${'A'.repeat(16)}.${'B'.repeat(30)}`),
      decrypt: vi.fn(async () => PASSWORD),
    };
    const lockPolicyRecord = vi.fn(async () => realmPolicyRecord(REALM));
    const writePolicies = vi.fn(async () => ({ ...REALM, policiesVersion: 6 }) as Realm);
    const secrets = createRealmSecretStoreOfRealms({ repository, cipher });
    const app = Fastify();
    await app.register(fakeDatabasePlugin());
    await app.register(realmPolicyPlugin, {
      seeds: SEEDS,
      realms: fakeRealms({ lockPolicyRecord, writePolicies }),
      secrets,
    });
    await app.ready();

    await app.policyStore.update(
      'realm-1',
      { mail: { smtp: { password: PASSWORD } } },
      { expectedVersion: 5 }
    );

    expect(cipher.encrypt).toHaveBeenCalledWith({
      realmId: 'realm-1',
      plaintext: PASSWORD,
      context: 'realm_secrets:mail.smtp.password',
    });
    expect(repository.write).toHaveBeenCalledWith(
      'realm-1',
      'mail.smtp.password',
      { ciphertext: `v1.kid-7.${'A'.repeat(16)}.${'B'.repeat(30)}`, keyId: 'kid-7' },
      expect.anything()
    );
    expect(JSON.stringify(writePolicies.mock.calls)).not.toContain(PASSWORD);
    expect(await app.realmSecretStore?.isSet('realm-1', 'mail.smtp.password')).toBe(true);
    // A value is read only through the store the caller kept, for the mail
    // sender: the decorator any plugin can reach has no reader.
    expect(Object.keys(app.realmSecretStore ?? {}).sort()).toEqual(['isSet', 'seed']);
    expect(app.realmSecretStore).not.toHaveProperty('getForUse');
    expect(await secrets.getForUse('realm-1', 'mail.smtp.password')).toBe(PASSWORD);
    await app.close();
  });
});
