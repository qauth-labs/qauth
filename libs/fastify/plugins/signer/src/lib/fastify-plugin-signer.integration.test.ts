/**
 * Real-Postgres integration tests for the signer's wiring (issues #464 and
 * #547).
 *
 * The keys are created through the key factory over the realm keys
 * repository (`createRepositoryKeyStore`), and the plugin's signer reads them
 * back through the repositories (`createRepositorySignerKeyStore`): the path a
 * deployment takes, end to end, against the migrated schema.
 *
 * Requires Docker; self-skips without it, like the other container suites.
 */
import {
  importPublicSigningJwk,
  type JwsAlgorithm,
  verifyWithHeader,
} from '@qauth-labs/core-crypto';
import {
  createDatabase,
  createRealmsRepository,
  type DatabaseInstance,
} from '@qauth-labs/infra-db';
import { SignerKeyNotFoundError, UpstreamClientNotFoundError } from '@qauth-labs/server-keys';
import { createKeyFactory, createLocalKekProvider } from '@qauth-labs/server-keys/custody';
import {
  applyQauthMigrations,
  requireDockerOrSkip,
  type StartedPostgres,
  startPostgresContainer,
  truncateDomainTablesStatement,
} from '@qauth-labs/shared-testing';
import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { signerPlugin } from './fastify-plugin-signer';
import { createRepositoryKeyStore } from './repository-key-stores';

const KEK_ENV = { KEK: Buffer.alloc(32, 0xa1).toString('base64'), NODE_ENV: 'test' };
const CLAIMS = { sub: 'user-1', aud: 'client-1', iat: 1_800_000_000, exp: 1_800_000_300 };

/** The protected header of a compact JWS, unverified. */
function protectedHeader(token: string): { kid?: string; alg?: string } {
  return JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString('utf8'));
}

describe('signer wiring integration (real Postgres)', () => {
  let container: StartedPostgres | undefined;
  let database: DatabaseInstance | undefined;
  let dockerUp = false;
  /** Every statement sent to the pool, in order. */
  const statements: string[] = [];

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    container = await startPostgresContainer();
    await applyQauthMigrations(container.connectionString);
    database = createDatabase({ connectionString: container.connectionString });
    // Count what the repositories send: drizzle calls `query` on the pool.
    const pool = database.pool;
    const query = pool.query.bind(pool) as (...args: unknown[]) => unknown;
    (pool as unknown as { query: (...args: unknown[]) => unknown }).query = (...args) => {
      const [config] = args;
      statements.push(
        typeof config === 'string' ? config : String((config as { text?: string }).text)
      );
      return query(...args);
    };
  }, 180_000);

  afterAll(async () => {
    await database?.close();
    await container?.stop();
  });

  beforeEach(async (testCtx) => {
    if (!dockerUp || !database) {
      testCtx.skip();
      return;
    }
    await database.pool.query(truncateDomainTablesStatement());
    statements.length = 0;
  });

  function db() {
    if (!database) throw new Error('no database');
    return database.db;
  }

  async function seedRealm(host: string): Promise<string> {
    const { realm } = await createRealmsRepository(db()).createWithPrimaryHost(
      { name: host, issuer: `https://${host}` },
      host
    );
    return realm.id;
  }

  function keyFactory() {
    return createKeyFactory({
      store: createRepositoryKeyStore(db()),
      kekProvider: createLocalKekProvider({ env: KEK_ENV, warn: () => undefined }),
      enabledSignatureAlgorithms: ['EdDSA'],
      hybridSigning: false,
    });
  }

  async function provision(realmId: string): Promise<void> {
    await keyFactory().provisionRealmKeys(realmId);
  }

  async function app(refreshIntervalMs?: number): Promise<FastifyInstance> {
    const instance = Fastify({ logger: false });
    await instance.register(signerPlugin, {
      db: db(),
      kekEnv: KEK_ENV,
      enabledSignatureAlgorithms: ['EdDSA'],
      hybridSigning: false,
      ...(refreshIntervalMs !== undefined ? { refreshIntervalMs } : {}),
    });
    await instance.ready();
    return instance;
  }

  it('signs per realm through the repositories, verifiable with the realm JWKS', async () => {
    const realmA = await seedRealm('a.example.test');
    const realmB = await seedRealm('b.example.test');
    await provision(realmA);
    await provision(realmB);
    const server = await app();

    for (const [realmId, issuer] of [
      [realmA, 'https://a.example.test'],
      [realmB, 'https://b.example.test'],
    ]) {
      const token = await server.signer.signJws('local', {
        realmId,
        purpose: 'token_signing',
        typ: 'at+jwt',
        claims: CLAIMS,
      });
      const { kid, alg } = protectedHeader(token);
      const jwk = (await server.signer.getJwks('local', realmId)).keys.find(
        (key) => key.kid === kid
      );
      if (jwk === undefined) throw new Error('kid not published');
      const { claims } = await verifyWithHeader(
        token,
        await importPublicSigningJwk(jwk, alg as JwsAlgorithm),
        { algorithms: [alg as JwsAlgorithm], issuer, currentDate: new Date(1_800_000_000_000) }
      );
      expect(claims['iss']).toBe(issuer);
    }
    await server.close();
  });

  it('runs no query for a signature with a warm cache', async () => {
    const realmId = await seedRealm('a.example.test');
    await provision(realmId);
    const server = await app();
    const request = { realmId, purpose: 'token_signing', typ: 'at+jwt', claims: CLAIMS } as const;
    await server.signer.signJws('local', request);
    statements.length = 0;

    await server.signer.signJws('local', request);
    await server.signer.signJws('local', { ...request, typ: 'JWT' });

    expect(statements).toEqual([]);
    await server.close();
  });

  it('gives a typed error for a realm without keys and writes nothing', async () => {
    const realmId = await seedRealm('a.example.test');
    const server = await app();
    statements.length = 0;

    await expect(
      server.signer.signJws('local', {
        realmId,
        purpose: 'token_signing',
        typ: 'at+jwt',
        claims: CLAIMS,
      })
    ).rejects.toBeInstanceOf(SignerKeyNotFoundError);
    expect(statements.length).toBeGreaterThan(0);
    expect(statements.every((text) => /^\s*select/i.test(text))).toBe(true);
    await server.close();
  });

  describe('scoped keys (#547)', () => {
    /** Every key row and public row of the realm, as `kid` and scope. */
    async function rowsOf(realmId: string) {
      const keys = await database?.pool.query<{ kid: string; scope_id: string | null }>(
        'SELECT kid, scope_id FROM realm_keys WHERE realm_id = $1 ORDER BY created_at, kid',
        [realmId]
      );
      const published = await database?.pool.query<{ kid: string }>(
        'SELECT kid FROM realm_public_keys WHERE realm_id = $1 ORDER BY kid',
        [realmId]
      );
      return { keys: keys?.rows ?? [], published: (published?.rows ?? []).map((row) => row.kid) };
    }

    it("removes a subscription's key rows when the subscription is deleted, in the same transaction", async () => {
      const realmId = await seedRealm('a.example.test');
      await provision(realmId);
      const keys = keyFactory();
      const scope = { realmId, purpose: 'webhook_signing', scopeId: 'sub-1' } as const;
      const [active] = await keys.createKey(scope);
      const [next] = await keys.createKey({ ...scope, status: 'next' });
      const [kept] = await keys.createKey({ ...scope, scopeId: 'sub-2' });
      const server = await app(0);
      const request = { realmId, subscriptionId: 'sub-1', id: 'evt_1', timestamp: 1, body: '{}' };
      expect((await server.signer.signWebhook('delivery', request)).split(' ')).toHaveLength(2);

      // The owner's deletion calls the hook in its own transaction; a
      // failure after it takes the key rows back with it.
      await expect(
        db().transaction(async (tx) => {
          await keys.deleteScopedKeys({ ...scope, tx });
          throw new Error('the subscription delete failed');
        })
      ).rejects.toThrow('the subscription delete failed');
      expect((await rowsOf(realmId)).keys.map((row) => row.kid)).toContain(active.kid);

      const deleted = await db().transaction((tx) => keys.deleteScopedKeys({ ...scope, tx }));

      expect([...deleted].sort()).toEqual([active.kid, next.kid].sort());
      const remaining = (await rowsOf(realmId)).keys;
      expect(remaining.filter((row) => row.scope_id !== null)).toEqual([
        { kid: kept.kid, scope_id: 'sub-2' },
      ]);
      expect(remaining.filter((row) => row.scope_id === null)).toHaveLength(4);
      await expect(server.signer.signWebhook('delivery', request)).rejects.toBeInstanceOf(
        SignerKeyNotFoundError
      );
      await server.close();
    });

    it("removes a provider's keys with their public rows, and its JWKS empties", async () => {
      const realmId = await seedRealm('a.example.test');
      await provision(realmId);
      const keys = keyFactory();
      const scope = { realmId, purpose: 'upstream_client_assertion', scopeId: 'idp-1' } as const;
      const [active] = await keys.createKey(scope);
      const server = await app(0);
      expect(
        (await server.signer.getUpstreamJwks('admin', realmId, 'idp-1')).keys.map((key) => key.kid)
      ).toEqual([active.kid]);
      const publishedBefore = (await rowsOf(realmId)).published;

      await keys.deleteScopedKeys(scope);

      expect((await rowsOf(realmId)).published).toEqual(
        publishedBefore.filter((kid) => kid !== active.kid)
      );
      await expect(server.signer.getUpstreamJwks('admin', realmId, 'idp-1')).resolves.toEqual({
        keys: [],
      });
      await server.close();
    });

    it('signs no client assertion until upstream login supplies the provider configuration', async () => {
      const realmId = await seedRealm('a.example.test');
      await keyFactory().createKey({
        realmId,
        purpose: 'upstream_client_assertion',
        scopeId: 'idp-1',
      });
      const server = await app();

      await expect(
        server.signer.signClientAssertion('api', {
          realmId,
          providerId: 'idp-1',
          audience: 'https://idp.example.test',
          claims: { jti: 'j', exp: 1_800_000_060 },
        })
      ).rejects.toBeInstanceOf(UpstreamClientNotFoundError);
      await server.close();
    });
  });
});
