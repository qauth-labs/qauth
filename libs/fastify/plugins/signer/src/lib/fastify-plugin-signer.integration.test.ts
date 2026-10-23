/**
 * Real-Postgres integration tests for the signer's wiring (issue #464).
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
import { SignerKeyNotFoundError } from '@qauth-labs/server-keys';
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

  async function provision(realmId: string): Promise<void> {
    await createKeyFactory({
      store: createRepositoryKeyStore(db()),
      kekProvider: createLocalKekProvider({ env: KEK_ENV, warn: () => undefined }),
      enabledSignatureAlgorithms: ['EdDSA'],
      hybridSigning: false,
    }).provisionRealmKeys(realmId);
  }

  async function app(): Promise<FastifyInstance> {
    const instance = Fastify({ logger: false });
    await instance.register(signerPlugin, {
      db: db(),
      kekEnv: KEK_ENV,
      enabledSignatureAlgorithms: ['EdDSA'],
      hybridSigning: false,
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
});
