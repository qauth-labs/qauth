/**
 * Real-Postgres integration tests for the key boot step and key creation
 * (issue #485), through the signer plugin's `realmKeysBoot` option: the path a
 * deployment takes at boot, against the migrated schema.
 *
 * A "node" here is a Fastify instance with its own connection pool, so two
 * nodes that boot together contend for the realm's advisory lock for real.
 *
 * Requires Docker; self-skips without it, like the other container suites.
 */
import { createPublicKey, generateKeyPairSync } from 'node:crypto';

import {
  importPrivateSigningKey,
  importPublicSigningJwk,
  type JwsAlgorithm,
  sign,
  verifyWithHeader,
} from '@qauth-labs/core-crypto';
import {
  createDatabase,
  createRealmsRepository,
  type DatabaseInstance,
} from '@qauth-labs/infra-db';
import type { VerificationKey } from '@qauth-labs/server-keys';
import {
  applyQauthMigrations,
  requireDockerOrSkip,
  type StartedPostgres,
  startPostgresContainer,
  truncateDomainTablesStatement,
} from '@qauth-labs/shared-testing';
import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import type { EnvironmentKeySettings } from '../types';
import { signerPlugin } from './fastify-plugin-signer';
import { createRealmKey, keyReplacedWarning, keyVariableWarning } from './realm-keys';

const KEK_ENV = { KEK: Buffer.alloc(32, 0xa1).toString('base64'), NODE_ENV: 'test' };
const REALM = 'master';
const ISSUER = 'https://auth.example.test';
const COOKIE_SECRET = 'an-operator-session-cookie-secret-0123456789';

function pemPair(type: 'ed25519' | 'rsa') {
  const { privateKey, publicKey } =
    type === 'ed25519'
      ? generateKeyPairSync('ed25519')
      : generateKeyPairSync('rsa', { modulusLength: 2048 });
  return {
    privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKey: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
}

const ED25519 = pemPair('ed25519');
const RSA = pemPair('rsa');

/** The key variables of a deployment from before the key store. */
const OLD_VARIABLES: EnvironmentKeySettings = {
  ed25519: {
    privateKey: { value: ED25519.privateKey, variables: ['JWT_PRIVATE_KEY'] },
    publicKey: { value: ED25519.publicKey, variables: ['JWT_PUBLIC_KEY'] },
  },
  rs256: {
    privateKey: { value: RSA.privateKey, variables: ['JWT_RS256_PRIVATE_KEY_PATH'] },
    kid: { value: 'rsa-2026', variables: ['JWT_RS256_KID'] },
  },
  cookieSecret: { value: COOKIE_SECRET, variables: ['SESSION_COOKIE_SECRET'] },
};

/** The public members of a JWK, as the JWKS published them before the key store. */
function publicMembers(jwk: object): Record<string, unknown> {
  const { kty, crv, x, n, e } = jwk as Record<string, unknown>;
  return Object.fromEntries(
    Object.entries({ kty, crv, x, n, e }).filter(([, value]) => value !== undefined)
  );
}

/**
 * Verify `token` against a set of public keys: by its `kid` when the header
 * names one, else by its `alg` alone, which must then pick one key.
 */
async function verifyWithKeys(
  token: string,
  keys: readonly VerificationKey['publicJwk'][]
): Promise<Record<string, unknown>> {
  const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString('utf8')) as {
    alg: JwsAlgorithm;
    kid?: string;
  };
  const candidates = keys.filter(
    (key) => key.alg === header.alg && (header.kid === undefined || key.kid === header.kid)
  );
  expect(candidates).toHaveLength(1);
  const { claims } = await verifyWithHeader(
    token,
    await importPublicSigningJwk(candidates[0], header.alg),
    { algorithms: [header.alg], issuer: ISSUER }
  );
  return claims;
}

interface Node {
  readonly app: FastifyInstance;
  readonly warnings: { variable?: string; msg: string }[];
}

describe('realm key boot integration (real Postgres)', () => {
  let container: StartedPostgres | undefined;
  const databases: DatabaseInstance[] = [];
  let dockerUp = false;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    container = await startPostgresContainer();
    await applyQauthMigrations(container.connectionString);
    for (let node = 0; node < 2; node++) {
      databases.push(createDatabase({ connectionString: container.connectionString }));
    }
  }, 180_000);

  afterAll(async () => {
    await Promise.all(databases.map((database) => database.close()));
    await container?.stop();
  });

  beforeEach(async (testCtx) => {
    if (!dockerUp || databases.length === 0) {
      testCtx.skip();
      return;
    }
    await databases[0].pool.query(truncateDomainTablesStatement());
    await createRealmsRepository(databases[0].db).createWithPrimaryHost(
      { name: REALM, issuer: ISSUER },
      'auth.example.test'
    );
  });

  /** Boot a node with the key step for the default realm. Rejects as `ready()` does. */
  async function boot(
    environmentKeys: EnvironmentKeySettings,
    options: { node?: number; kekEnv?: Record<string, string> } = {}
  ): Promise<Node> {
    const warnings: Node['warnings'] = [];
    const app = Fastify({
      logger: {
        level: 'warn',
        stream: {
          write(line: string) {
            const entry = JSON.parse(line) as { variable?: string; msg: string };
            warnings.push(entry);
          },
        },
      },
    });
    await app.register(signerPlugin, {
      db: databases[options.node ?? 0].db,
      kekEnv: options.kekEnv ?? KEK_ENV,
      enabledSignatureAlgorithms: ['EdDSA'],
      hybridSigning: false,
      realmKeysBoot: { realmName: REALM, environmentKeys },
    });
    try {
      await app.ready();
    } catch (error) {
      await app.close();
      throw error;
    }
    return { app, warnings };
  }

  async function realmId(): Promise<string> {
    const realm = await createRealmsRepository(databases[0].db).findByName(REALM);
    if (realm === undefined) throw new Error('no realm');
    return realm.id;
  }

  async function storedKeys(): Promise<string[]> {
    const { rows } = await databases[0].pool.query<{ purpose: string; algorithm: string }>(
      'SELECT purpose, algorithm FROM realm_keys WHERE realm_id = $1 ORDER BY purpose, algorithm',
      [await realmId()]
    );
    return rows.map((row) => `${row.purpose}/${row.algorithm}`);
  }

  it('stores the old keys; the JWKS has the same public keys, plus a kid on Ed25519', async () => {
    const { app } = await boot(OLD_VARIABLES);

    expect(await storedKeys()).toEqual([
      'cookie_hmac/HS256',
      'data_at_rest/A256GCM',
      'event_signing/EdDSA',
      'token_signing/EdDSA',
      'token_signing/RS256',
    ]);
    const jwks = await app.signer.getJwks('local', await realmId());
    const tokenKeys = jwks.keys.filter((key) => key.kty !== 'OKP' || key.x !== undefined);
    const ed25519 = tokenKeys.find(
      (key) =>
        JSON.stringify(publicMembers(key)) ===
        JSON.stringify(publicMembers(createPublicKey(ED25519.publicKey).export({ format: 'jwk' })))
    );
    const rs256 = tokenKeys.find((key) => key.kty === 'RSA');
    expect(ed25519).toMatchObject({ alg: 'EdDSA', use: 'sig', kid: expect.any(String) });
    expect(publicMembers(rs256 ?? {})).toEqual(
      publicMembers(createPublicKey(RSA.publicKey).export({ format: 'jwk' }))
    );
    expect(rs256).toMatchObject({ kid: 'rsa-2026', alg: 'RS256' });
    await app.close();
  });

  it('verifies a token signed before the upgrade with the stored keys', async () => {
    // What the server issued before the key store: an EdDSA access token with
    // no kid, and an RS256 ID token under JWT_RS256_KID.
    const accessToken = await sign(
      { sub: 'user-1', client_id: 'client-1' },
      await importPrivateSigningKey(ED25519.privateKey, 'EdDSA'),
      'EdDSA',
      { issuer: ISSUER, expiresIn: 300, audience: 'client-1', typ: 'at+jwt' }
    );
    const idToken = await sign(
      { sub: 'user-1' },
      await importPrivateSigningKey(RSA.privateKey, 'RS256'),
      'RS256',
      {
        issuer: ISSUER,
        expiresIn: 300,
        audience: 'client-1',
        typ: 'JWT',
        header: { kid: 'rsa-2026' },
      }
    );

    const { app } = await boot(OLD_VARIABLES);
    // The keys the server verifies its own tokens with after the upgrade. A
    // kid-less token picks the one EdDSA key among them; the realm JWKS also
    // lists the event-signing key, so a relying party that resolves by `alg`
    // alone must try both, as jose does.
    const keys = (
      await app.signer.getVerificationKeys('local', await realmId(), 'token_signing')
    ).map((key) => key.publicJwk);

    expect(await verifyWithKeys(accessToken, keys)).toMatchObject({ sub: 'user-1' });
    expect(await verifyWithKeys(idToken, keys)).toMatchObject({ sub: 'user-1' });
    await app.close();
  });

  it('imports nothing on a second boot with the variables still set, and warns once per variable', async () => {
    const first = await boot(OLD_VARIABLES);
    await first.app.close();
    const { rows: before } = await databases[0].pool.query('SELECT kid FROM realm_keys');

    const second = await boot(OLD_VARIABLES);

    const { rows: after } = await databases[0].pool.query('SELECT kid FROM realm_keys');
    expect(after).toEqual(before);
    const variableWarnings = second.warnings.filter((entry) => entry.variable !== undefined);
    expect(variableWarnings.map((entry) => entry.variable)).toEqual([
      'JWT_PRIVATE_KEY',
      'JWT_PUBLIC_KEY',
      'JWT_RS256_PRIVATE_KEY_PATH',
      'JWT_RS256_KID',
      'SESSION_COOKIE_SECRET',
    ]);
    for (const entry of variableWarnings) {
      const purpose = entry.variable === 'SESSION_COOKIE_SECRET' ? 'cookie_hmac' : 'token_signing';
      expect(entry.msg).toBe(keyVariableWarning(entry.variable ?? '', purpose));
      // The cookie is still signed with its variable (#493); the tokens are
      // signed through the store, which reads a token variable only to
      // replace the stored key (#491).
      expect(entry.msg).toContain(
        purpose === 'cookie_hmac' ? 'keep it set' : 'replaces the stored key'
      );
    }
    await second.app.close();
  });

  it('replaces the stored key when its variable holds a new one; the JWKS drops the old key at once', async () => {
    const first = await boot(OLD_VARIABLES);
    await first.app.close();
    const next = pemPair('ed25519');

    const { app, warnings } = await boot({
      ...OLD_VARIABLES,
      ed25519: { privateKey: { value: next.privateKey, variables: ['JWT_PRIVATE_KEY'] } },
    });

    const { rows } = await databases[0].pool.query<{ status: string }>(
      `SELECT status FROM realm_keys
       WHERE realm_id = $1 AND purpose = 'token_signing' AND algorithm = 'EdDSA'`,
      [await realmId()]
    );
    expect(rows.map((row) => row.status).sort()).toEqual(['active', 'retired']);
    const published = (await app.signer.getJwks('local', await realmId())).keys.map((key) =>
      JSON.stringify(publicMembers(key))
    );
    const publicJwk = (pem: string) =>
      JSON.stringify(publicMembers(createPublicKey(pem).export({ format: 'jwk' })));
    expect(published).toContain(publicJwk(next.publicKey));
    expect(published).not.toContain(publicJwk(ED25519.publicKey));
    expect(warnings).toContainEqual(
      expect.objectContaining({ msg: keyReplacedWarning(['JWT_PRIVATE_KEY'], 'EdDSA') })
    );
    await app.close();
  });

  it('imports once when two nodes boot together', async () => {
    const nodes = await Promise.all([
      boot(OLD_VARIABLES, { node: 0 }),
      boot(OLD_VARIABLES, { node: 1 }),
    ]);

    expect(await storedKeys()).toHaveLength(5);
    await Promise.all(nodes.map(({ app }) => app.close()));
  });

  it('stops the boot when JWT_PUBLIC_KEY is not the public half of the private key', async () => {
    const mismatched: EnvironmentKeySettings = {
      ed25519: {
        privateKey: OLD_VARIABLES.ed25519?.privateKey ?? { value: '', variables: [] },
        publicKey: { value: pemPair('ed25519').publicKey, variables: ['JWT_PUBLIC_KEY'] },
      },
    };

    await expect(boot(mismatched)).rejects.toMatchObject({
      name: 'InvalidConfigurationError',
      message: expect.stringContaining('JWT_PUBLIC_KEY does not match JWT_PRIVATE_KEY'),
    });
    expect(await storedKeys()).toEqual([]);
  });

  it('boots a fresh deployment with generated keys and serves a JWKS with EdDSA and RS256', async () => {
    const { app, warnings } = await boot({});

    expect(await storedKeys()).toEqual([
      'cookie_hmac/HS256',
      'data_at_rest/A256GCM',
      'event_signing/EdDSA',
      'token_signing/EdDSA',
      'token_signing/RS256',
    ]);
    const id = await realmId();
    const jwks = await app.signer.getJwks('local', id);
    // The token keys; the event key is published apart (d-1026-09).
    expect(jwks.keys.map((key) => key.alg).sort()).toEqual(['EdDSA', 'RS256']);
    for (const key of jwks.keys) expect(key.kid).toEqual(expect.any(String));
    // The cookie and data-at-rest keys work.
    const secrets = await app.signer.getCookieSecrets('local', id);
    expect(secrets.current.secret).toHaveLength(32);
    const ciphertext = await app.signer.encrypt('local', {
      realmId: id,
      plaintext: Buffer.from('hello'),
    });
    expect((await app.signer.decrypt('local', { realmId: id, ciphertext })).toString('utf8')).toBe(
      'hello'
    );
    expect(warnings.filter((entry) => entry.variable !== undefined)).toEqual([]);
    await app.close();
  });

  it('stops the boot with a clear message when keys must be imported and no KEK is set', async () => {
    await expect(boot(OLD_VARIABLES, { kekEnv: { NODE_ENV: 'test' } })).rejects.toMatchObject({
      name: 'InvalidConfigurationError',
      message: expect.stringContaining('no KEK is set'),
    });
    expect(await storedKeys()).toEqual([]);
  });

  it('stops the boot when the default realm does not exist', async () => {
    await databases[0].pool.query(truncateDomainTablesStatement());

    await expect(boot({})).rejects.toThrow('The realm "master" does not exist');
  });
});

describe('createRealmKey integration (real Postgres)', () => {
  let container: StartedPostgres | undefined;
  let database: DatabaseInstance | undefined;
  let dockerUp = false;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    container = await startPostgresContainer();
    await applyQauthMigrations(container.connectionString);
    database = createDatabase({ connectionString: container.connectionString });
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
    await createRealmsRepository(database.db).createWithPrimaryHost(
      { name: REALM, issuer: ISSUER },
      'auth.example.test'
    );
  });

  function deps() {
    if (!database) throw new Error('no database');
    return {
      db: database.db,
      kekEnv: KEK_ENV,
      warn: () => undefined,
      enabledSignatureAlgorithms: ['EdDSA'] as const,
      hybridSigning: false,
    };
  }

  it('adds an RS256 signing key to a realm, published with its kid', async () => {
    const [key] = await createRealmKey(deps(), {
      realmName: REALM,
      purpose: 'token_signing',
      algorithm: 'RS256',
    });

    expect(key).toMatchObject({ purpose: 'token_signing', algorithm: 'RS256', status: 'active' });
    expect(key.publicJwk).toMatchObject({ kty: 'RSA', kid: key.kid, alg: 'RS256' });
    expect(key).not.toHaveProperty('material');
  });

  it('refuses a second active key of the same algorithm; a next key is accepted', async () => {
    await createRealmKey(deps(), {
      realmName: REALM,
      purpose: 'token_signing',
      algorithm: 'RS256',
    });

    await expect(
      createRealmKey(deps(), { realmName: REALM, purpose: 'token_signing', algorithm: 'RS256' })
    ).rejects.toMatchObject({ code: 'ACTIVE_KEY_CONFLICT' });
    await expect(
      createRealmKey(deps(), {
        realmName: REALM,
        purpose: 'token_signing',
        algorithm: 'RS256',
        status: 'next',
      })
    ).resolves.toEqual([expect.objectContaining({ status: 'next' })]);
  });

  it('refuses an unknown purpose, an unknown algorithm and an unknown realm', async () => {
    await expect(
      createRealmKey(deps(), { realmName: REALM, purpose: 'nonsense' })
    ).rejects.toMatchObject({ code: 'KEY_CREATION_REFUSED', reason: 'UNKNOWN_PURPOSE' });
    await expect(
      createRealmKey(deps(), { realmName: REALM, purpose: 'token_signing', algorithm: 'HS512' })
    ).rejects.toMatchObject({ code: 'KEY_CREATION_REFUSED' });
    await expect(
      createRealmKey(deps(), { realmName: 'nowhere', purpose: 'token_signing' })
    ).rejects.toThrow('The realm "nowhere" does not exist');
  });
});
