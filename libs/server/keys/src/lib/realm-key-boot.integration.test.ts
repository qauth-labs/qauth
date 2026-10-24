/**
 * Real-Postgres integration tests for the realm key boot step (issue #485).
 *
 * The step runs against the migrated schema of `realm_keys` and
 * `realm_public_keys`, under the transaction-level advisory lock the realm
 * keys repository takes, so two nodes that boot together really contend for
 * it. Every stored byte string and text column is searched for the imported
 * private keys.
 *
 * Requires Docker; self-skips without it, like the other container suites.
 */
import { createPrivateKey, createPublicKey, generateKeyPairSync } from 'node:crypto';

import {
  applyQauthMigrations,
  requireDockerOrSkip,
  type StartedPostgres,
  startPostgresContainer,
  truncateDomainTablesStatement,
} from '@qauth-labs/shared-testing';
import { Pool } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { KEK_A, localProvider } from '../testing/keks';
import { createPgKeyStore } from '../testing/pg-key-store';
import type { EnvironmentKeySettings } from './environment-keys';
import { bootRealmKeys, type RealmKeysBootResult } from './realm-key-boot';

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

const UPGRADE: EnvironmentKeySettings = {
  ed25519: {
    privateKey: { value: ED25519.privateKey, variables: ['JWT_PRIVATE_KEY'] },
    publicKey: { value: ED25519.publicKey, variables: ['JWT_PUBLIC_KEY'] },
  },
  rs256: { privateKey: { value: RSA.privateKey, variables: ['JWT_RS256_PRIVATE_KEY'] } },
  cookieSecret: { value: COOKIE_SECRET, variables: ['SESSION_COOKIE_SECRET'] },
};

interface KeyRow {
  readonly purpose: string;
  readonly algorithm: string;
  readonly kid: string;
  readonly status: string;
  readonly [column: string]: unknown;
}

describe('realm key boot integration (real Postgres)', () => {
  let container: StartedPostgres | undefined;
  let pools: Pool[] = [];
  let dockerUp = false;
  const kekProvider = localProvider({ KEK: KEK_A });

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    container = await startPostgresContainer();
    await applyQauthMigrations(container.connectionString);
    // One pool per node: two nodes never share a connection.
    pools = [0, 1].map(() => new Pool({ connectionString: container?.connectionString }));
  }, 180_000);

  afterAll(async () => {
    await Promise.all(pools.map((pool) => pool.end()));
    await container?.stop();
  });

  beforeEach(async (testCtx) => {
    if (!dockerUp || pools.length === 0) {
      testCtx.skip();
      return;
    }
    await pools[0].query(truncateDomainTablesStatement());
  });

  async function seedRealm(): Promise<string> {
    const { rows } = await pools[0].query<{ id: string }>(
      'INSERT INTO realms (name) VALUES ($1) RETURNING id',
      [`realm-${Math.random().toString(36).slice(2)}`]
    );
    return rows[0].id;
  }

  function bootOn(
    node: number,
    realmId: string,
    environmentKeys?: EnvironmentKeySettings
  ): Promise<RealmKeysBootResult> {
    return bootRealmKeys({
      store: createPgKeyStore(pools[node]),
      kekProvider,
      enabledSignatureAlgorithms: ['EdDSA'],
      hybridSigning: false,
      realmId,
      ...(environmentKeys === undefined ? {} : { environmentKeys }),
    });
  }

  async function keyRows(realmId: string): Promise<KeyRow[]> {
    const { rows } = await pools[0].query<KeyRow>(
      'SELECT * FROM realm_keys WHERE realm_id = $1 ORDER BY purpose, algorithm',
      [realmId]
    );
    return rows;
  }

  async function publicJwks(realmId: string): Promise<Record<string, Record<string, unknown>>> {
    const { rows } = await pools[0].query<{ kid: string; public_jwk: Record<string, unknown> }>(
      'SELECT kid, public_jwk FROM realm_public_keys WHERE realm_id = $1',
      [realmId]
    );
    return Object.fromEntries(rows.map((row) => [row.kid, row.public_jwk]));
  }

  it('stores the configured keys once, with the same public keys and a kid on Ed25519', async () => {
    const realmId = await seedRealm();

    const first = await bootOn(0, realmId, UPGRADE);
    const second = await bootOn(0, realmId, UPGRADE);

    expect(first.imported).toHaveLength(3);
    expect(second.imported).toEqual([]);
    expect(second.alreadyStored).toEqual(first.imported);
    expect((await keyRows(realmId)).map((row) => `${row.purpose}/${row.algorithm}`)).toEqual([
      'cookie_hmac/HS256',
      'data_at_rest/A256GCM',
      'event_signing/EdDSA',
      'token_signing/EdDSA',
      'token_signing/RS256',
    ]);

    const jwks = await publicJwks(realmId);
    const [ed25519, rs256] = first.imported;
    const edJwk = createPublicKey(ED25519.publicKey).export({ format: 'jwk' });
    const rsaJwk = createPublicKey(RSA.publicKey).export({ format: 'jwk' });
    expect(jwks[ed25519.kid]).toMatchObject({ ...edJwk, kid: ed25519.kid, alg: 'EdDSA' });
    expect(jwks[rs256.kid]).toMatchObject({ ...rsaJwk, kid: rs256.kid, alg: 'RS256' });
  });

  it('imports once when two nodes boot together', async () => {
    const realmId = await seedRealm();

    const results = await Promise.all([bootOn(0, realmId, UPGRADE), bootOn(1, realmId, UPGRADE)]);

    const importing = results.filter((result) => result.imported.length > 0);
    expect(importing).toHaveLength(1);
    expect(results.filter((result) => result.alreadyStored.length === 3)).toHaveLength(1);
    expect(await keyRows(realmId)).toHaveLength(5);
  });

  it('creates the keys of a fresh realm once when two nodes boot together', async () => {
    const realmId = await seedRealm();

    const results = await Promise.all([bootOn(0, realmId), bootOn(1, realmId)]);

    expect(results.map((result) => result.generated.length).sort()).toEqual([0, 5]);
    expect((await keyRows(realmId)).map((row) => `${row.purpose}/${row.algorithm}`)).toEqual([
      'cookie_hmac/HS256',
      'data_at_rest/A256GCM',
      'event_signing/EdDSA',
      'token_signing/EdDSA',
      'token_signing/RS256',
    ]);
  });

  it('keeps no imported private key or secret in plaintext in any column', async () => {
    const realmId = await seedRealm();
    await bootOn(0, realmId, UPGRADE);

    const secrets = [
      createPrivateKey(ED25519.privateKey).export({ type: 'pkcs8', format: 'der' }),
      createPrivateKey(RSA.privateKey).export({ type: 'pkcs8', format: 'der' }),
      Buffer.from(COOKIE_SECRET, 'utf8'),
    ];
    const texts = [ED25519.privateKey, RSA.privateKey, COOKIE_SECRET];
    for (const row of await keyRows(realmId)) {
      for (const value of Object.values(row)) {
        if (Buffer.isBuffer(value)) {
          for (const secret of secrets) expect(value.includes(secret)).toBe(false);
        } else if (typeof value === 'string') {
          for (const text of texts) expect(value).not.toContain(text);
        }
      }
    }
    const publicText = JSON.stringify(await publicJwks(realmId));
    for (const text of texts) expect(publicText).not.toContain(text);
    expect(publicText).not.toContain('"d"');
  });

  it('stores nothing when the import is refused', async () => {
    const realmId = await seedRealm();

    await expect(
      bootRealmKeys({
        store: createPgKeyStore(pools[0]),
        kekProvider: localProvider({}),
        enabledSignatureAlgorithms: ['EdDSA'],
        hybridSigning: false,
        realmId,
        environmentKeys: UPGRADE,
      })
    ).rejects.toThrow('no KEK is set');
    expect(await keyRows(realmId)).toEqual([]);
  });
});
