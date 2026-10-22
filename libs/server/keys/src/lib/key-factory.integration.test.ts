/**
 * Real-Postgres integration tests for key creation (issue #463).
 *
 * `createKey` and `provisionRealmKeys` run against the migrated schema of
 * `realm_keys` and `realm_public_keys` (#461), so the CHECKs, the foreign key
 * between the two tables and the one-active-key index see every row the
 * factory writes. Each stored key is opened again and compared with its
 * published public half, and every stored byte string is searched for a
 * plaintext PKCS#8 header.
 *
 * Requires Docker; self-skips without it, like the other container suites.
 */
import { createPrivateKey } from 'node:crypto';

import { deriveMlDsaPublicKey, getSignatureBackend } from '@qauth-labs/core-crypto';
import {
  applyQauthMigrations,
  requireDockerOrSkip,
  type StartedPostgres,
  startPostgresContainer,
  truncateDomainTablesStatement,
} from '@qauth-labs/shared-testing';
import { Pool, type PoolClient } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { KEK_A, localProvider } from '../testing/keks';
import { createPgKeyStore } from '../testing/pg-key-store';
import { openKeyMaterial } from './envelope';
import { createKeyFactory, type KeyFactoryOptions } from './key-factory';
import {
  KEY_PURPOSES,
  type KeyAlgorithm,
  type KeyPurpose,
  type KeyPurposeDefinition,
} from './key-purposes';
import type { RealmKeyStore } from './key-store';

/** A `realm_keys` row as node-postgres returns it. */
interface KeyRow {
  realm_id: string;
  purpose: string;
  scope_id: string | null;
  algorithm: KeyAlgorithm;
  kid: string;
  status: string;
  pair_id: string | null;
  ciphertext: Buffer;
  iv: Buffer;
  wrapped_dek: Buffer;
  kek_ref: string;
  aad_version: number;
  publish_at: string | null;
  activate_at: string | null;
}

/** A `realm_public_keys` row as node-postgres returns it. */
interface PublicKeyRow {
  realm_id: string;
  kid: string;
  purpose: string;
  algorithm: string;
  status: string;
  public_jwk: Record<string, unknown>;
  publish_at: string;
}

const NOW = 1_800_000_000_000;
const PKCS8_ALGORITHMS: readonly KeyAlgorithm[] = ['EdDSA', 'RS256', 'ES256', 'ECDH-ES'];

/**
 * The start of every PKCS#8 private key this library writes (RFC 5208 §5):
 * version 0, then the algorithm identifier, as DER. Ed25519 (RFC 8410), EC on
 * P-256 (RFC 5480) and rsaEncryption (RFC 8017).
 */
const PKCS8_HEADERS = [
  '020100300506032b6570',
  '020100301306072a8648ce3d020106082a8648ce3d030107',
  '020100300d06092a864886f70d0101010500',
].map((hex) => Buffer.from(hex, 'hex'));

const PUBLIC_MEMBERS: Record<string, readonly string[]> = {
  OKP: ['kty', 'crv', 'x'],
  EC: ['kty', 'crv', 'x', 'y'],
  RSA: ['kty', 'n', 'e'],
};

describe('key creation integration (real Postgres)', () => {
  let container: StartedPostgres | undefined;
  let pool: Pool | undefined;
  let dockerUp = false;
  const kekProvider = localProvider({ KEK: KEK_A });

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    container = await startPostgresContainer();
    await applyQauthMigrations(container.connectionString);
    pool = new Pool({ connectionString: container.connectionString });
  }, 180_000);

  afterAll(async () => {
    await pool?.end();
    await container?.stop();
  });

  beforeEach(async (testCtx) => {
    if (!dockerUp || !pool) {
      testCtx.skip();
      return;
    }
    await pool.query(truncateDomainTablesStatement());
  });

  function db(): Pool {
    if (!pool) throw new Error('no pool');
    return pool;
  }

  function factory(
    overrides: Partial<KeyFactoryOptions<PoolClient>> = {}
  ): ReturnType<typeof createKeyFactory<PoolClient>> {
    return createKeyFactory<PoolClient>({
      store: createPgKeyStore(db()),
      kekProvider,
      enabledSignatureAlgorithms: ['EdDSA'],
      hybridSigning: false,
      now: () => NOW,
      ...overrides,
    });
  }

  const hybridOn = {
    enabledSignatureAlgorithms: ['EdDSA', 'ML-DSA-65'],
    hybridSigning: true,
  } as const;

  async function seedRealm(client: Pool | PoolClient = db()): Promise<string> {
    const { rows } = await client.query<{ id: string }>(
      'INSERT INTO realms (name) VALUES ($1) RETURNING id',
      [`realm-${Math.random().toString(36).slice(2)}`]
    );
    return rows[0].id;
  }

  async function keyRows(realmId?: string): Promise<KeyRow[]> {
    const { rows } = await db().query<KeyRow>(
      realmId === undefined
        ? 'SELECT * FROM realm_keys ORDER BY created_at, id'
        : 'SELECT * FROM realm_keys WHERE realm_id = $1 ORDER BY created_at, id',
      realmId === undefined ? [] : [realmId]
    );
    return rows;
  }

  async function publicRows(realmId: string): Promise<PublicKeyRow[]> {
    const { rows } = await db().query<PublicKeyRow>(
      'SELECT * FROM realm_public_keys WHERE realm_id = $1',
      [realmId]
    );
    return rows;
  }

  /** Open a stored row with the KEK and the row's own identity. */
  function open(row: KeyRow): Promise<Buffer> {
    return openKeyMaterial(
      kekProvider,
      {
        ciphertext: row.ciphertext,
        iv: row.iv,
        wrappedDek: row.wrapped_dek,
        kekRef: row.kek_ref,
        aadVersion: row.aad_version,
      },
      {
        realmId: row.realm_id,
        purpose: row.purpose,
        scopeId: row.scope_id,
        kid: row.kid,
        algorithm: row.algorithm,
      }
    );
  }

  /** The public members the stored private material implies, as a JWK subset. */
  function impliedPublicJwk(row: KeyRow, material: Buffer): Record<string, unknown> {
    if (row.algorithm === 'ML-DSA-65') {
      const backend = getSignatureBackend('ML-DSA-65', ['EdDSA', 'ML-DSA-65']);
      const privateKey = backend.importKey(material.toString('base64url'), 'private');
      const derived = deriveMlDsaPublicKey(privateKey);
      privateKey.destroy();
      return { kty: 'AKP', pub: Buffer.from(derived.material()).toString('base64url') };
    }
    const privateKey = createPrivateKey({ key: material, format: 'der', type: 'pkcs8' });
    const jwk = { ...privateKey.export({ format: 'jwk' }) } as Record<string, unknown>;
    const members = PUBLIC_MEMBERS[String(jwk['kty'])];
    return Object.fromEntries(members.map((member) => [member, jwk[member]]));
  }

  /** Assert that no stored byte string of `row` holds a plaintext private key. */
  function expectNoPlaintextKey(row: KeyRow, material: Buffer): void {
    for (const stored of [row.ciphertext, row.iv, row.wrapped_dek]) {
      for (const header of PKCS8_HEADERS) expect(stored.includes(header)).toBe(false);
      expect(stored.includes(material.subarray(0, 16))).toBe(false);
      expect(stored.includes(Buffer.from('PRIVATE KEY'))).toBe(false);
    }
  }

  /** Every purpose and algorithm pair, without the hybrid companion, which is never created alone. */
  function everyPurposeAndAlgorithm(): [KeyPurpose, KeyAlgorithm][] {
    return (Object.keys(KEY_PURPOSES) as KeyPurpose[]).flatMap((purpose) => {
      const definition: KeyPurposeDefinition = KEY_PURPOSES[purpose];
      return definition.algorithms
        .filter((algorithm) => algorithm !== definition.hybridCompanion)
        .map((algorithm): [KeyPurpose, KeyAlgorithm] => [purpose, algorithm]);
    });
  }

  function scopeFor(purpose: KeyPurpose): string | undefined {
    return KEY_PURPOSES[purpose].scoped ? `${purpose}-owner` : undefined;
  }

  describe('createKey', () => {
    it.each(
      (Object.keys(KEY_PURPOSES) as KeyPurpose[]).filter((purpose) => purpose !== 'trust_anchor')
    )('stores a %s key in a standard deployment', async (purpose) => {
      const realmId = await seedRealm();
      const definition = KEY_PURPOSES[purpose];

      const [created] = await factory().createKey({
        realmId,
        purpose,
        scopeId: scopeFor(purpose),
      });

      const [row, ...others] = await keyRows(realmId);
      expect(others).toEqual([]);
      expect(row).toMatchObject({
        purpose,
        scope_id: scopeFor(purpose) ?? null,
        algorithm: definition.defaultAlgorithm,
        kid: created.kid,
        status: 'active',
        pair_id: null,
        activate_at: String(NOW),
        publish_at: definition.published ? String(NOW) : null,
      });

      const material = await open(row);
      expectNoPlaintextKey(row, material);

      const published = await publicRows(realmId);
      if (!definition.published) {
        expect(published).toEqual([]);
        return;
      }
      expect(published).toHaveLength(1);
      expect(published[0]).toMatchObject({
        kid: created.kid,
        purpose,
        algorithm: definition.defaultAlgorithm,
        status: 'active',
        publish_at: String(NOW),
      });
      expect(published[0].public_jwk).toMatchObject({
        kid: created.kid,
        ...impliedPublicJwk(row, material),
      });
    });

    it('stores a trust_anchor key in a federation-operator deployment', async () => {
      const realmId = await seedRealm();

      await factory({ federationOperator: true }).createKey({ realmId, purpose: 'trust_anchor' });

      expect((await keyRows(realmId)).map((row) => row.purpose)).toEqual(['trust_anchor']);
      expect(await publicRows(realmId)).toHaveLength(1);
    });

    it('holds no plaintext PKCS#8 header in any stored byte string, for every algorithm', async () => {
      const realmId = await seedRealm();
      const keys = factory({ ...hybridOn, federationOperator: true });

      for (const [purpose, algorithm] of everyPurposeAndAlgorithm()) {
        await keys.createKey({ realmId, purpose, algorithm, scopeId: scopeFor(purpose) });
      }

      const rows = await keyRows(realmId);
      expect(new Set(rows.map((row) => row.algorithm))).toEqual(
        new Set(['EdDSA', 'RS256', 'ES256', 'ML-DSA-65', 'ECDH-ES', 'HS256', 'A256GCM'])
      );
      for (const row of rows) {
        const material = await open(row);
        if (PKCS8_ALGORITHMS.includes(row.algorithm)) {
          expect(PKCS8_HEADERS.some((header) => material.includes(header))).toBe(true);
        }
        expectNoPlaintextKey(row, material);
      }
      for (const { public_jwk: jwk } of await publicRows(realmId)) {
        for (const member of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k', 'priv']) {
          expect(jwk).not.toHaveProperty(member);
        }
      }
    });

    it('stores the two keys of a hybrid pair under one pair_id', async () => {
      const realmId = await seedRealm();

      const created = await factory(hybridOn).createKey({ realmId, purpose: 'token_signing' });

      const rows = await keyRows(realmId);
      expect(rows.map((row) => row.algorithm).sort()).toEqual(['EdDSA', 'ML-DSA-65']);
      expect(rows[0].pair_id).not.toBeNull();
      expect(rows[1].pair_id).toBe(rows[0].pair_id);
      expect(created[0].pairId).toBe(rows[0].pair_id);

      const published = await publicRows(realmId);
      expect(published.map((row) => row.public_jwk['kty']).sort()).toEqual(['AKP', 'OKP']);
      for (const row of rows) {
        const material = await open(row);
        const publicRow = published.find((candidate) => candidate.kid === row.kid);
        expect(publicRow?.public_jwk).toMatchObject(impliedPublicJwk(row, material));
      }
    });

    it('stores one token key with hybrid signing off', async () => {
      const realmId = await seedRealm();

      await factory().createKey({ realmId, purpose: 'token_signing' });

      const rows = await keyRows(realmId);
      expect(rows.map((row) => [row.algorithm, row.pair_id])).toEqual([['EdDSA', null]]);
    });
  });

  describe('provisionRealmKeys', () => {
    it('creates the four standard keys in one transaction', async () => {
      const realmId = await seedRealm();

      const created = await factory().provisionRealmKeys(realmId);

      expect(created).toHaveLength(4);
      const rows = await keyRows(realmId);
      expect(rows.map((row) => [row.purpose, row.algorithm, row.status])).toEqual([
        ['token_signing', 'EdDSA', 'active'],
        ['event_signing', 'EdDSA', 'active'],
        ['cookie_hmac', 'HS256', 'active'],
        ['data_at_rest', 'A256GCM', 'active'],
      ]);
      expect((await publicRows(realmId)).map((row) => row.purpose).sort()).toEqual([
        'event_signing',
        'token_signing',
      ]);
      for (const row of rows) expectNoPlaintextKey(row, await open(row));
    });

    it('creates none of the keys when one cannot be stored', async () => {
      const realmId = await seedRealm();
      const store = createPgKeyStore(db());
      const failing: RealmKeyStore<PoolClient> = {
        ...store,
        async create(input, tx) {
          if (input.key.purpose === 'cookie_hmac') {
            // A real database error, after two keys were already inserted.
            await tx.query('SELECT 1 / 0');
          }
          return store.create(input, tx);
        },
      };

      await expect(factory({ store: failing }).provisionRealmKeys(realmId)).rejects.toThrow(
        /division by zero/
      );

      expect(await keyRows(realmId)).toEqual([]);
      expect(await publicRows(realmId)).toEqual([]);
    });

    it('adds the ML-DSA-65 token key under one pair_id with hybrid signing on', async () => {
      const realmId = await seedRealm();

      await factory(hybridOn).provisionRealmKeys(realmId);

      const rows = await keyRows(realmId);
      expect(rows).toHaveLength(5);
      const tokenKeys = rows.filter((row) => row.purpose === 'token_signing');
      expect(tokenKeys.map((row) => row.algorithm).sort()).toEqual(['EdDSA', 'ML-DSA-65']);
      expect(tokenKeys[0].pair_id).not.toBeNull();
      expect(tokenKeys[1].pair_id).toBe(tokenKeys[0].pair_id);
    });

    it('fills only the missing keys when called again', async () => {
      const realmId = await seedRealm();
      await factory().createKey({ realmId, purpose: 'token_signing' });

      await factory().provisionRealmKeys(realmId);
      expect(await factory().provisionRealmKeys(realmId)).toEqual([]);

      expect((await keyRows(realmId)).map((row) => row.purpose)).toEqual([
        'token_signing',
        'event_signing',
        'cookie_hmac',
        'data_at_rest',
      ]);
    });

    it('creates a realm and its keys together in the caller’s transaction', async () => {
      const client = await db().connect();
      let realmId: string;
      try {
        await client.query('BEGIN');
        realmId = await seedRealm(client);
        await factory().provisionRealmKeys(realmId, { tx: client });
        await client.query('ROLLBACK');
      } finally {
        client.release();
      }

      expect(await keyRows(realmId)).toEqual([]);
      const { rows } = await db().query('SELECT id FROM realms WHERE id = $1', [realmId]);
      expect(rows).toEqual([]);
    });
  });
});
