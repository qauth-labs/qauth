import { randomUUID } from 'node:crypto';

import type { SignatureAlgorithm } from '@qauth-labs/core-crypto';
import type { Signer } from '@qauth-labs/server-keys';
import {
  bootRealmKeys,
  createInProcessSigner,
  createKeyFactory,
  createLocalKekProvider,
  type NewStoredKeyRow,
  type PublicKeyRecord,
  type RealmKeyBootStore,
  type SignerKeyRecord,
  type SignerKeyStore,
  type StoredKeyStatus,
  type WrappedSignerKey,
} from '@qauth-labs/server-keys/custody';

import {
  prepublishTokenKeys,
  rotateTokenKeys,
  type TokenKeyPrepublication,
  type TokenKeyPrepublicationOptions,
  type TokenKeyRotation,
  type TokenKeyRotationOptions,
} from './key-rotation';

/**
 * The real in-process signer over keys held in memory, for unit tests that
 * sign and verify tokens without a database: the JWT plugin's own and the
 * auth server's (issue #491). Never exported from the package entry point.
 *
 * Each realm gets its keys from the real key factory, sealed under a test KEK,
 * so a token signed here carries the realm's `iss` and `kid` exactly as one
 * signed in production does.
 */

/** The KEK every test signer seals its keys under: 32 bytes of 0x7e. */
const TEST_KEK = Buffer.alloc(32, 0x7e).toString('base64');

/** Options of {@link createTestSigner}. */
export interface TestSignerOptions {
  /** `HYBRID_SIGNING_ENABLED`: each realm then gets an EdDSA and ML-DSA-65 pair. */
  readonly hybridSigning?: boolean;
  /** How long the signer trusts a key lookup, in ms. The production default when absent. */
  readonly refreshIntervalMs?: number;
}

/** A realm to add to a {@link TestSigner}. */
export interface TestRealmKeys {
  /** The realm's issuer, which the signer puts in every token's `iss`. */
  readonly issuer: string;
  /** The realm id. A new UUID when absent. */
  readonly id?: string;
  /** Add an RS256 `token_signing` key beside the standard keys. */
  readonly rs256?: boolean;
  /**
   * An Ed25519 private key, PKCS#8 PEM, to import as the realm's EdDSA
   * `token_signing` key, as the key boot step imports `JWT_PRIVATE_KEY`: for
   * a test that signs a token the way a release before the key store did.
   */
  readonly ed25519PrivateKey?: string;
}

/** What {@link createTestSigner} returns. */
export interface TestSigner {
  readonly signer: Signer;
  /** Create a realm with the standard keys (and RS256 when asked); returns its id. */
  addRealm(realm: TestRealmKeys): Promise<string>;
  /**
   * Change the status of a realm's key, as a rotation or a retirement would.
   * It sets no `unpublishAt`, so a key it retires neither verifies nor is
   * published; `rotateTokenKeys` retires a key that does.
   */
  setKeyStatus(realmId: string, kid: string, status: StoredKeyStatus): void;
  /**
   * Publish a new `next` `token_signing` key of one algorithm in the realm
   * (#494): in its JWKS at once, signing nothing until `rotateTokenKeys`
   * activates it. See `prepublishTokenKeys`. A signer whose refresh interval
   * is not `0` sees it only after that interval.
   */
  prepublishTokenKeys(
    realmId: string,
    options?: TokenKeyPrepublicationOptions
  ): Promise<TokenKeyPrepublication>;
  /**
   * Rotate the realm's `token_signing` keys of one algorithm (#492): its
   * pre-published `next` key, or a new one, becomes active and the old one
   * retired, published until its retention ends. See `rotateTokenKeys`. A
   * signer whose refresh interval is not `0` sees it only after that interval.
   */
  rotateTokenKeys(realmId: string, options?: TokenKeyRotationOptions): Promise<TokenKeyRotation>;
  /** Every store read the signer made, by method name, in order. */
  readonly storeReads: string[];
}

interface MemoryRow {
  key: Omit<NewStoredKeyRow, 'status'> & { status: StoredKeyStatus };
  publicJwk?: Record<string, unknown>;
  /** Epoch ms. When a retired key leaves its JWKS; a retired key with `null` is out at once. */
  unpublishAt: number | null;
}

/** The signer of `options`, with no realm yet. */
export function createTestSigner(options: TestSignerOptions = {}): TestSigner {
  const hybridSigning = options.hybridSigning === true;
  const enabledSignatureAlgorithms: readonly SignatureAlgorithm[] = hybridSigning
    ? ['EdDSA', 'ML-DSA-65']
    : ['EdDSA'];
  const kekProvider = createLocalKekProvider({
    env: { KEK: TEST_KEK, NODE_ENV: 'test' },
    warn: () => undefined,
  });
  const rows: MemoryRow[] = [];
  const issuers = new Map<string, string>();
  const storeReads: string[] = [];

  /** A row with its sealed material, as `realm_keys` holds it. */
  function wrappedKey(realmId: string, kid: string): WrappedSignerKey | undefined {
    const row = rows.find(({ key }) => key.realmId === realmId && key.kid === kid);
    if (row === undefined) return undefined;
    const { key } = row;
    return {
      realmId: key.realmId,
      purpose: key.purpose,
      scopeId: key.scopeId,
      kid: key.kid,
      algorithm: key.algorithm,
      status: key.status,
      ciphertext: key.ciphertext,
      iv: key.iv,
      wrappedDek: key.wrappedDek,
      kekRef: key.kekRef,
      aadVersion: key.aadVersion,
    };
  }

  const keyStore: RealmKeyBootStore<null> = {
    transaction: async (work) => {
      const snapshot = rows.map((row) => ({ ...row }));
      try {
        return await work(null);
      } catch (error) {
        rows.splice(0, rows.length, ...snapshot);
        throw error;
      }
    },
    findByKid: async (realmId, kid) =>
      rows.find((row) => row.key.realmId === realmId && row.key.kid === kid)?.key,
    listByRealm: async (realmId, filter) =>
      rows
        .map((row) => row.key)
        .filter(
          (key) =>
            key.realmId === realmId &&
            (filter.purpose === undefined || key.purpose === filter.purpose) &&
            (filter.scopeId === undefined || key.scopeId === filter.scopeId) &&
            (filter.status === undefined || key.status === filter.status)
        ),
    create: async (input) => {
      rows.push({
        key: { ...input.key },
        ...(input.publicJwk ? { publicJwk: input.publicJwk } : {}),
        unpublishAt: null,
      });
      return input.key;
    },
    // As the repository does: only a key in the status the step starts from moves.
    updateStatus: async (realmId, kid, change) => {
      const from = change.status === 'active' ? 'next' : 'active';
      const row = rows.find(
        ({ key }) => key.realmId === realmId && key.kid === kid && key.status === from
      );
      if (row === undefined) return undefined;
      if (change.status === 'active') {
        row.key = { ...row.key, status: 'active', activateAt: change.activateAt };
      } else {
        row.key = { ...row.key, status: 'retired' };
        row.unpublishAt = change.unpublishAt;
      }
      return row.key;
    },
    deleteByScope: async () => [],
    lockRealm: async () => undefined,
    getWrappedKey: async (realmId, kid) => wrappedKey(realmId, kid),
    anotherRealmPublishes: async (realmId, identity) =>
      rows.some(
        ({ key, publicJwk }) =>
          key.realmId !== realmId &&
          publicJwk !== undefined &&
          Object.entries(identity).every(
            ([name, value]) => (publicJwk as Record<string, unknown>)[name] === value
          )
      ),
    listPublicKeys: async (realmId) =>
      rows.flatMap(({ key, publicJwk }) =>
        key.realmId === realmId && publicJwk !== undefined
          ? [{ kid: key.kid, purpose: key.purpose, status: key.status, publicJwk }]
          : []
      ),
  };

  const signerStore: SignerKeyStore = {
    async findRealmIssuer(realmId) {
      storeReads.push('findRealmIssuer');
      return issuers.get(realmId);
    },
    async listKeys(realmId, filter): Promise<readonly SignerKeyRecord[]> {
      storeReads.push('listKeys');
      return rows
        .filter(
          ({ key }) =>
            key.realmId === realmId &&
            key.purpose === filter.purpose &&
            key.scopeId === filter.scopeId
        )
        .map(({ key }, index) => ({
          kid: key.kid,
          algorithm: key.algorithm,
          status: key.status,
          pairId: key.pairId,
          retireAt: key.status === 'retired' ? key.createdAt : null,
          createdAt: key.createdAt + index,
        }));
    },
    async getWrappedKey(realmId, kid): Promise<WrappedSignerKey | undefined> {
      storeReads.push('getWrappedKey');
      return wrappedKey(realmId, kid);
    },
    async listPublicKeys(realmId): Promise<readonly PublicKeyRecord[]> {
      storeReads.push('listPublicKeys');
      return rows.flatMap(({ key, publicJwk, unpublishAt }) =>
        key.realmId === realmId && publicJwk !== undefined && key.publishAt !== null
          ? [
              {
                kid: key.kid,
                purpose: key.purpose,
                algorithm: key.algorithm,
                status: key.status,
                publicJwk,
                publishAt: key.publishAt,
                unpublishAt,
              },
            ]
          : []
      );
    },
    findUpstreamClient: async () => undefined,
  };

  const factory = createKeyFactory({
    store: keyStore,
    kekProvider,
    enabledSignatureAlgorithms,
    hybridSigning,
  });

  return {
    signer: createInProcessSigner({
      store: signerStore,
      kekProvider,
      enabledSignatureAlgorithms,
      hybridSigning,
      ...(options.refreshIntervalMs === undefined
        ? {}
        : { refreshIntervalMs: options.refreshIntervalMs }),
    }),
    async addRealm(realm) {
      const id = realm.id ?? randomUUID();
      issuers.set(id, realm.issuer);
      if (realm.ed25519PrivateKey === undefined) {
        await factory.provisionRealmKeys(id);
      } else {
        await bootRealmKeys({
          store: keyStore,
          kekProvider,
          enabledSignatureAlgorithms,
          hybridSigning,
          realmId: id,
          environmentKeys: {
            ed25519: {
              privateKey: { value: realm.ed25519PrivateKey, variables: ['JWT_PRIVATE_KEY'] },
            },
          },
        });
      }
      if (realm.rs256 === true) {
        await factory.createKey({ realmId: id, purpose: 'token_signing', algorithm: 'RS256' });
      }
      return id;
    },
    setKeyStatus(realmId, kid, status) {
      const row = rows.find(({ key }) => key.realmId === realmId && key.kid === kid);
      if (row === undefined) throw new Error(`No key ${kid} in realm ${realmId}`);
      row.key = { ...row.key, status };
    },
    prepublishTokenKeys(realmId, prepublication) {
      return prepublishTokenKeys(keyStore, factory, realmId, prepublication);
    },
    rotateTokenKeys(realmId, rotation) {
      return rotateTokenKeys(keyStore, factory, realmId, rotation);
    },
    storeReads,
  };
}
