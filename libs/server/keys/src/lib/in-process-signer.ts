import {
  extractJwsSigningInput,
  getSignatureBackend,
  type HybridSignedToken,
  type MlDsaKey,
  PQC_ALG_ML_DSA_65,
  PQC_HEADER_ALG_MEMBER,
  PQC_HEADER_KID_MEMBER,
  type SignatureAlgorithm,
} from '@qauth-labs/core-crypto';
import { InvalidConfigurationError } from '@qauth-labs/shared-errors';
import { type JWK, type JWTPayload, SignJWT } from 'jose';

import type { KeyIdentity } from './aad';
import { BoundedCache } from './bounded-cache';
import {
  bufferSource,
  isDataKid,
  openData,
  parseDataEnvelope,
  resolveDataContext,
  sealData,
} from './data-at-rest';
import { openKeyMaterial } from './envelope';
import { KeyDecryptionError } from './errors';
import type { KekProvider } from './kek-provider';
import { isScopeId, MAX_SCOPE_ID_LENGTH } from './key-factory';
import { KEY_PURPOSES, type KeyPurpose } from './key-purposes';
import { isRealmId } from './realm-id';
import type {
  CookieSecret,
  CookieSecrets,
  DecryptRequest,
  EncryptRequest,
  JwsKeyAlgorithm,
  RealmJwks,
  SignClientAssertionRequest,
  Signer,
  SignerOperation,
  SignHybridRequest,
  SignJwsRequest,
  SignWebhookRequest,
  VerificationKey,
} from './signer';
import {
  RealmIssuerNotFoundError,
  SignerAccessDeniedError,
  SignerKeyNotFoundError,
  SignerRequestRefusedError,
  UpstreamClientNotFoundError,
} from './signer-errors';
import type {
  PublicKeyRecord,
  SignerKeyRecord,
  SignerKeyStore,
  UpstreamClientRecord,
  WrappedSignerKey,
} from './signer-key-store';
import { isSignerCallAllowed, isSignerCaller, type SignerCaller } from './signer-policy';
import {
  CLIENT_ASSERTION_TYP,
  isJwsSigningPurpose,
  isTypAllowed,
  type JwsSigningPurpose,
  type JwsTyp,
  REALM_JWKS_PURPOSES,
} from './signer-typ';
import {
  formatWebhookSignature,
  isWebhookId,
  isWebhookTimestamp,
  MAX_WEBHOOK_ID_LENGTH,
  webhookSignedContent,
} from './webhook-signature';

/**
 * The in-process signer (ADR-019 Decision 9, issue #464): the {@link Signer}
 * of a single deployment, where every role shares the signer's process.
 *
 * ## Keys in memory
 *
 * A key is read and unwrapped the first time an operation needs it, then kept
 * in memory, unwrapped, under a size limit ({@link DEFAULT_SIGNER_KEY_CACHE_SIZE}).
 * Signing and encryption keys are imported as non-extractable WebCrypto keys,
 * so not even this module can export them again. The plaintext material is
 * zeroed as soon as the key is imported; the ML-DSA-65 backend takes its seed
 * as a base64url string, a copy that cannot be zeroed.
 *
 * Which key is active is read from the store at most once per refresh
 * interval ({@link DEFAULT_SIGNER_REFRESH_INTERVAL_MS}) per realm, purpose
 * and scope, so a signature with a warm cache runs no database query. A
 * rotation (#542) is seen within one interval; until then the old key, which
 * stays published and verifiable, keeps signing. When the key list changes,
 * the node reads its published keys again, so it never signs with a key its
 * own verification set does not list. Two nodes can still disagree for up to
 * one interval, which the rotation's schedule must allow for. A key marked
 * `compromised` likewise stops signing, decrypting and appearing in the JWKS
 * at each node's next read; emergency retirement (#551) needs an invalidation
 * that reaches every node at once. The realm's issuer never changes once set,
 * so it is read once.
 *
 * ## What it never does
 *
 * - It never creates a key. A missing key is a {@link SignerKeyNotFoundError}.
 * - It never falls back to another key. A key that does not unwrap gives the
 *   key-custody error of the KEK provider, and the call fails.
 * - It never returns key material or a key object, and never puts either in
 *   an error or a log line. The cookie HMAC secret is the one secret it hands
 *   out, as a fresh copy. A webhook secret is imported as a non-extractable
 *   HMAC key and only signs.
 *
 * ## Scoped keys
 *
 * A webhook subscription's secrets and an upstream provider's client-assertion
 * keys are read per realm, purpose and scope, under the same refresh interval,
 * and unwrapped under the scope they belong to: a row moved to another
 * subscription or provider does not open. The client id an assertion names is
 * read from the provider's configuration at most once per interval; a provider
 * that has none is read again on the next call. A rotation, or a deletion with
 * the subscription or provider, reaches a node within one interval.
 */

/** The default size limit of the unwrapped-key cache, in keys. */
export const DEFAULT_SIGNER_KEY_CACHE_SIZE = 256;

/** The default time a key lookup is trusted before the store is asked again, in ms. */
export const DEFAULT_SIGNER_REFRESH_INTERVAL_MS = 60_000;

/**
 * The least time between two reads that a `decrypt` miss forces, per realm
 * and purpose, in ms. A ciphertext naming a key the cached list lacks reads
 * the list again, but a run of them does not each cost a query.
 */
const MIN_FORCED_READ_INTERVAL_MS = 1_000;

/** Options of {@link createInProcessSigner}. */
export interface InProcessSignerOptions {
  /** Where the keys and realms are read. See {@link SignerKeyStore}. */
  readonly store: SignerKeyStore;
  /** Unwraps each key's data key. */
  readonly kekProvider: KekProvider;
  /**
   * The signature algorithms `SIGNING_ALGORITHM_MODE` enables
   * (`cryptoEnv.enabledSignatureAlgorithms`). They gate the ML-DSA-65 backend.
   */
  readonly enabledSignatureAlgorithms: readonly SignatureAlgorithm[];
  /**
   * `HYBRID_SIGNING_ENABLED`. When off, `signHybrid` is refused and no
   * ML-DSA-65 private key is ever unwrapped (ADR-005, #248 F10).
   */
  readonly hybridSigning: boolean;
  /** The most unwrapped keys held at once. Defaults to {@link DEFAULT_SIGNER_KEY_CACHE_SIZE}. */
  readonly keyCacheSize?: number;
  /**
   * How long a key lookup is trusted, in ms. Defaults to
   * {@link DEFAULT_SIGNER_REFRESH_INTERVAL_MS}; `0` reads the store on every
   * call.
   */
  readonly refreshIntervalMs?: number;
  /** The clock, in epoch ms. Defaults to `Date.now`. */
  readonly now?: () => number;
}

/**
 * An unwrapped key, as the cache holds it. `hmac` is the cookie HMAC secret,
 * which the signer hands out; `hmac-key` is any other HMAC secret, which only
 * signs.
 */
type LoadedKey =
  | { readonly kind: 'jws'; readonly key: CryptoKey }
  | { readonly kind: 'ml-dsa'; readonly key: MlDsaKey }
  | { readonly kind: 'hmac'; readonly secret: Buffer }
  | { readonly kind: 'hmac-key'; readonly key: CryptoKey }
  | { readonly kind: 'aes'; readonly key: CryptoKey };

/** A store answer and when it was read. */
interface Timed<T> {
  readonly value: T;
  readonly readAt: number;
}

/** The fields each operation's request takes. Any other field is refused. */
const REQUEST_FIELDS = {
  signJws: ['realmId', 'purpose', 'scopeId', 'typ', 'algorithm', 'claims'],
  signHybrid: ['realmId', 'typ', 'claims'],
  signWebhook: ['realmId', 'subscriptionId', 'id', 'timestamp', 'body'],
  signClientAssertion: ['realmId', 'providerId', 'audience', 'algorithm', 'claims'],
  encrypt: ['realmId', 'plaintext', 'context'],
  decrypt: ['realmId', 'ciphertext', 'context'],
} as const satisfies Partial<Record<SignerOperation, readonly string[]>>;

/** The algorithms `signJws` signs with, and their WebCrypto import parameters. */
const JWS_IMPORT_PARAMS: Readonly<
  Record<JwsKeyAlgorithm, Parameters<SubtleCrypto['importKey']>[2]>
> = Object.freeze({
  EdDSA: { name: 'Ed25519' },
  RS256: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
  ES256: { name: 'ECDSA', namedCurve: 'P-256' },
});

/**
 * The private members of every JWK key type (RFC 7518 §6, RFC 8037 §2,
 * RFC 9964), as the `realm_public_keys` CHECK lists them.
 */
const PRIVATE_JWK_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k', 'priv'] as const;

/** The claims the signer sets on a client assertion. */
const CLIENT_ASSERTION_RESERVED_CLAIMS = ['iss', 'sub', 'aud'] as const;

/** The longest client-assertion audience the signer accepts. */
const MAX_AUDIENCE_LENGTH = 2048;

function isJwsKeyAlgorithm(value: unknown): value is JwsKeyAlgorithm {
  return typeof value === 'string' && Object.hasOwn(JWS_IMPORT_PARAMS, value);
}

/**
 * Create the in-process signer of a deployment.
 *
 * @throws InvalidConfigurationError when hybrid signing is on and
 *   `SIGNING_ALGORITHM_MODE` does not enable ML-DSA-65, or a cache option is
 *   out of range
 */
export function createInProcessSigner(options: InProcessSignerOptions): Signer {
  const { store, kekProvider, enabledSignatureAlgorithms } = options;
  // Strict, so a string 'false' from an untyped configuration path stays off.
  const hybridSigning = options.hybridSigning === true;
  const now = options.now ?? Date.now;
  const refreshIntervalMs = options.refreshIntervalMs ?? DEFAULT_SIGNER_REFRESH_INTERVAL_MS;
  const keyCacheSize = options.keyCacheSize ?? DEFAULT_SIGNER_KEY_CACHE_SIZE;

  if (hybridSigning && !enabledSignatureAlgorithms.includes('ML-DSA-65')) {
    throw new InvalidConfigurationError(
      "HYBRID_SIGNING_ENABLED=true requires SIGNING_ALGORITHM_MODE='ed25519+ml-dsa-65'."
    );
  }
  if (!Number.isFinite(refreshIntervalMs) || refreshIntervalMs < 0) {
    throw new InvalidConfigurationError(
      'The signer refresh interval is a non-negative number of ms'
    );
  }
  if (!Number.isSafeInteger(keyCacheSize) || keyCacheSize < 1) {
    throw new InvalidConfigurationError('The signer key cache size is a positive integer');
  }

  // A key pushed out of the cache is dropped, not zeroed or destroyed: a call
  // that is still waiting on it would otherwise sign with, or copy, a cleared
  // key.
  const keys = new BoundedCache<string, LoadedKey>(keyCacheSize);
  const pendingKeys = new Map<string, Promise<LoadedKey>>();
  const keyLists = new BoundedCache<string, Timed<readonly SignerKeyRecord[]>>(keyCacheSize);
  const publicLists = new BoundedCache<string, Timed<readonly PublicKeyRecord[]>>(keyCacheSize);
  // Raised each time a key-list read drops a realm's published keys, so a
  // published-key read already running cannot store its older answer. A plain
  // map: an evicted count would restart at 0 and let that read in. An entry
  // lives only until the next stored read.
  const publicGenerations = new Map<string, number>();
  // One store read per slot at a time: concurrent callers share it.
  const pendingReads = new Map<string, Promise<unknown>>();
  const issuers = new BoundedCache<string, string>(keyCacheSize);
  const upstreamClients = new BoundedCache<string, Timed<UpstreamClientRecord>>(keyCacheSize);

  function isFresh(entry: Timed<unknown> | undefined): boolean {
    return entry !== undefined && now() - entry.readAt < refreshIntervalMs;
  }

  /** The realm's issuer, read once. */
  async function realmIssuer(realmId: string): Promise<string> {
    const cached = issuers.get(realmId);
    if (cached !== undefined) return cached;
    const issuer = await store.findRealmIssuer(realmId);
    if (typeof issuer !== 'string' || issuer.length === 0) {
      throw new RealmIssuerNotFoundError(realmId);
    }
    issuers.set(realmId, issuer);
    return issuer;
  }

  /**
   * Run `read` once for `slot` however many callers ask while it runs. The
   * time is taken before the read, so an answer is never trusted for longer
   * than the interval since the store was asked.
   */
  function sharedRead<T>(slot: string, read: (readAt: number) => Promise<T>): Promise<T> {
    let pending = pendingReads.get(slot) as Promise<T> | undefined;
    if (pending === undefined) {
      pending = read(now()).finally(() => pendingReads.delete(slot));
      pendingReads.set(slot, pending);
    }
    return pending;
  }

  /**
   * Every key of the realm's purpose and scope, read at most once per refresh
   * interval. `forceRead` reads again sooner, but not twice within
   * {@link MIN_FORCED_READ_INTERVAL_MS}.
   */
  async function listKeys(
    realmId: string,
    purpose: KeyPurpose,
    scopeId: string | null,
    forceRead = false
  ): Promise<readonly SignerKeyRecord[]> {
    const slot = `keys\u0000${realmId}\u0000${purpose}\u0000${scopeId ?? ''}`;
    const cached = keyLists.get(slot);
    if (cached !== undefined) {
      const age = now() - cached.readAt;
      const trusted = forceRead
        ? Math.min(MIN_FORCED_READ_INTERVAL_MS, refreshIntervalMs)
        : refreshIntervalMs;
      if (age < trusted) {
        return cached.value;
      }
    }
    return sharedRead(slot, async (readAt) => {
      const value = Object.freeze([...(await store.listKeys(realmId, { purpose, scopeId }))]);
      const current = keyLists.get(slot);
      if (current === undefined || current.readAt <= readAt) {
        // A key changed status, or there is no earlier list to compare (a
        // first read, or one evicted): the published keys this node holds may
        // be older than this list, so read them again too. Otherwise this node
        // could sign with a key its own verification set still calls `next`.
        if (current === undefined || !sameKeys(current.value, value)) {
          publicLists.delete(realmId);
          publicGenerations.set(realmId, (publicGenerations.get(realmId) ?? 0) + 1);
        }
        keyLists.set(slot, { value, readAt });
      }
      return value;
    });
  }

  /**
   * The client id of the realm's configuration for `providerId`, read at most
   * once per refresh interval. A provider without one is not kept, so its
   * configuration is used as soon as it exists.
   */
  async function upstreamClient(realmId: string, providerId: string): Promise<string> {
    const slot = `upstream\u0000${realmId}\u0000${providerId}`;
    const cached = upstreamClients.get(slot);
    if (cached !== undefined && isFresh(cached)) return cached.value.clientId;
    const record = await sharedRead(slot, async (readAt) => {
      const found = await store.findUpstreamClient(realmId, providerId);
      if (found === undefined || typeof found.clientId !== 'string' || found.clientId === '') {
        upstreamClients.delete(slot);
        return undefined;
      }
      const value = Object.freeze({ clientId: found.clientId });
      upstreamClients.set(slot, { value, readAt });
      return value;
    });
    if (record === undefined) throw new UpstreamClientNotFoundError(realmId);
    return record.clientId;
  }

  /** The realm's published keys, read at most once per refresh interval. */
  async function listPublicKeys(realmId: string): Promise<readonly PublicKeyRecord[]> {
    const cached = publicLists.get(realmId);
    if (cached !== undefined && isFresh(cached)) return cached.value;
    return sharedRead(`public\u0000${realmId}`, async (readAt) => {
      const generation = publicGenerations.get(realmId) ?? 0;
      const value = Object.freeze([...(await store.listPublicKeys(realmId))]);
      const current = publicLists.get(realmId);
      // One read per realm runs at a time, so removing the count after a store
      // cannot make an older read match it.
      if (
        (publicGenerations.get(realmId) ?? 0) === generation &&
        (current === undefined || current.readAt <= readAt)
      ) {
        publicLists.set(realmId, { value, readAt });
        publicGenerations.delete(realmId);
      }
      return value;
    });
  }

  /** The one active key of the purpose, scope and algorithm. */
  async function activeKey(
    realmId: string,
    purpose: KeyPurpose,
    algorithm: string,
    scopeId: string | null = null
  ): Promise<SignerKeyRecord> {
    const active = (await listKeys(realmId, purpose, scopeId)).filter(
      (key) => key.status === 'active' && key.algorithm === algorithm
    );
    // The one-active-key index makes two impossible; refuse rather than pick.
    if (active.length !== 1) {
      throw new SignerKeyNotFoundError(realmId, purpose, { algorithm });
    }
    return active[0];
  }

  /** The unwrapped key named by `identity`: from memory, or read and unwrapped once. */
  async function loadKey(identity: KeyIdentity): Promise<LoadedKey> {
    const cacheKey = [
      identity.realmId,
      identity.purpose,
      identity.scopeId ?? '',
      identity.algorithm,
      identity.kid,
    ].join('\u0000');
    const cached = keys.get(cacheKey);
    if (cached !== undefined) return cached;

    let pending = pendingKeys.get(cacheKey);
    if (pending === undefined) {
      pending = unwrapKey(identity).then(
        (loaded) => {
          pendingKeys.delete(cacheKey);
          keys.set(cacheKey, loaded);
          return loaded;
        },
        (error: unknown) => {
          pendingKeys.delete(cacheKey);
          throw error;
        }
      );
      pendingKeys.set(cacheKey, pending);
    }
    return pending;
  }

  /**
   * Read one key and unwrap it under the identity the signer expects, not the
   * one the row states. A row moved to another realm, purpose, scope or
   * algorithm therefore fails to open (its associated data differs).
   */
  async function unwrapKey(identity: KeyIdentity): Promise<LoadedKey> {
    const row: WrappedSignerKey | undefined = await store.getWrappedKey(
      identity.realmId,
      identity.kid
    );
    if (row === undefined) {
      throw new SignerKeyNotFoundError(identity.realmId, identity.purpose, { kid: identity.kid });
    }
    const material = await openKeyMaterial(kekProvider, row, identity);
    try {
      return await importMaterial(identity.purpose, identity.algorithm, material);
    } catch (error) {
      if (error instanceof KeyDecryptionError) throw error;
      // The import error is dropped: it may describe the material.
      throw new KeyDecryptionError({ detail: 'key material did not import' });
    } finally {
      material.fill(0);
    }
  }

  async function importMaterial(
    purpose: string,
    algorithm: string,
    material: Buffer
  ): Promise<LoadedKey> {
    if (isJwsKeyAlgorithm(algorithm)) {
      const key = await crypto.subtle.importKey(
        'pkcs8',
        bufferSource(material),
        JWS_IMPORT_PARAMS[algorithm],
        false,
        ['sign']
      );
      return Object.freeze({ kind: 'jws', key });
    }
    switch (algorithm) {
      case 'ML-DSA-65': {
        const backend = getSignatureBackend('ML-DSA-65', enabledSignatureAlgorithms);
        const key = backend.importKey(material.toString('base64url'), 'private', {
          extractable: false,
        });
        return Object.freeze({ kind: 'ml-dsa', key });
      }
      case 'HS256': {
        // Only the cookie HMAC secret is handed out (ADR-019 Decision 9).
        if (purpose === 'cookie_hmac') {
          return Object.freeze({ kind: 'hmac', secret: ownCopy(material) });
        }
        const key = await crypto.subtle.importKey(
          'raw',
          bufferSource(material),
          { name: 'HMAC', hash: 'SHA-256' },
          false,
          ['sign']
        );
        return Object.freeze({ kind: 'hmac-key', key });
      }
      case 'A256GCM': {
        const key = await crypto.subtle.importKey('raw', bufferSource(material), 'AES-GCM', false, [
          'encrypt',
          'decrypt',
        ]);
        return Object.freeze({ kind: 'aes', key });
      }
      default:
        throw new KeyDecryptionError({ detail: 'unsupported key algorithm' });
    }
  }

  function identityOf(
    realmId: string,
    purpose: KeyPurpose,
    record: SignerKeyRecord,
    scopeId: string | null = null
  ): KeyIdentity {
    return { realmId, purpose, scopeId, kid: record.kid, algorithm: record.algorithm };
  }

  async function jwsKey(
    realmId: string,
    purpose: KeyPurpose,
    record: SignerKeyRecord,
    scopeId: string | null = null
  ) {
    const loaded = await loadKey(identityOf(realmId, purpose, record, scopeId));
    if (loaded.kind !== 'jws') throw new KeyDecryptionError({ detail: 'not a JWS signing key' });
    return loaded.key;
  }

  async function aesKey(realmId: string, record: SignerKeyRecord): Promise<CryptoKey> {
    const loaded = await loadKey(identityOf(realmId, 'data_at_rest', record));
    if (loaded.kind !== 'aes') throw new KeyDecryptionError({ detail: 'not an AES-GCM key' });
    return loaded.key;
  }

  /** The webhook secret of `record`, as a key that only signs. */
  async function webhookKey(
    realmId: string,
    subscriptionId: string,
    record: SignerKeyRecord
  ): Promise<CryptoKey> {
    const loaded = await loadKey(identityOf(realmId, 'webhook_signing', record, subscriptionId));
    if (loaded.kind !== 'hmac-key') throw new KeyDecryptionError({ detail: 'not an HMAC key' });
    return loaded.key;
  }

  /** A copy of the HMAC secret of `record`, which belongs to the caller. */
  async function secretOf(realmId: string, record: SignerKeyRecord): Promise<CookieSecret> {
    const loaded = await loadKey(identityOf(realmId, 'cookie_hmac', record));
    if (loaded.kind !== 'hmac') throw new KeyDecryptionError({ detail: 'not an HMAC secret' });
    return Object.freeze({ kid: record.kid, secret: ownCopy(loaded.secret) });
  }

  function authorize(caller: unknown, operation: SignerOperation, purpose?: string): void {
    if (!isSignerCallAllowed(caller, operation, purpose)) {
      throw new SignerAccessDeniedError(
        isSignerCaller(caller) ? caller : undefined,
        operation,
        purpose
      );
    }
  }

  function signJwt(
    payload: JWTPayload,
    key: CryptoKey,
    header: { alg: string; kid: string; typ: string } & Record<string, string>
  ): Promise<string> {
    return new SignJWT(payload).setProtectedHeader(header).sign(key);
  }

  return Object.freeze({
    async signJws(caller: SignerCaller, request: SignJwsRequest): Promise<string> {
      const fields = readRequest(request, REQUEST_FIELDS.signJws);
      const purpose = fields['purpose'];
      if (!isJwsSigningPurpose(purpose)) {
        throw new SignerRequestRefusedError(
          'PURPOSE_NOT_ALLOWED',
          `${describePurpose(purpose)} does not sign through signJws`
        );
      }
      authorize(caller, 'signJws', purpose);
      const realmId = resolveRealmId(fields['realmId']);
      if (fields['scopeId'] !== undefined && fields['scopeId'] !== null) {
        throw new SignerRequestRefusedError(
          'SCOPE_NOT_ALLOWED',
          `Key purpose '${purpose}' is not scoped and takes no scope id`
        );
      }
      const typ = resolveTyp(purpose, fields['typ']);
      const definition = KEY_PURPOSES[purpose];
      const algorithm = fields['algorithm'] ?? definition.defaultAlgorithm;
      if (
        !isJwsKeyAlgorithm(algorithm) ||
        !(definition.algorithms as readonly string[]).includes(algorithm)
      ) {
        throw new SignerRequestRefusedError(
          'ALGORITHM_NOT_ALLOWED',
          `Key purpose '${purpose}' does not sign JWS with the requested algorithm ` +
            `(allowed: ${definition.algorithms.filter(isJwsKeyAlgorithm).join(', ')}; ` +
            'ML-DSA-65 signs only through signHybrid)'
        );
      }
      const claims = resolveClaims(fields['claims']);

      const issuer = await realmIssuer(realmId);
      const record = await activeKey(realmId, purpose, algorithm);
      const key = await jwsKey(realmId, purpose, record);
      return signJwt({ iss: issuer, ...claims } as JWTPayload, key, {
        alg: algorithm,
        kid: record.kid,
        typ,
      });
    },

    async signHybrid(caller: SignerCaller, request: SignHybridRequest): Promise<HybridSignedToken> {
      const fields = readRequest(request, REQUEST_FIELDS.signHybrid);
      authorize(caller, 'signHybrid');
      if (!hybridSigning) {
        throw new SignerRequestRefusedError(
          'HYBRID_SIGNING_DISABLED',
          'Hybrid signing is off (HYBRID_SIGNING_ENABLED=false)'
        );
      }
      const realmId = resolveRealmId(fields['realmId']);
      const typ = resolveTyp('token_signing', fields['typ']);
      const claims = resolveClaims(fields['claims']);

      const issuer = await realmIssuer(realmId);
      const active = (await listKeys(realmId, 'token_signing', null)).filter(
        (key) => key.status === 'active'
      );
      const classical = active.filter((key) => key.algorithm === 'EdDSA');
      const pqc = active.filter((key) => key.algorithm === PQC_ALG_ML_DSA_65);
      if (
        classical.length !== 1 ||
        pqc.length !== 1 ||
        classical[0].pairId === null ||
        classical[0].pairId !== pqc[0].pairId
      ) {
        throw new SignerKeyNotFoundError(realmId, 'token_signing', {
          algorithm: `EdDSA+${PQC_ALG_ML_DSA_65}`,
          detail: 'no complete hybrid pair',
        });
      }
      const [edRecord, mlDsaRecord] = [classical[0], pqc[0]];

      // Resolved before anything is signed, so a disabled backend never leaves
      // a classical-only token behind.
      const backend = getSignatureBackend(PQC_ALG_ML_DSA_65, enabledSignatureAlgorithms);
      const edKey = await jwsKey(realmId, 'token_signing', edRecord);
      const mlDsa = await loadKey(identityOf(realmId, 'token_signing', mlDsaRecord));
      if (mlDsa.kind !== 'ml-dsa') {
        throw new KeyDecryptionError({ detail: 'not an ML-DSA-65 key' });
      }

      const token = await signJwt({ iss: issuer, ...claims } as JWTPayload, edKey, {
        alg: 'EdDSA',
        kid: edRecord.kid,
        typ,
        [PQC_HEADER_ALG_MEMBER]: PQC_ALG_ML_DSA_65,
        [PQC_HEADER_KID_MEMBER]: mlDsaRecord.kid,
      });
      const pqcSignature = Buffer.from(
        backend.sign(mlDsa.key, extractJwsSigningInput(token))
      ).toString('base64url');
      return Object.freeze({ token, pqcSignature, pqcAlg: PQC_ALG_ML_DSA_65 });
    },

    async signWebhook(caller: SignerCaller, request: SignWebhookRequest): Promise<string> {
      const fields = readRequest(request, REQUEST_FIELDS.signWebhook);
      authorize(caller, 'signWebhook');
      const realmId = resolveRealmId(fields['realmId']);
      const subscriptionId = resolveScope(fields['subscriptionId'], 'subscription id');
      const id = fields['id'];
      if (!isWebhookId(id)) {
        throw new SignerRequestRefusedError(
          'INVALID_WEBHOOK_ID',
          `A webhook id is 1 to ${MAX_WEBHOOK_ID_LENGTH} printable ASCII characters, ` +
            'without a full stop or a space'
        );
      }
      const timestamp = fields['timestamp'];
      if (!isWebhookTimestamp(timestamp)) {
        throw new SignerRequestRefusedError(
          'INVALID_TIMESTAMP',
          'A webhook timestamp is a whole, non-negative number of seconds since the epoch'
        );
      }
      const body = resolveWebhookBody(fields['body']);

      const records = await listKeys(realmId, 'webhook_signing', subscriptionId);
      const usable = (status: SignerKeyRecord['status']) =>
        records.filter((key) => key.status === status && key.algorithm === 'HS256');
      const active = usable('active');
      if (active.length !== 1) {
        throw new SignerKeyNotFoundError(realmId, 'webhook_signing', { algorithm: 'HS256' });
      }
      // During a rotation the next secret signs too, so a receiver that has
      // already switched verifies the message (Standard Webhooks, "webhook
      // headers"). The key list is oldest first, so the order is stable.
      const content = bufferSource(webhookSignedContent(id, timestamp, body));
      const signatures: string[] = [];
      for (const record of [active[0], ...usable('next')]) {
        const key = await webhookKey(realmId, subscriptionId, record);
        signatures.push(formatWebhookSignature(await crypto.subtle.sign('HMAC', key, content)));
      }
      return signatures.join(' ');
    },

    async signClientAssertion(
      caller: SignerCaller,
      request: SignClientAssertionRequest
    ): Promise<string> {
      const fields = readRequest(request, REQUEST_FIELDS.signClientAssertion);
      authorize(caller, 'signClientAssertion');
      const realmId = resolveRealmId(fields['realmId']);
      const providerId = resolveScope(fields['providerId'], 'provider id');
      const audience = fields['audience'];
      if (
        typeof audience !== 'string' ||
        audience.length === 0 ||
        audience.length > MAX_AUDIENCE_LENGTH
      ) {
        throw new SignerRequestRefusedError(
          'INVALID_AUDIENCE',
          'A client assertion audience is one string: the upstream issuer identifier'
        );
      }
      const definition = KEY_PURPOSES.upstream_client_assertion;
      const algorithm = fields['algorithm'] ?? definition.defaultAlgorithm;
      if (
        !isJwsKeyAlgorithm(algorithm) ||
        !(definition.algorithms as readonly string[]).includes(algorithm)
      ) {
        throw new SignerRequestRefusedError(
          'ALGORITHM_NOT_ALLOWED',
          'Client assertions are signed with ' + definition.algorithms.join(', ')
        );
      }
      const claims = resolveClaims(fields['claims'], CLIENT_ASSERTION_RESERVED_CLAIMS);
      // RFC 7523 §3 requires exp; OpenID Connect Core §9 requires jti for
      // private_key_jwt.
      if (
        typeof claims['exp'] !== 'number' ||
        !Number.isFinite(claims['exp']) ||
        typeof claims['jti'] !== 'string' ||
        claims['jti'].length === 0
      ) {
        throw new SignerRequestRefusedError(
          'MISSING_CLAIM',
          'A client assertion carries exp, a number, and jti, a non-empty string'
        );
      }

      const clientId = await upstreamClient(realmId, providerId);
      const record = await activeKey(realmId, 'upstream_client_assertion', algorithm, providerId);
      const key = await jwsKey(realmId, 'upstream_client_assertion', record, providerId);
      return signJwt(
        { iss: clientId, sub: clientId, aud: audience, ...claims } as JWTPayload,
        key,
        {
          alg: algorithm,
          kid: record.kid,
          typ: CLIENT_ASSERTION_TYP,
        }
      );
    },

    async getCookieSecrets(caller: SignerCaller, realmIdInput: string): Promise<CookieSecrets> {
      authorize(caller, 'getCookieSecrets');
      const realmId = resolveRealmId(realmIdInput);
      const records = await listKeys(realmId, 'cookie_hmac', null);
      const current = records.filter((key) => key.status === 'active' && key.algorithm === 'HS256');
      if (current.length !== 1) {
        throw new SignerKeyNotFoundError(realmId, 'cookie_hmac', { algorithm: 'HS256' });
      }
      const [previous] = records
        .filter((key) => key.status === 'retired' && key.algorithm === 'HS256')
        .sort(byMostRecentlyRetired);

      return Object.freeze({
        current: await secretOf(realmId, current[0]),
        previous: previous === undefined ? null : await secretOf(realmId, previous),
      });
    },

    async encrypt(caller: SignerCaller, request: EncryptRequest): Promise<string> {
      const fields = readRequest(request, REQUEST_FIELDS.encrypt);
      authorize(caller, 'encrypt');
      const realmId = resolveRealmId(fields['realmId']);
      const plaintext = fields['plaintext'];
      if (!(plaintext instanceof Uint8Array)) {
        throw new SignerRequestRefusedError('INVALID_PLAINTEXT', 'The plaintext is a byte array');
      }
      const context = resolveDataContext(fields['context']);

      const record = await activeKey(realmId, 'data_at_rest', 'A256GCM');
      if (!isDataKid(record.kid)) {
        throw new SignerKeyNotFoundError(realmId, 'data_at_rest', {
          algorithm: 'A256GCM',
          detail: 'the active key has a kid the ciphertext format cannot carry',
        });
      }
      return sealData(await aesKey(realmId, record), record.kid, realmId, context, plaintext);
    },

    async decrypt(caller: SignerCaller, request: DecryptRequest): Promise<Buffer> {
      const fields = readRequest(request, REQUEST_FIELDS.decrypt);
      const context = resolveDataContext(fields['context']);
      // A role may be limited to contexts with given prefixes (the delivery
      // role's destination secrets). The context is not echoed in the refusal.
      if (!isSignerCallAllowed(caller, 'decrypt', context)) {
        throw new SignerAccessDeniedError(isSignerCaller(caller) ? caller : undefined, 'decrypt');
      }
      const realmId = resolveRealmId(fields['realmId']);
      const envelope = parseDataEnvelope(fields['ciphertext']);

      const usable = (key: SignerKeyRecord) =>
        key.kid === envelope.kid &&
        key.algorithm === 'A256GCM' &&
        (key.status === 'active' || key.status === 'retired');
      // A key created since the last read is not in the cached list yet, so a
      // miss reads the list once more before it gives up.
      const record =
        (await listKeys(realmId, 'data_at_rest', null)).find(usable) ??
        (await listKeys(realmId, 'data_at_rest', null, true)).find(usable);
      if (record === undefined) {
        throw new SignerKeyNotFoundError(realmId, 'data_at_rest', { kid: envelope.kid });
      }
      return openData(await aesKey(realmId, record), envelope, realmId, context);
    },

    async getVerificationKeys(
      caller: SignerCaller,
      realmIdInput: string,
      purpose: string
    ): Promise<readonly VerificationKey[]> {
      if (!isJwsSigningPurpose(purpose)) {
        throw new SignerRequestRefusedError(
          'PURPOSE_NOT_ALLOWED',
          `${describePurpose(purpose)} has no verification keys`
        );
      }
      authorize(caller, 'getVerificationKeys');
      const realmId = resolveRealmId(realmIdInput);
      const at = now();
      const keys: VerificationKey[] = [];
      for (const record of sortForPublication(await listPublicKeys(realmId))) {
        if (record.purpose !== purpose || !isPublishedAt(record, at)) continue;
        if (record.status !== 'active' && record.status !== 'retired') continue;
        keys.push(
          Object.freeze({
            kid: record.kid,
            algorithm: record.algorithm,
            status: record.status,
            publicJwk: publicJwkOf(record),
          })
        );
      }
      return Object.freeze(keys);
    },

    async getJwks(caller: SignerCaller, realmIdInput: string): Promise<RealmJwks> {
      authorize(caller, 'getJwks');
      const realmId = resolveRealmId(realmIdInput);
      const at = now();
      const keys = sortForPublication(await listPublicKeys(realmId))
        .filter(
          (record) =>
            (REALM_JWKS_PURPOSES as readonly string[]).includes(record.purpose) &&
            record.status !== 'compromised' &&
            isPublishedAt(record, at)
        )
        .map(publicJwkOf);
      return Object.freeze({ keys: Object.freeze(keys) });
    },

    async getUpstreamJwks(
      caller: SignerCaller,
      realmIdInput: string,
      providerIdInput: string
    ): Promise<RealmJwks> {
      authorize(caller, 'getUpstreamJwks');
      const realmId = resolveRealmId(realmIdInput);
      const providerId = resolveScope(providerIdInput, 'provider id');
      // `realm_public_keys` names no scope; the provider's keys are those its
      // key list names. Read first, so a changed list refreshes the public keys.
      const kids = new Set(
        (await listKeys(realmId, 'upstream_client_assertion', providerId)).map((key) => key.kid)
      );
      const at = now();
      const keys = sortForPublication(await listPublicKeys(realmId))
        .filter(
          (record) =>
            record.purpose === 'upstream_client_assertion' &&
            kids.has(record.kid) &&
            record.status !== 'compromised' &&
            isPublishedAt(record, at)
        )
        .map(publicJwkOf);
      return Object.freeze({ keys: Object.freeze(keys) });
    },
  } satisfies Signer);
}

/**
 * The request's own fields, refusing any field the operation does not take.
 * A caller cannot slip in a `kid`, an `iss` or a header this way.
 */
function readRequest<F extends string>(
  request: unknown,
  allowed: readonly F[]
): Partial<Record<F, unknown>> {
  if (typeof request !== 'object' || request === null || Array.isArray(request)) {
    throw new SignerRequestRefusedError('UNEXPECTED_FIELD', 'A signer request is an object');
  }
  for (const field of Object.keys(request)) {
    if (!(allowed as readonly string[]).includes(field)) {
      throw new SignerRequestRefusedError(
        'UNEXPECTED_FIELD',
        `The request field '${field.slice(0, 64)}' is not one this operation takes`
      );
    }
  }
  return request as Partial<Record<F, unknown>>;
}

/** The realm id in lowercase, the form the store keeps and the key's associated data binds. */
function resolveRealmId(realmId: unknown): string {
  if (!isRealmId(realmId)) {
    throw new SignerRequestRefusedError('INVALID_REALM_ID', 'A realm id is a UUID');
  }
  return realmId.toLowerCase();
}

/** A subscription or provider id: the scope id of its keys, as the key factory stores it. */
function resolveScope(scopeId: unknown, name: string): string {
  if (!isScopeId(scopeId)) {
    throw new SignerRequestRefusedError(
      'INVALID_SCOPE_ID',
      `A ${name} is a non-empty, well-formed string of at most ${MAX_SCOPE_ID_LENGTH} characters`
    );
  }
  return scopeId;
}

/** A webhook body as the bytes that are sent: bytes as given, text as UTF-8. */
function resolveWebhookBody(body: unknown): Uint8Array {
  if (body instanceof Uint8Array) return body;
  // A lone surrogate would be sent as U+FFFD: what is signed would not be
  // what the caller meant to send.
  if (typeof body === 'string' && Buffer.from(body, 'utf8').toString('utf8') === body) {
    return Buffer.from(body, 'utf8');
  }
  throw new SignerRequestRefusedError(
    'INVALID_BODY',
    'A webhook body is a byte array or well-formed text'
  );
}

function resolveTyp(purpose: JwsSigningPurpose, typ: unknown): JwsTyp {
  if (!isTypAllowed(purpose, typ)) {
    throw new SignerRequestRefusedError(
      'TYP_NOT_ALLOWED',
      `Key purpose '${purpose}' does not sign the requested typ`
    );
  }
  return typ;
}

/** A purpose in a message: named when it is one, never echoed when it is not. */
function describePurpose(purpose: unknown): string {
  return typeof purpose === 'string' && Object.hasOwn(KEY_PURPOSES, purpose)
    ? `Key purpose '${purpose}'`
    : 'An unknown key purpose';
}

/**
 * The claims as plain JSON data, refusing the claims the signer sets: `iss`,
 * and for a client assertion `sub` and `aud` too.
 *
 * The claims are serialized and parsed once, so what the signer checks is what
 * it signs: a `toJSON` method could otherwise turn checked claims into
 * different ones, an `iss` among them, at signing time.
 */
function resolveClaims(
  claims: unknown,
  reserved: readonly string[] = ['iss']
): Record<string, unknown> {
  const setsReserved = (value: object) => reserved.some((claim) => Object.hasOwn(value, claim));
  if (
    typeof claims !== 'object' ||
    claims === null ||
    Array.isArray(claims) ||
    setsReserved(claims)
  ) {
    throw claimsRefusal(claims, reserved);
  }
  let normalized: unknown;
  try {
    normalized = JSON.parse(JSON.stringify(claims));
  } catch {
    // The serializer's message is dropped: it may quote a claim.
    throw claimsRefusal(claims, reserved);
  }
  if (
    typeof normalized !== 'object' ||
    normalized === null ||
    Array.isArray(normalized) ||
    setsReserved(normalized)
  ) {
    throw claimsRefusal(normalized, reserved);
  }
  return normalized as Record<string, unknown>;
}

function claimsRefusal(claims: unknown, reserved: readonly string[]): SignerRequestRefusedError {
  const set =
    typeof claims === 'object' && claims !== null
      ? reserved.find((claim) => Object.hasOwn(claims, claim))
      : undefined;
  if (set === 'iss' && reserved.length === 1) {
    return new SignerRequestRefusedError(
      'RESERVED_CLAIM',
      "The claims set 'iss'; the signer sets it from the realm row"
    );
  }
  if (set !== undefined) {
    return new SignerRequestRefusedError(
      'RESERVED_CLAIM',
      `The claims set '${set}'; the signer sets ${reserved.join(', ')}`
    );
  }
  return new SignerRequestRefusedError('INVALID_CLAIMS', 'The claims are not a JSON object');
}

/**
 * A copy of `bytes` in memory of its own. `Buffer.from` would place a small
 * copy in Node's shared allocation pool, where its `.buffer` reaches the
 * bytes of other buffers, a cached secret among them.
 */
function ownCopy(bytes: Uint8Array): Buffer {
  const copy = Buffer.alloc(bytes.length);
  copy.set(bytes);
  return copy;
}

/** Whether two key lists name the same keys with the same statuses. */
function sameKeys(a: readonly SignerKeyRecord[], b: readonly SignerKeyRecord[]): boolean {
  const describe = (keys: readonly SignerKeyRecord[]) =>
    keys
      .map((key) => `${key.kid}\u0000${key.status}`)
      .sort()
      .join('\u0001');
  return describe(a) === describe(b);
}

/** Newest retirement first; a key without a retirement time, then the newest key, last. */
function byMostRecentlyRetired(a: SignerKeyRecord, b: SignerKeyRecord): number {
  return (b.retireAt ?? -1) - (a.retireAt ?? -1) || b.createdAt - a.createdAt;
}

/** Whether a published key is inside its publication window at `at`. */
function isPublishedAt(record: PublicKeyRecord, at: number): boolean {
  return record.publishAt <= at && (record.unpublishAt === null || at < record.unpublishAt);
}

/** A fixed order, so every node serves the same JWKS: purpose, then publication, then `kid`. */
function sortForPublication(records: readonly PublicKeyRecord[]): PublicKeyRecord[] {
  const rank = (purpose: string) => {
    const index = (REALM_JWKS_PURPOSES as readonly string[]).indexOf(purpose);
    return index === -1 ? Number.MAX_SAFE_INTEGER : index;
  };
  return [...records].sort(
    (a, b) =>
      rank(a.purpose) - rank(b.purpose) ||
      a.publishAt - b.publishAt ||
      (a.kid < b.kid ? -1 : a.kid > b.kid ? 1 : 0)
  );
}

/**
 * A frozen copy of a published key's JWK, carrying the row's `kid`. A JWK with
 * a private member is refused rather than served; the `realm_public_keys`
 * CHECK makes one impossible to store.
 */
function publicJwkOf(record: PublicKeyRecord): JWK {
  const jwk = structuredClone(record.publicJwk) as JWK;
  if (PRIVATE_JWK_MEMBERS.some((member) => Object.hasOwn(jwk, member))) {
    throw new Error(`The published key '${record.kid}' carries a private member`);
  }
  return deepFreeze({ ...jwk, kid: record.kid });
}

function deepFreeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null) {
    for (const member of Object.values(value)) deepFreeze(member);
    Object.freeze(value);
  }
  return value;
}
