import type { JWK } from 'jose';

import { BoundedCache } from './bounded-cache';
import { KEY_PURPOSES } from './key-purposes';
import { isRealmId } from './realm-id';
import type { RealmJwks, Signer, VerificationKey } from './signer';
import { SignerAccessDeniedError, SignerRequestRefusedError } from './signer-errors';
import type { PublicKeyRecord, SignerKeyStore } from './signer-key-store';
import { isSignerCallAllowed, isSignerCaller } from './signer-policy';
import { isJwsSigningPurpose, REALM_JWKS_PURPOSES } from './signer-typ';

/**
 * A realm's published keys (`realm_public_keys`), read without a KEK
 * (ADR-019 Decisions 8 and 9, #491, #495).
 *
 * The published keys are public material: the `realm_public_keys` CHECK keeps
 * every private JWK member out, and every role's database user may read the
 * table, while only the signer's reads `realm_keys`. So a process without the
 * signer role lists a realm's verification keys and JWKS from them, as the
 * in-process signer does, and verifies the realm's tokens without holding a
 * KEK or a key. Both build their answers with {@link verificationKeysOf} and
 * {@link realmJwksOf}, so a token verifies the same on every process.
 */

/** The default time a published-key list is trusted before the store is asked again, in ms. */
export const DEFAULT_PUBLISHED_KEY_REFRESH_INTERVAL_MS = 60_000;

/** The default number of realms whose published keys are kept. */
export const DEFAULT_PUBLISHED_KEY_CACHE_SIZE = 256;

/**
 * The private members of every JWK key type (RFC 7518 §6, RFC 8037 §2,
 * RFC 9964), as the `realm_public_keys` CHECK lists them.
 */
export const PRIVATE_JWK_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k', 'priv'] as const;

/** Whether a published key is inside its publication window at `at`. */
export function isPublishedAt(record: PublicKeyRecord, at: number): boolean {
  return record.publishAt <= at && (record.unpublishAt === null || at < record.unpublishAt);
}

/** A fixed order, so every node serves the same JWKS: purpose, then publication, then `kid`. */
export function sortForPublication(records: readonly PublicKeyRecord[]): PublicKeyRecord[] {
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
export function publicJwkOf(record: PublicKeyRecord): JWK {
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

/**
 * The keys of `purpose` that may verify at `at`: published, inside their
 * window, and active or retired, in publication order.
 */
export function verificationKeysOf(
  records: readonly PublicKeyRecord[],
  purpose: string,
  at: number
): readonly VerificationKey[] {
  const keys: VerificationKey[] = [];
  for (const record of sortForPublication(records)) {
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
}

/** The realm's JWKS at `at`: its published token keys inside their window, none compromised. */
export function realmJwksOf(records: readonly PublicKeyRecord[], at: number): RealmJwks {
  const keys = sortForPublication(records)
    .filter(
      (record) =>
        (REALM_JWKS_PURPOSES as readonly string[]).includes(record.purpose) &&
        record.status !== 'compromised' &&
        isPublishedAt(record, at)
    )
    .map(publicJwkOf);
  return Object.freeze({ keys: Object.freeze(keys) });
}

/** A purpose for a refusal, never echoing one that is not a key purpose. */
export function describePurpose(purpose: unknown): string {
  return typeof purpose === 'string' && Object.hasOwn(KEY_PURPOSES, purpose)
    ? `Key purpose '${purpose}'`
    : 'An unknown key purpose';
}

/**
 * The members that identify a public key, whatever else its JWK carries
 * (`kid`, `use`, `alg` on a classical key): the key type and its public value,
 * RFC 7638's required members. `undefined` for a JWK of no key type here.
 */
export function publicKeyIdentity(
  jwk: Readonly<Record<string, unknown>>
): Readonly<Record<string, string>> | undefined {
  const members: Readonly<Record<string, readonly string[]>> = {
    OKP: ['kty', 'crv', 'x'],
    EC: ['kty', 'crv', 'x', 'y'],
    RSA: ['kty', 'n', 'e'],
    AKP: ['kty', 'alg', 'pub'],
  };
  const names = typeof jwk['kty'] === 'string' ? members[jwk['kty']] : undefined;
  if (names === undefined) return undefined;
  const identity: Record<string, string> = {};
  for (const name of names) {
    const value = jwk[name];
    if (typeof value !== 'string' || value.length === 0) return undefined;
    identity[name] = value;
  }
  return Object.freeze(identity);
}

/** The realm id a caller named, lower-cased, or a refusal. */
export function resolveRealmId(realmId: unknown): string {
  if (!isRealmId(realmId)) {
    throw new SignerRequestRefusedError('INVALID_REALM_ID', 'A realm id is a UUID');
  }
  return realmId.toLowerCase();
}

/** What {@link createPublishedKeyReader} reads: the published keys alone. */
export type PublishedKeyStore = Pick<SignerKeyStore, 'listPublicKeys'>;

/** The signer's two public reads, answered from the published keys. */
export type PublishedKeyReader = Pick<Signer, 'getVerificationKeys' | 'getJwks'>;

/** Options of {@link createPublishedKeyReader}. */
export interface PublishedKeyReaderOptions {
  /** How long a realm's list is trusted, in ms. {@link DEFAULT_PUBLISHED_KEY_REFRESH_INTERVAL_MS}. */
  readonly refreshIntervalMs?: number;
  /** The most realms whose lists are kept. {@link DEFAULT_PUBLISHED_KEY_CACHE_SIZE}. */
  readonly cacheSize?: number;
  /** The clock, in epoch ms. */
  readonly now?: () => number;
}

/**
 * Read a realm's verification keys and JWKS from its published keys, without
 * a KEK (#495): the signer's `getVerificationKeys` and `getJwks` for a process
 * that does not hold the signer role. Each realm's list is read at most once
 * per refresh interval, as the in-process signer reads it, so a key the signer
 * starts to sign with reaches this process within one interval of its
 * publication, which precedes its activation.
 *
 * It holds and returns public material only.
 */
export function createPublishedKeyReader(
  store: PublishedKeyStore,
  options: PublishedKeyReaderOptions = {}
): PublishedKeyReader {
  const now = options.now ?? Date.now;
  const refreshIntervalMs = options.refreshIntervalMs ?? DEFAULT_PUBLISHED_KEY_REFRESH_INTERVAL_MS;
  const lists = new BoundedCache<string, { value: readonly PublicKeyRecord[]; readAt: number }>(
    options.cacheSize ?? DEFAULT_PUBLISHED_KEY_CACHE_SIZE
  );
  const pending = new Map<string, Promise<readonly PublicKeyRecord[]>>();

  function authorize(caller: unknown, operation: 'getVerificationKeys' | 'getJwks'): void {
    if (!isSignerCallAllowed(caller, operation)) {
      throw new SignerAccessDeniedError(isSignerCaller(caller) ? caller : undefined, operation);
    }
  }

  function listPublicKeys(realmId: string): Promise<readonly PublicKeyRecord[]> {
    const cached = lists.get(realmId);
    if (cached !== undefined && now() - cached.readAt < refreshIntervalMs) {
      return Promise.resolve(cached.value);
    }
    let read = pending.get(realmId);
    if (read === undefined) {
      const readAt = now();
      read = store
        .listPublicKeys(realmId)
        .then((records) => {
          const value = Object.freeze([...records]);
          lists.set(realmId, { value, readAt });
          return value;
        })
        .finally(() => pending.delete(realmId));
      pending.set(realmId, read);
    }
    return read;
  }

  return Object.freeze({
    async getVerificationKeys(caller, realmIdInput, purpose) {
      if (!isJwsSigningPurpose(purpose)) {
        throw new SignerRequestRefusedError(
          'PURPOSE_NOT_ALLOWED',
          `${describePurpose(purpose)} has no verification keys`
        );
      }
      authorize(caller, 'getVerificationKeys');
      const realmId = resolveRealmId(realmIdInput);
      return verificationKeysOf(await listPublicKeys(realmId), purpose, now());
    },
    async getJwks(caller, realmIdInput) {
      authorize(caller, 'getJwks');
      const realmId = resolveRealmId(realmIdInput);
      return realmJwksOf(await listPublicKeys(realmId), now());
    },
  } satisfies PublishedKeyReader);
}
