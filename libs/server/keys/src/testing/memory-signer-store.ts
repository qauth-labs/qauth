import type { StoredKeyStatus } from '../lib/key-store';
import type {
  PublicKeyRecord,
  SignerKeyRecord,
  SignerKeyStore,
  WrappedSignerKey,
} from '../lib/signer-key-store';
import type { MemoryKeyStore } from './memory-key-store';

/**
 * A {@link SignerKeyStore} over the rows of a {@link MemoryKeyStore}, for this
 * library's unit tests. Never exported from the package entry point.
 *
 * The key factory writes the rows; this store reads them as the signer's
 * wiring reads `realm_keys` and `realm_public_keys`. {@link update} changes a
 * key's status and times, as a rotation would.
 */

/** The lifecycle columns a test can change on a stored key. */
export interface KeyLifecycle {
  readonly status?: StoredKeyStatus;
  readonly retireAt?: number | null;
  readonly publishAt?: number;
  readonly unpublishAt?: number | null;
}

export interface MemorySignerStore extends SignerKeyStore {
  /** Every call, in order, by method name. */
  readonly calls: string[];
  /** Each realm's issuer. A realm missing here does not exist. */
  readonly issuers: Map<string, string | null>;
  /** Change a stored key's status and times. */
  update(realmId: string, kid: string, changes: KeyLifecycle): void;
  /** Replace a stored key's sealed bytes, as tampering or corruption would. */
  replaceSealed(realmId: string, kid: string, sealed: Partial<WrappedSignerKey>): void;
}

export function createMemorySignerStore(
  keys: MemoryKeyStore,
  issuers: Record<string, string | null> = {}
): MemorySignerStore {
  const calls: string[] = [];
  const lifecycle = new Map<string, KeyLifecycle>();
  const sealedOverrides = new Map<string, Partial<WrappedSignerKey>>();
  const issuerMap = new Map(Object.entries(issuers));
  const id = (realmId: string, kid: string) => `${realmId}/${kid}`;

  function rowsOf(realmId: string) {
    return keys.rows
      .map((row, index) => ({ row, index }))
      .filter(({ row }) => row.key.realmId === realmId);
  }

  return {
    calls,
    issuers: issuerMap,

    update(realmId, kid, changes) {
      lifecycle.set(id(realmId, kid), { ...lifecycle.get(id(realmId, kid)), ...changes });
    },

    replaceSealed(realmId, kid, sealed) {
      sealedOverrides.set(id(realmId, kid), sealed);
    },

    async findRealmIssuer(realmId) {
      calls.push('findRealmIssuer');
      return issuerMap.has(realmId) ? issuerMap.get(realmId) : undefined;
    },

    async listKeys(realmId, filter): Promise<readonly SignerKeyRecord[]> {
      calls.push('listKeys');
      return rowsOf(realmId)
        .filter(({ row }) => row.key.purpose === filter.purpose)
        .filter(({ row }) => row.key.scopeId === filter.scopeId)
        .map(({ row, index }) => {
          const changes = lifecycle.get(id(realmId, row.key.kid)) ?? {};
          return {
            kid: row.key.kid,
            algorithm: row.key.algorithm,
            status: changes.status ?? row.key.status,
            pairId: row.key.pairId,
            retireAt: changes.retireAt ?? row.key.retireAt ?? null,
            createdAt: index,
          };
        });
    },

    async getWrappedKey(realmId, kid): Promise<WrappedSignerKey | undefined> {
      calls.push('getWrappedKey');
      const found = rowsOf(realmId).find(({ row }) => row.key.kid === kid);
      if (found === undefined) return undefined;
      const { key } = found.row;
      return {
        realmId: key.realmId,
        purpose: key.purpose,
        scopeId: key.scopeId,
        kid: key.kid,
        algorithm: key.algorithm,
        status: lifecycle.get(id(realmId, kid))?.status ?? key.status,
        ciphertext: key.ciphertext,
        iv: key.iv,
        wrappedDek: key.wrappedDek,
        kekRef: key.kekRef,
        aadVersion: key.aadVersion,
        ...sealedOverrides.get(id(realmId, kid)),
      };
    },

    async listPublicKeys(realmId): Promise<readonly PublicKeyRecord[]> {
      calls.push('listPublicKeys');
      return rowsOf(realmId)
        .filter(({ row }) => row.publicJwk !== undefined && row.key.publishAt !== null)
        .map(({ row }) => {
          const changes = lifecycle.get(id(realmId, row.key.kid)) ?? {};
          return {
            kid: row.key.kid,
            purpose: row.key.purpose,
            algorithm: row.key.algorithm,
            status: changes.status ?? row.key.status,
            publicJwk: row.publicJwk as Record<string, unknown>,
            publishAt: changes.publishAt ?? (row.key.publishAt as number),
            unpublishAt: changes.unpublishAt ?? row.key.unpublishAt ?? null,
          };
        });
    },
  };
}
