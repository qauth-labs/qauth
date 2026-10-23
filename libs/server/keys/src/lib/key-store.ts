/**
 * The storage the key factory writes through (issue #463).
 *
 * This library may import only the core and shared layers (its
 * `type:key-custody` tag), so it cannot import `@qauth-labs/infra-db`. It
 * names what it needs instead, in the shape of the realm keys repository
 * (#461), and the signer's wiring hands it the repository:
 *
 * ```typescript
 * const store: RealmKeyStore<DbClient> = {
 *   transaction: (work, outer) => (outer ?? db).transaction(work),
 *   findByKid: repositories.realmKeys.findByKid,
 *   listByRealm: repositories.realmKeys.listByRealm,
 *   create: repositories.realmKeys.create,
 *   updateStatus: repositories.realmKeys.updateStatus,
 *   deleteByScope: repositories.realmKeys.deleteByScope,
 * };
 * ```
 *
 * The column names and types are those of `realm_keys`; the repository's
 * `create` writes the key row and its `realm_public_keys` row in one
 * transaction.
 */

/** Every status a stored key can have (`realm_key_status`). */
export type StoredKeyStatus = 'next' | 'active' | 'retired' | 'compromised';

/**
 * The status a new key gets: `active` signs or encrypts at once; `next` is
 * created ahead of a rotation and, when its purpose is published, published
 * before it signs.
 */
export type NewKeyStatus = Extract<StoredKeyStatus, 'active' | 'next'>;

/** A new `realm_keys` row. Its material is sealed; nothing in it is plaintext. */
export interface NewStoredKeyRow {
  readonly realmId: string;
  readonly purpose: string;
  readonly scopeId: string | null;
  readonly algorithm: string;
  readonly kid: string;
  readonly status: NewKeyStatus;
  /** Shared by both keys of a hybrid pair; `null` outside a pair. */
  readonly pairId: string | null;
  readonly ciphertext: Buffer;
  readonly iv: Buffer;
  readonly wrappedDek: Buffer;
  readonly kekRef: string;
  readonly aadVersion: number;
  /** Epoch ms. Set for a published purpose; `null` for one that is never published. */
  readonly publishAt: number | null;
  /** Epoch ms. Set for an `active` key; `null` for a `next` key, which rotation activates. */
  readonly activateAt: number | null;
  /** Epoch ms, from the factory's clock like the other times. */
  readonly createdAt: number;
}

/**
 * What {@link RealmKeyStore.create} writes: the key row, plus the public JWK
 * of a published key. The public row copies the key row's `realmId`, `kid`,
 * `purpose`, `algorithm`, `status`, `publishAt` and `unpublishAt`.
 */
export type NewStoredKey =
  | {
      readonly key: NewStoredKeyRow & { readonly publishAt: number };
      readonly publicJwk: Record<string, unknown>;
    }
  | { readonly key: NewStoredKeyRow; readonly publicJwk?: undefined };

/** Which keys {@link RealmKeyStore.listByRealm} returns. `scopeId: null` means unscoped keys only. */
export interface StoredKeyFilter {
  readonly purpose?: string;
  readonly scopeId?: string | null;
  readonly status?: StoredKeyStatus;
}

/** The columns of a stored key the factory reads back. */
export interface StoredKeySummary {
  readonly kid: string;
  readonly algorithm: string;
  readonly status: StoredKeyStatus;
  /** Epoch ms; `null` for a purpose that is never published. */
  readonly publishAt: number | null;
  /** Epoch ms. */
  readonly createdAt: number;
}

/**
 * One rotation step (#547): a `next` key becomes `active`, or an `active` key
 * becomes `retired`. A retired key that is published leaves its JWKS at
 * `unpublishAt`; an unpublished one passes `null`.
 */
export type StoredKeyStatusChange =
  | { readonly status: 'active'; readonly activateAt: number }
  | { readonly status: 'retired'; readonly retireAt: number; readonly unpublishAt: number | null };

/**
 * The key storage the factory needs. `Tx` is the store's transaction handle,
 * such as a Drizzle `DbClient`.
 */
export interface RealmKeyStore<Tx> {
  /**
   * Run `work` in one transaction: everything it writes is kept, or nothing
   * is. With `outer`, run it inside that transaction (a savepoint), so a
   * caller can create a realm and its keys together.
   */
  transaction<T>(work: (tx: Tx) => Promise<T>, outer?: Tx): Promise<T>;
  /** The key with `kid` in the realm, or `undefined`. Any status counts. */
  findByKid(realmId: string, kid: string, tx: Tx): Promise<object | undefined>;
  /** The realm's keys that match `filter`. */
  listByRealm(
    realmId: string,
    filter: StoredKeyFilter,
    tx: Tx
  ): Promise<readonly StoredKeySummary[]>;
  /** Write a key row and, when `publicJwk` is given, its public row. */
  create(input: NewStoredKey, tx: Tx): Promise<unknown>;
  /**
   * Move the key with `kid` one rotation step, and its public row with it.
   * Only a key in the status the step starts from moves (`next` to activate,
   * `active` to retire).
   *
   * @returns the moved key, or `undefined` when no key was in that status.
   */
  updateStatus(
    realmId: string,
    kid: string,
    change: StoredKeyStatusChange,
    tx: Tx
  ): Promise<object | undefined>;
  /**
   * Delete every key of one realm, purpose and scope, with their public rows.
   *
   * @returns the `kid`s it deleted.
   */
  deleteByScope(
    realmId: string,
    purpose: string,
    scopeId: string,
    tx: Tx
  ): Promise<readonly string[]>;
}
