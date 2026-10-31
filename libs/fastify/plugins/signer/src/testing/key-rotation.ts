import { DEFAULT_KEY_RETIRED_RETENTION_DAYS } from '@qauth-labs/server-keys';
import type { KeyFactory, RealmKeyBootStore } from '@qauth-labs/server-keys/custody';

/**
 * TEST SUPPORT: one rotation of a realm's `token_signing` keys, the step the
 * rotation job (#542) and manual rotation (#544) will take, for tests that
 * check what a rotation leaves verifiable (issue #492), and its first half,
 * the publication of the `next` key before it signs (#494). Never exported
 * from the package entry point.
 *
 * A rotation activates the realm's `next` key of the algorithm: one
 * {@link prepublishTokenKeys} published earlier, or else a new one it creates
 * as `next` itself. The realm's active key of the algorithm moves from
 * `active` to `retired`, and the `next` key becomes `active`, in one
 * transaction under the realm's key lock. With hybrid signing on, an EdDSA
 * rotation brings a new ML-DSA-65 key with it, and both keys of the old pair
 * retire together (ADR-005). The retired keys stay published, and so in the
 * realm's verification set, until `unpublishAt`: their retention.
 *
 * It does not wait between publishing the `next` key and activating it, as a
 * real rotation does (ADR-019, 7 days by default): a test that needs a relying
 * party to see the key first pre-publishes it and reads the JWKS itself.
 */

const DAY_MS = 86_400_000;

/** What to rotate, and how long the retired keys stay published. */
export interface TokenKeyRotationOptions {
  /**
   * The algorithm to rotate: `EdDSA` by default, with its ML-DSA-65 partner
   * when hybrid signing is on, or `RS256`.
   */
  readonly algorithm?: 'EdDSA' | 'RS256';
  /**
   * How long a retired key stays published after the switch, in ms: 14 days
   * by default (`DEFAULT_KEY_RETIRED_RETENTION_DAYS`). `0` ends its retention
   * at the switch, as if the retention had already run out.
   */
  readonly retiredRetentionMs?: number;
}

/** A key a rotation moved. */
export interface RotatedTokenKey {
  readonly kid: string;
  readonly algorithm: string;
}

/** What to pre-publish. */
export interface TokenKeyPrepublicationOptions {
  /**
   * The algorithm of the `next` key: `EdDSA` by default, with its ML-DSA-65
   * partner when hybrid signing is on, or `RS256`.
   */
  readonly algorithm?: 'EdDSA' | 'RS256';
}

/** What one pre-publication created. */
export interface TokenKeyPrepublication {
  /**
   * The `next` keys, published and signing nothing yet: the requested one,
   * then its hybrid partner.
   */
  readonly prepublished: readonly RotatedTokenKey[];
}

/** What one rotation changed. */
export interface TokenKeyRotation {
  /** The keys that sign from now on: the requested one, then its hybrid partner. */
  readonly activated: readonly RotatedTokenKey[];
  /** The keys that stopped signing, with the end of their retention (epoch ms). */
  readonly retired: readonly (RotatedTokenKey & { readonly unpublishAt: number })[];
  /** Epoch ms. When the switch happened. */
  readonly at: number;
}

/**
 * The realm's `next` `token_signing` keys of `algorithm`, with their hybrid
 * partners: the requested algorithm first. Empty when it has none.
 */
async function nextTokenKeys<Tx>(
  store: RealmKeyBootStore<Tx>,
  realmId: string,
  algorithm: string,
  tx: Tx
): Promise<RotatedTokenKey[]> {
  const next = await store.listByRealm(
    realmId,
    { purpose: 'token_signing', scopeId: null, status: 'next' },
    tx
  );
  const requested = next.filter((key) => key.algorithm === algorithm);
  const pairs = new Set(requested.map((key) => key.pairId).filter((pairId) => pairId !== null));
  const partners = next.filter(
    (key) => key.algorithm !== algorithm && key.pairId !== null && pairs.has(key.pairId)
  );
  return [...requested, ...partners].map(({ kid, algorithm: keyAlgorithm }) => ({
    kid,
    algorithm: keyAlgorithm,
  }));
}

/**
 * Publish a new `next` `token_signing` key of one algorithm in the realm,
 * through `store`, creating it with `factory`: the first half of a rotation.
 * The key is in the realm's JWKS from now on and signs nothing until
 * {@link rotateTokenKeys} activates it. With hybrid signing on, an EdDSA key
 * comes with its ML-DSA-65 partner.
 *
 * A signer reads key lists at most once per refresh interval, so one that
 * read the realm's keys before sees the new key only after that interval.
 *
 * @throws Error when the realm already has a `next` key of the algorithm;
 *   nothing changes then
 */
export async function prepublishTokenKeys<Tx>(
  store: RealmKeyBootStore<Tx>,
  factory: KeyFactory<Tx>,
  realmId: string,
  options: TokenKeyPrepublicationOptions = {}
): Promise<TokenKeyPrepublication> {
  const algorithm = options.algorithm ?? 'EdDSA';
  return store.transaction(async (tx) => {
    await store.lockRealm(realmId, tx);
    if ((await nextTokenKeys(store, realmId, algorithm, tx)).length > 0) {
      throw new Error(`The realm already has a next ${algorithm} key`);
    }
    const created = await factory.createKey({
      realmId,
      purpose: 'token_signing',
      algorithm,
      status: 'next',
      tx,
    });
    return Object.freeze({
      prepublished: Object.freeze(
        created.map(({ kid, algorithm: keyAlgorithm }) =>
          Object.freeze({ kid, algorithm: keyAlgorithm })
        )
      ),
    });
  });
}

/**
 * Rotate the realm's `token_signing` keys of one algorithm through `store`:
 * activate its `next` keys of the algorithm, or new ones created with
 * `factory` when it has none.
 *
 * A signer reads key lists at most once per refresh interval, so one that
 * read the realm's keys before the rotation sees it only after that interval:
 * a test reads with a signer whose interval is `0`, or one created after the
 * rotation.
 *
 * @throws Error when a key moved meanwhile; nothing changes then
 */
export async function rotateTokenKeys<Tx>(
  store: RealmKeyBootStore<Tx>,
  factory: KeyFactory<Tx>,
  realmId: string,
  options: TokenKeyRotationOptions = {}
): Promise<TokenKeyRotation> {
  const algorithm = options.algorithm ?? 'EdDSA';
  const retentionMs = options.retiredRetentionMs ?? DEFAULT_KEY_RETIRED_RETENTION_DAYS * DAY_MS;
  return store.transaction(async (tx) => {
    await store.lockRealm(realmId, tx);
    const prepublished = await nextTokenKeys(store, realmId, algorithm, tx);
    const created: readonly RotatedTokenKey[] =
      prepublished.length > 0
        ? prepublished
        : await factory.createKey({
            realmId,
            purpose: 'token_signing',
            algorithm,
            status: 'next',
            tx,
          });
    const algorithms = new Set<string>(created.map((key) => key.algorithm));
    const active = (
      await store.listByRealm(
        realmId,
        { purpose: 'token_signing', scopeId: null, status: 'active' },
        tx
      )
    ).filter((key) => algorithms.has(key.algorithm));

    const at = Date.now();
    const unpublishAt = at + retentionMs;
    // Retire first: the one-active-key index allows no moment with two.
    for (const key of active) {
      const moved = await store.updateStatus(
        realmId,
        key.kid,
        { status: 'retired', retireAt: at, unpublishAt },
        tx
      );
      if (moved === undefined) throw new Error(`The key ${key.kid} moved during the rotation`);
    }
    for (const key of created) {
      const moved = await store.updateStatus(
        realmId,
        key.kid,
        { status: 'active', activateAt: at },
        tx
      );
      if (moved === undefined) throw new Error(`The key ${key.kid} moved during the rotation`);
    }

    return Object.freeze({
      activated: Object.freeze(
        created.map(({ kid, algorithm: keyAlgorithm }) =>
          Object.freeze({ kid, algorithm: keyAlgorithm })
        )
      ),
      retired: Object.freeze(
        active.map(({ kid, algorithm: keyAlgorithm }) =>
          Object.freeze({ kid, algorithm: keyAlgorithm, unpublishAt })
        )
      ),
      at,
    });
  });
}
