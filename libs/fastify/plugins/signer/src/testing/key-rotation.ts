import { DEFAULT_KEY_RETIRED_RETENTION_DAYS } from '@qauth-labs/server-keys';
import type { KeyFactory, RealmKeyBootStore } from '@qauth-labs/server-keys/custody';

/**
 * TEST SUPPORT: one rotation of a realm's `token_signing` keys, the step the
 * rotation job (#542) and manual rotation (#544) will take, for tests that
 * check what a rotation leaves verifiable (issue #492). Never exported from
 * the package entry point.
 *
 * A new key is created as `next`, the realm's active key of its algorithm
 * moves from `active` to `retired`, and the new key becomes `active`, in one
 * transaction under the realm's key lock. With hybrid signing on, an EdDSA
 * rotation brings a new ML-DSA-65 key with it, and both keys of the old pair
 * retire together (ADR-005). The retired keys stay published, and so in the
 * realm's verification set, until `unpublishAt`: their retention.
 *
 * It skips the wait a real rotation makes between publishing the `next` key
 * and activating it (ADR-019, 7 days by default): a test has no relying party
 * whose cache needs it.
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
 * Rotate the realm's `token_signing` keys of one algorithm through `store`,
 * creating the new keys with `factory`.
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
    const created = await factory.createKey({
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
