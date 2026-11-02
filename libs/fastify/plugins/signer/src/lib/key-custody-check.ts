import { KekUnavailableError } from '@qauth-labs/server-keys';
import {
  type KekProvider,
  openKeyMaterial,
  type WrappedSignerKey,
} from '@qauth-labs/server-keys/custody';

/**
 * The signer's readiness check (#500): the KEK still opens what the store
 * holds.
 *
 * The in-process signer unwraps a key once and keeps it, so its signatures
 * say nothing about the KEK after the first: a KEK removed from the
 * configuration, a KMS key disabled or a policy that no longer grants this
 * role the unwrap shows only when a key not yet held is needed. The check
 * asks the provider whether it can be used, then unwraps one stored key per
 * KEK reference in use, the canaries the store names, and zeroes each at
 * once. Nothing is cached: each run unwraps afresh.
 */

/** The most canaries one run unwraps: one per KEK reference, so one or two in practice. */
export const KEK_CANARY_LIMIT = 8;

/** What the check reads: which keys to try, and each one's wrapped material. */
export interface KekCanaryStore {
  /** One key per KEK reference in use, newest first per reference; at most `limit`. */
  listKekCanaries(
    limit: number
  ): Promise<readonly { readonly realmId: string; readonly kid: string }[]>;
  /** A key's sealed row, as the signer reads it. */
  getWrappedKey(realmId: string, kid: string): Promise<WrappedSignerKey | undefined>;
}

/**
 * Resolve when the KEK provider reports itself usable and unwraps every
 * canary; with no key stored, the provider's report decides alone.
 *
 * @throws KekUnavailableError when the provider reports itself unusable
 * @throws the provider's error (`KeyDecryptionError`, `UnknownKekRefError`,
 *   `KekUnavailableError`, `KekAccessDeniedError`) for a canary it cannot open
 */
export async function checkKeyCustody(
  kekProvider: KekProvider,
  store: KekCanaryStore
): Promise<void> {
  const health = await kekProvider.health();
  if (!health.ok) {
    throw new KekUnavailableError({
      cause: new Error(`${health.provider}: ${health.reason ?? 'no reason given'}`),
    });
  }
  for (const canary of await store.listKekCanaries(KEK_CANARY_LIMIT)) {
    const sealed = await store.getWrappedKey(canary.realmId, canary.kid);
    // Deleted since it was listed: nothing to open.
    if (sealed === undefined) continue;
    const material = await openKeyMaterial(kekProvider, sealed, {
      realmId: sealed.realmId,
      purpose: sealed.purpose,
      scopeId: sealed.scopeId,
      kid: sealed.kid,
      algorithm: sealed.algorithm,
    });
    material.fill(0);
  }
}
