import type { DbClient } from '@qauth-labs/infra-db';
import { KekUnavailableError } from '@qauth-labs/server-keys';
import {
  type KekEnv,
  type KekProvider,
  type KekWarning,
  loadKekProvider,
} from '@qauth-labs/server-keys/custody';

import { type KekCanaryStore, openKekCanaries } from './key-custody-check';
import { createRepositoryKekCanaryStore } from './repository-key-stores';

/**
 * THE BREAK-GLASS CLI'S START CHECK (ADR-019 Decision 7, issue #602): the
 * host it runs on holds the KEK.
 *
 * The CLI runs only on a host that holds the database credentials and the
 * KEK. The database credentials show when it connects; the KEK shows only
 * when it opens a stored key. So the check loads the KEK provider from the
 * environment, asks it whether it can be used, and unwraps one stored key per
 * KEK reference in use (the signer's readiness canaries, #500), zeroing each
 * at once. It needs at least one: a provider that reports itself usable but
 * has opened nothing has proved nothing, so a database that holds no key yet
 * is refused too, as the server's first boot creates the keys.
 */

/** What the check reads: the database, and the KEK provider's settings. */
export interface HostKeyCustodyDependencies {
  readonly db: DbClient;
  /** The KEK provider's settings (`KEK_PROVIDER`, `KEK`, …, `NODE_ENV`). */
  readonly kekEnv: KekEnv;
  /** Receives the KEK provider's warnings, such as the development KEK fallback. */
  readonly warn: (warning: KekWarning) => void;
}

/**
 * Resolve when the provider reports itself usable and opens every canary,
 * and at least one.
 *
 * @throws KekUnavailableError when the provider reports itself unusable, or
 *   when no stored key was there to open
 * @throws the provider's error for a canary it cannot open, as
 *   `checkKeyCustody` does
 */
export async function proveKeyCustody(
  kekProvider: KekProvider,
  store: KekCanaryStore
): Promise<void> {
  const opened = await openKekCanaries(kekProvider, store);
  if (opened === 0) {
    throw new KekUnavailableError({
      cause: new Error('the database holds no key the KEK opens, so the KEK is not proved'),
    });
  }
}

/**
 * {@link proveKeyCustody} with the provider `kekEnv` selects, over the
 * database's keys. The provider is closed before it returns.
 *
 * @throws the errors of `loadKekProvider` and of {@link proveKeyCustody}
 */
export async function proveHostKeyCustody(deps: HostKeyCustodyDependencies): Promise<void> {
  const kekProvider = await loadKekProvider({ env: deps.kekEnv, warn: deps.warn });
  try {
    await proveKeyCustody(kekProvider, createRepositoryKekCanaryStore(deps.db));
  } finally {
    await kekProvider.close?.();
  }
}
