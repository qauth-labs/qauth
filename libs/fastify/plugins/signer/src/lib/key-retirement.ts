import type { SignatureAlgorithm } from '@qauth-labs/core-crypto';
import type { DbClient } from '@qauth-labs/infra-db';
import {
  createKeyRotation,
  type KekEnv,
  type KekWarning,
  type KeyRetirementRecord,
  loadKekProvider,
  type RetireNowInput,
} from '@qauth-labs/server-keys/custody';

import { createRepositoryKeyStore } from './repository-key-stores';

/**
 * THE EMERGENCY KEY RETIREMENT over the database repositories, for a process
 * that holds no signer (ADR-019 Decisions 7 and 9, issue #551): the
 * break-glass command `auth-server:keys:retire`, on a host that holds the
 * database credentials and the KEK.
 *
 * It needs the KEK, as it creates the key that signs in place of the one it
 * retires, so it lives in the signer's wiring, which loads the KEK provider
 * from the environment it is given. A signer node retires through
 * `fastify.keyRotation.retireNow` instead.
 */

/** What the retirement works with: it loads the KEK provider itself. */
export interface KeyRetirementDependencies {
  readonly db: DbClient;
  /** The KEK provider's settings (`KEK_PROVIDER`, `KEK`, …, `NODE_ENV`). */
  readonly kekEnv: KekEnv;
  /** Receives the KEK provider's warnings, such as the development KEK fallback. */
  readonly warn: (warning: KekWarning) => void;
  /** `cryptoEnv.enabledSignatureAlgorithms`, which the new key's algorithm must be one of. */
  readonly enabledSignatureAlgorithms: readonly SignatureAlgorithm[];
  /** `HYBRID_SIGNING_ENABLED`: the new EdDSA key comes with its ML-DSA-65 companion. */
  readonly hybridSigning: boolean;
}

/**
 * Retire a `token_signing` key now, under the approval, and create its
 * replacement. See `KeyRotation.retireNow` of `@qauth-labs/server-keys`.
 *
 * @throws the errors of `loadKekProvider` and of `KeyRotation.retireNow`
 */
export async function retireKey(
  deps: KeyRetirementDependencies,
  input: RetireNowInput<DbClient>
): Promise<KeyRetirementRecord> {
  const kekProvider = await loadKekProvider({ env: deps.kekEnv, warn: deps.warn });
  try {
    return await createKeyRotation({
      store: createRepositoryKeyStore(deps.db),
      kekProvider,
      enabledSignatureAlgorithms: deps.enabledSignatureAlgorithms,
      hybridSigning: deps.hybridSigning,
    }).retireNow(input);
  } finally {
    await kekProvider.close?.();
  }
}
