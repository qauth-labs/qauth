import type { SignatureAlgorithm } from '@qauth-labs/core-crypto';
import { createRealmKeysRepository, type DbClient } from '@qauth-labs/infra-db';
import { keySignedSince } from '@qauth-labs/server-keys';
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
 * from the environment it is given. A signer node can retire through
 * `fastify.keyRotation.retireNow`; no route does yet. The admin route that
 * will must run it under a database role that may also revoke the realm's
 * refresh tokens and write the admin audit log, which the signer's role may
 * not.
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

/** A key compromised already, as the break-glass command reads it to run again. */
export interface CompromisedKey {
  readonly algorithm: string;
  /**
   * Epoch ms. The earliest moment it may have signed (`keySignedSince`), or
   * `null` when that moment is after it was marked compromised: it never
   * signed. The status it had is gone: a key with no `activateAt` counts as
   * signing since it was made, so a run again revokes no less than the first.
   */
  readonly signedSince: number | null;
}

/**
 * The realm's `token_signing` key with `kid` when it is `compromised`, else
 * `undefined`: what the break-glass command reads to end the sessions of a
 * key retired already again. No key material is returned.
 */
export async function compromisedKeyOf(
  db: DbClient,
  realmId: string,
  kid: string
): Promise<CompromisedKey | undefined> {
  const key = await createRealmKeysRepository(db).findByKid(realmId, kid, db);
  if (key === undefined || key.status !== 'compromised' || key.purpose !== 'token_signing') {
    return undefined;
  }
  const signedSince = keySignedSince(key);
  return {
    algorithm: key.algorithm,
    signedSince: key.compromisedAt !== null && signedSince > key.compromisedAt ? null : signedSince,
  };
}
