import type { DbClient } from '@qauth-labs/infra-db';
import type { ApprovedOperation, KekRotateOperation } from '@qauth-labs/server-keys';
import {
  createKekRewrap,
  type KekEnv,
  type KekRefCensus,
  type KekRewrapProgress,
  KekRewrapRefusedError,
  type KekRewrapReport,
  type KekRotationRecord,
  type KekWarning,
  loadKekProvider,
} from '@qauth-labs/server-keys/custody';

import { createRepositoryKekRewrapStore } from './repository-key-stores';

/**
 * THE KEK ROTATION over the database repositories (ADR-019 Decision 9, issue
 * #545): re-wrap every stored key's data key from the old KEK to the new one,
 * and count the stored keys per KEK reference.
 *
 * It needs the KEK, so it lives in the signer's wiring, which loads the KEK
 * provider from the environment it is given: on a host that holds both KEKs,
 * the new one as the KEK it wraps under and the old one as one it still opens
 * (`KEK` and `KEK_PREVIOUS`, for the default provider). The operator command
 * `auth-server:keys:rewrap` calls it.
 */

/** What the KEK rotation works with: it loads the KEK provider itself. */
export interface KekRotationDependencies {
  readonly db: DbClient;
  /** The KEK provider's settings (`KEK_PROVIDER`, `KEK`, `KEK_PREVIOUS`, …, `NODE_ENV`). */
  readonly kekEnv: KekEnv;
  /** Receives the KEK provider's warnings, such as the development KEK fallback. */
  readonly warn: (warning: KekWarning) => void;
}

/** What to rotate, under which approval, and the hooks it calls. */
export interface RotateKekInput {
  /** The KEK reference to re-wrap from: the old KEK. */
  readonly from: string;
  /**
   * The KEK reference to re-wrap to. Absent: the KEK the provider wraps
   * under now, which the approval is then bound to.
   */
  readonly to?: string;
  /** The approval of exactly this rotation (`kek.rotate`). */
  readonly approval: ApprovedOperation<KekRotateOperation, DbClient>;
  /** The audit hook, called once in the transaction that consumes the approval. */
  readonly onAudit: (entry: KekRotationRecord, tx: DbClient) => Promise<void>;
  /** Called after each key's write. */
  readonly onKey?: (progress: KekRewrapProgress) => Promise<void> | void;
  /** Stops the run between two keys. */
  readonly signal?: AbortSignal;
}

/**
 * Re-wrap every stored key from `input.from` to `input.to` (by default, the
 * KEK the provider wraps under), under the approval, and report the keys per
 * KEK reference afterwards. See `KekRewrap.rewrapAll` of
 * `@qauth-labs/server-keys`.
 *
 * @throws KekRewrapRefusedError (`CURRENT_KEK_UNKNOWN`) when `to` is absent
 *   and the provider does not say which KEK it wraps under
 * @throws the errors of `loadKekProvider` and of `KekRewrap.rewrapAll`
 */
export async function rotateKek(
  deps: KekRotationDependencies,
  input: RotateKekInput
): Promise<KekRewrapReport> {
  const kekProvider = await loadKekProvider({ env: deps.kekEnv, warn: deps.warn });
  try {
    let to = input.to;
    if (to === undefined) {
      to = (await kekProvider.health()).kekRef;
      if (to === undefined) {
        throw new KekRewrapRefusedError(
          'CURRENT_KEK_UNKNOWN',
          `The KEK provider '${kekProvider.name}' does not report the KEK it wraps under: name it`
        );
      }
    }
    return await createKekRewrap({
      store: createRepositoryKekRewrapStore(deps.db),
      kekProvider,
    }).rewrapAll({
      from: input.from,
      to,
      approval: input.approval,
      onAudit: input.onAudit,
      ...(input.onKey === undefined ? {} : { onKey: input.onKey }),
      ...(input.signal === undefined ? {} : { signal: input.signal }),
    });
  } finally {
    await kekProvider.close?.();
  }
}

/**
 * Count the stored keys per KEK reference, and try whether this host opens
 * each one, changing nothing. `current` marks the KEK its provider wraps
 * under. See `KekRewrap.census` of `@qauth-labs/server-keys`.
 *
 * @throws the errors of `loadKekProvider` and of `KekRewrap.census`
 */
export async function countKeysPerKek(
  deps: KekRotationDependencies
): Promise<readonly KekRefCensus[]> {
  const kekProvider = await loadKekProvider({ env: deps.kekEnv, warn: deps.warn });
  try {
    return await createKekRewrap({
      store: createRepositoryKekRewrapStore(deps.db),
      kekProvider,
    }).census();
  } finally {
    await kekProvider.close?.();
  }
}
