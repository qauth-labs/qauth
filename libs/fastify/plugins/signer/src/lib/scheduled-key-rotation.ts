import type { SignatureAlgorithm } from '@qauth-labs/core-crypto';
import type { DbClient } from '@qauth-labs/infra-db';
import {
  DEFAULT_KEY_ROTATION_SETTINGS,
  DEFAULT_PUBLISHED_KEY_REFRESH_INTERVAL_MS,
  KEY_ACTIVATION_DELAY_MS,
  type KeyPurpose,
  type KeyRotationDays,
  keyRotationSettingsFromDays,
  type KeyRotationStep,
  type ResolvedKeyRotationSettings,
} from '@qauth-labs/server-keys';
import {
  createKeyRotation,
  DEFAULT_SIGNER_REFRESH_INTERVAL_MS,
  type KekProvider,
  type KeyRotationNowRecord,
  type KeyRotationReport,
  type RotateNowInput,
} from '@qauth-labs/server-keys/custody';

import { createRepositoryKeyStore } from './repository-key-stores';

/**
 * THE SCHEDULED KEY ROTATION, as the auth server's job runs it (ADR-019
 * Decision 9, issue #542): every rotating purpose of every realm that holds
 * keys moves to a new key on the rotation schedule, with the overlap windows
 * of `KEY_ROTATION_PERIOD_DAYS`, `KEY_PREPUBLISH_DAYS` and
 * `KEY_RETIRED_RETENTION_DAYS`.
 *
 * It lives in the signer's wiring because it creates keys, sealed under the
 * KEK: only a process that holds the signer role builds it. The job (in the
 * auth server) gives each run its clock, the lifetimes of the tokens, cookies
 * and ciphertexts each purpose's keys make, and the hook that writes each
 * step's audit row in the step's transaction.
 *
 * The manual rotation of #544 ({@link ScheduledKeyRotation.rotateNow}) starts
 * one purpose's rotation before it is due, under an approval, with the same
 * windows: the scheduled run then switches to its key. The admin API's route
 * and the break-glass CLI call it; neither ships yet.
 */

/** One run of {@link ScheduledKeyRotation.run}. */
export interface ScheduledKeyRotationRun {
  /** The clock, in epoch ms. */
  readonly now: () => number;
  /** Stops the run between two purposes. */
  readonly signal?: AbortSignal;
  /**
   * The longest a token, cookie or ciphertext made with a key of `purpose`
   * in the realm may live, in ms; `null` when one may live for ever (an
   * unpublished purpose only). A retired key is kept at least that long.
   */
  readonly lifetimeOf: (realmId: string, purpose: KeyPurpose) => Promise<number | null>;
  /** Called for each step inside its transaction: write its audit row there. */
  readonly onStep?: (step: KeyRotationStep, tx: DbClient) => Promise<void>;
}

/** The deployment's scheduled key rotation. See the module comment. */
export interface ScheduledKeyRotation {
  /** The windows it runs with, in ms. */
  readonly settings: ResolvedKeyRotationSettings;
  /** Rotate what is due in every realm. Failures are reported, not thrown. */
  run(run: ScheduledKeyRotationRun): Promise<KeyRotationReport>;
  /**
   * Start a rotation of one purpose of a realm now, under an approval of
   * exactly that rotation (`keys.rotate`): the `next` key is created and
   * published at once, and signs once the scheduled run switches to it after
   * the pre-publication window. A `next` key that waits already is returned
   * instead. The approval is consumed, and the audit hook called, in the
   * transaction that creates the key; `input.approval.consume` and the hooks
   * receive that transaction. See `KeyRotation.rotateNow` of
   * `@qauth-labs/server-keys`.
   */
  rotateNow(input: RotateNowInput<DbClient>): Promise<KeyRotationNowRecord>;
}

/** What {@link createScheduledKeyRotation} is built from. */
export interface ScheduledKeyRotationOptions {
  readonly db: DbClient;
  readonly kekProvider: KekProvider;
  readonly enabledSignatureAlgorithms: readonly SignatureAlgorithm[];
  readonly hybridSigning: boolean;
  /** The windows in days. Defaults to 90, 7 and 14 (ADR-019 Decision 9). */
  readonly days?: KeyRotationDays;
  /**
   * The signer's key-list refresh interval, in ms, when it is not the
   * default: a switch takes effect two intervals after it is written, so
   * every key cache has learned of the new key by then.
   */
  readonly signerRefreshIntervalMs?: number;
}

/**
 * Build the scheduled key rotation.
 *
 * @throws InvalidConfigurationError when the windows are refused: a period
 *   shorter than the pre-publication window, or one that is not a whole,
 *   positive number of days
 */
export function createScheduledKeyRotation(
  options: ScheduledKeyRotationOptions
): ScheduledKeyRotation {
  const base =
    options.days === undefined
      ? DEFAULT_KEY_ROTATION_SETTINGS
      : keyRotationSettingsFromDays(options.days);
  const refreshIntervalMs = Math.max(
    options.signerRefreshIntervalMs ?? DEFAULT_SIGNER_REFRESH_INTERVAL_MS,
    DEFAULT_PUBLISHED_KEY_REFRESH_INTERVAL_MS
  );
  const rotation = createKeyRotation({
    store: createRepositoryKeyStore(options.db),
    kekProvider: options.kekProvider,
    enabledSignatureAlgorithms: options.enabledSignatureAlgorithms,
    hybridSigning: options.hybridSigning,
    settings: {
      ...base,
      activationDelayMs: Math.max(KEY_ACTIVATION_DELAY_MS, 2 * Math.ceil(refreshIntervalMs)),
    },
  });
  return Object.freeze({
    settings: rotation.settings,
    run: (run: ScheduledKeyRotationRun) => rotation.rotateAll(run),
    rotateNow: (input: RotateNowInput<DbClient>) => rotation.rotateNow(input),
  });
}
