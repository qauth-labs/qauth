import { InvalidConfigurationError } from '@qauth-labs/shared-errors';

import {
  DEFAULT_KEY_PREPUBLISH_DAYS,
  DEFAULT_KEY_RETIRED_RETENTION_DAYS,
  DEFAULT_KEY_ROTATION_PERIOD_DAYS,
  KEY_PURPOSES,
  type KeyAlgorithm,
  type KeyPurpose,
  type KeyPurposeDefinition,
} from './key-purposes';
import type { StoredKeySummary } from './key-store';
import { DEFAULT_PUBLISHED_KEY_REFRESH_INTERVAL_MS } from './published-keys';

/**
 * The scheduled rotation of a realm's unscoped keys (ADR-019 Decision 9 and
 * its answers on the retired-key lifetime, issue #542).
 *
 * Each rotating purpose of each realm moves through the same steps:
 *
 * 1. When its active key has signed for `period - prepublish`, a `next` key is
 *    created. A published `next` key is in the JWKS at once, and signs
 *    nothing: no verifier accepts it either (#899).
 * 2. When the active key has signed for `period`, and the `next` key has been
 *    published for `prepublish`, the switch is written: the `next` key becomes
 *    `active` and the old key `retired`, both as of a moment
 *    {@link KEY_ACTIVATION_DELAY_MS} ahead. A `next` key that a manual rotation
 *    made (#544, {@link planKeyRotationNow}) carries the moment it was planned
 *    to sign as its `activateAt`, and its switch waits for its window only,
 *    not for the period. Until that moment the old key keeps signing, while every process's key cache, which lives at most one
 *    refresh interval, learns that the new key is `active` and so verifies its
 *    tokens. A signer picks its key by those times (`signingKeyOf`).
 * 3. The retired key stays published, or for the cookie HMAC and data at rest
 *    keeps verifying or decrypting, until `retention` after the switch, or
 *    until the longest-lived thing it signed or sealed has expired, whichever
 *    is later. A data-at-rest key whose ciphertexts may live for ever is kept
 *    with no end.
 *
 * A job that was down past the due date does not skip the overlap: it creates
 * the `next` key, and the old key signs on until the new one has been
 * published for the whole window. Both keys of a hybrid pair move together,
 * in one transaction. Every step runs under the realm's key lock and reads the
 * keys again first, so a second node, or a repeated run, finds nothing left to
 * do. The job itself is `createKeyRotation` (`key-rotation.ts`, custody);
 * this module holds the windows and the plan, which touch no key material.
 */

const DAY_MS = 86_400_000;

/**
 * The purposes the job rotates: those whose default rotation is `automatic`
 * and that are not scoped (`token_signing`, `event_signing`,
 * `oid4vp_response_encryption`, `data_at_rest`, `cookie_hmac` and
 * `agent_wrap`). A scoped key rotates when its owner asks (#547).
 */
export const AUTOMATIC_ROTATION_PURPOSES: readonly KeyPurpose[] = Object.freeze(
  (Object.keys(KEY_PURPOSES) as KeyPurpose[]).filter((purpose) => {
    const definition: KeyPurposeDefinition = KEY_PURPOSES[purpose];
    return definition.rotation.mode === 'automatic' && !definition.scoped;
  })
);

/**
 * How far ahead of the moment it is written a switch takes effect, in ms: two
 * refresh intervals of the key caches (`DEFAULT_SIGNER_REFRESH_INTERVAL_MS`,
 * `DEFAULT_PUBLISHED_KEY_REFRESH_INTERVAL_MS`), one for the cache and one for
 * clock skew between nodes. A process that read its keys just before the
 * switch was written reads them again before the new key signs.
 */
export const KEY_ACTIVATION_DELAY_MS = 2 * DEFAULT_PUBLISHED_KEY_REFRESH_INTERVAL_MS;

/**
 * Purposes whose consumer holds one retired key at a time: the cookie ring
 * has one previous key (`CookieSecrets.previous`). Their next switch waits
 * until the retired key's retention has run, so no cookie loses its key early.
 */
const ONE_RETIRED_KEY_PURPOSES: readonly KeyPurpose[] = Object.freeze(['cookie_hmac']);

/** The windows of the rotation, in ms. */
export interface KeyRotationSettings {
  /** How long a key signs before it is replaced (`KEY_ROTATION_PERIOD_DAYS`). */
  readonly periodMs: number;
  /** How long a `next` key is published before it signs (`KEY_PREPUBLISH_DAYS`). */
  readonly prepublishMs: number;
  /** How long a retired key stays published at least (`KEY_RETIRED_RETENTION_DAYS`). */
  readonly retiredRetentionMs: number;
  /** How far ahead a switch takes effect. Defaults to {@link KEY_ACTIVATION_DELAY_MS}. */
  readonly activationDelayMs?: number;
}

/** {@link KeyRotationSettings} with every member set. */
export type ResolvedKeyRotationSettings = Required<KeyRotationSettings>;

/** The rotation windows in days, as the deployment settings name them. */
export interface KeyRotationDays {
  readonly periodDays: number;
  readonly prepublishDays: number;
  readonly retiredRetentionDays: number;
}

/** The windows of {@link KeyRotationDays}, in ms. */
export function keyRotationSettingsFromDays(days: KeyRotationDays): KeyRotationSettings {
  return Object.freeze({
    periodMs: days.periodDays * DAY_MS,
    prepublishMs: days.prepublishDays * DAY_MS,
    retiredRetentionMs: days.retiredRetentionDays * DAY_MS,
  });
}

/** The default windows: 90 days, 7 days and 14 days (ADR-019 Decision 9). */
export const DEFAULT_KEY_ROTATION_SETTINGS: KeyRotationSettings = keyRotationSettingsFromDays({
  periodDays: DEFAULT_KEY_ROTATION_PERIOD_DAYS,
  prepublishDays: DEFAULT_KEY_PREPUBLISH_DAYS,
  retiredRetentionDays: DEFAULT_KEY_RETIRED_RETENTION_DAYS,
});

/**
 * Check the windows and fill in the activation delay.
 *
 * @throws InvalidConfigurationError when a window is not a non-negative whole
 *   number of ms, the period is zero, or the period is shorter than the
 *   pre-publication window: the next key would have to be published before
 *   the key it replaces started to sign.
 */
export function resolveKeyRotationSettings(
  settings: KeyRotationSettings
): ResolvedKeyRotationSettings {
  const resolved: ResolvedKeyRotationSettings = Object.freeze({
    periodMs: settings.periodMs,
    prepublishMs: settings.prepublishMs,
    retiredRetentionMs: settings.retiredRetentionMs,
    activationDelayMs: settings.activationDelayMs ?? KEY_ACTIVATION_DELAY_MS,
  });
  for (const [name, value] of Object.entries(resolved)) {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new InvalidConfigurationError(
        `The key rotation setting '${name}' is a non-negative whole number of ms`
      );
    }
  }
  if (resolved.periodMs === 0) {
    throw new InvalidConfigurationError('The key rotation period is longer than zero');
  }
  if (resolved.periodMs < resolved.prepublishMs) {
    throw new InvalidConfigurationError(
      'The key rotation period (KEY_ROTATION_PERIOD_DAYS) is shorter than the pre-publication ' +
        'window (KEY_PREPUBLISH_DAYS): a next key could not be published for the whole window ' +
        'before it signs',
      { periodMs: resolved.periodMs, prepublishMs: resolved.prepublishMs }
    );
  }
  return resolved;
}

/** One key a rotation step created, activated or retired. */
export interface RotatedKey {
  readonly kid: string;
  readonly algorithm: KeyAlgorithm;
}

/** A `next` key, or a hybrid pair of them, was created. */
export interface NextKeyCreatedStep {
  readonly kind: 'next_created';
  readonly realmId: string;
  readonly purpose: KeyPurpose;
  /** The new keys: the key, then its hybrid companion if it has one. */
  readonly keys: readonly RotatedKey[];
  /** Epoch ms. The earliest moment the new keys may sign. */
  readonly activatesAt: number;
}

/** The `next` keys were made `active`, and the keys they replace `retired`. */
export interface KeysRotatedStep {
  readonly kind: 'rotated';
  readonly realmId: string;
  readonly purpose: KeyPurpose;
  readonly activated: readonly RotatedKey[];
  readonly retired: readonly RotatedKey[];
  /** Epoch ms. When the new keys start to sign and the old keys stop. */
  readonly switchAt: number;
  /**
   * Epoch ms. When the retired keys leave their JWKS and their verification
   * set, or stop verifying or decrypting; `null` when they are kept with no
   * end, as a data-at-rest key whose ciphertexts may live for ever is.
   */
  readonly retainedUntil: number | null;
}

/** One change the rotation wrote. */
export type KeyRotationStep = NextKeyCreatedStep | KeysRotatedStep;

/** What {@link planKeyRotation} decided for one purpose and algorithm. */
export type KeyRotationPlan =
  | { readonly action: 'none' }
  | { readonly action: 'create'; readonly activatesAt: number }
  | {
      readonly action: 'activate';
      readonly incoming: readonly StoredKeySummary[];
      readonly outgoing: readonly StoredKeySummary[];
    }
  | {
      readonly action: 'refuse';
      readonly reason: 'AMBIGUOUS_KEYS' | 'SPLIT_HYBRID_PAIR';
      readonly message: string;
    };

/** Input of {@link planKeyRotation}. */
export interface PlanKeyRotationInput {
  readonly purpose: KeyPurpose;
  /** The algorithm to rotate: one of the purpose's, never a hybrid companion. */
  readonly algorithm: KeyAlgorithm;
  /** Every unscoped key of the realm's purpose, whatever its status. */
  readonly keys: readonly StoredKeySummary[];
  readonly settings: ResolvedKeyRotationSettings;
  /** `HYBRID_SIGNING_ENABLED`. */
  readonly hybridSigning: boolean;
  /** Epoch ms. */
  readonly now: number;
}

/**
 * What the rotation does next for one purpose and algorithm of a realm. Pure:
 * it reads the keys it is given and the time, and changes nothing.
 *
 * - `none` — the realm holds no active key of the algorithm (provisioning
 *   creates the first), a switch is still ahead, or nothing is due yet.
 * - `create` — a `next` key is due.
 * - `activate` — the `next` keys (`incoming`) replace the active ones
 *   (`outgoing`): the active key, its hybrid partner, and any other active
 *   key of an incoming algorithm, which the one-active index would refuse.
 * - `refuse` — the keys are not in a state the job can choose for: two
 *   active or two `next` keys, or a `next` key that would split a hybrid pair.
 */
/**
 * How long a purpose's switch waits for a key it retired before: for a purpose
 * whose verifiers hold one previous key ({@link ONE_RETIRED_KEY_PURPOSES}),
 * the end of every retired key's retention, so the switch never pushes a
 * previous key out of the ring while its cookies may live. A retired key kept
 * with no end (a replaced cookie key's) holds nothing. `0` for the others.
 */
function previousKeyHold(purpose: KeyPurpose, keys: readonly StoredKeySummary[]): number {
  if (!ONE_RETIRED_KEY_PURPOSES.includes(purpose)) return 0;
  let hold = 0;
  for (const key of keys) {
    if (key.status === 'retired' && key.unpublishAt !== null)
      hold = Math.max(hold, key.unpublishAt);
  }
  return hold;
}

export function planKeyRotation(input: PlanKeyRotationInput): KeyRotationPlan {
  const { purpose, algorithm, keys, settings, now } = input;
  const definition: KeyPurposeDefinition = KEY_PURPOSES[purpose];
  const ofAlgorithm = keys.filter((key) => key.algorithm === algorithm);
  const active = ofAlgorithm.filter((key) => key.status === 'active');
  if (active.length === 0) return { action: 'none' };
  if (active.length > 1) {
    return {
      action: 'refuse',
      reason: 'AMBIGUOUS_KEYS',
      message: `The realm holds ${active.length} active '${algorithm}' keys for purpose '${purpose}'`,
    };
  }
  const [current] = active;
  const startedAt = current.activateAt ?? current.createdAt;
  // A switch written earlier has not taken effect yet.
  if (startedAt > now) return { action: 'none' };

  const next = ofAlgorithm.filter((key) => key.status === 'next');
  if (next.length > 1) {
    return {
      action: 'refuse',
      reason: 'AMBIGUOUS_KEYS',
      message: `The realm holds ${next.length} next '${algorithm}' keys for purpose '${purpose}'`,
    };
  }
  if (next.length === 0) {
    if (now < startedAt + settings.periodMs - settings.prepublishMs) return { action: 'none' };
    return {
      action: 'create',
      activatesAt: Math.max(
        startedAt + settings.periodMs,
        now + settings.prepublishMs,
        previousKeyHold(purpose, ofAlgorithm)
      ),
    };
  }

  const incoming = incomingKeys(next[0], keys);
  const split = splitPairRefusal(input, definition, incoming);
  if (split !== null) return split;

  const notBefore = switchNotBefore(
    incoming,
    startedAt,
    previousKeyHold(purpose, ofAlgorithm),
    settings
  );
  if (now < notBefore) return { action: 'none' };

  const incomingAlgorithms = new Set(incoming.map((key) => key.algorithm));
  const outgoing = keys.filter(
    (key) =>
      key.status === 'active' &&
      (incomingAlgorithms.has(key.algorithm) ||
        (current.pairId !== null && key.pairId === current.pairId))
  );
  return { action: 'activate', incoming, outgoing };
}

/** The `next` keys that switch together with `lead`: its hybrid pair, or `lead` alone. */
function incomingKeys(
  lead: StoredKeySummary,
  keys: readonly StoredKeySummary[]
): readonly StoredKeySummary[] {
  return lead.pairId === null
    ? [lead]
    : keys.filter((key) => key.status === 'next' && key.pairId === lead.pairId);
}

/**
 * The refusal of `incoming` when switching to it would split a hybrid pair:
 * hybrid signing is on, and the next key of the purpose's default algorithm
 * has no companion. `null` otherwise.
 */
function splitPairRefusal(
  input: Pick<PlanKeyRotationInput, 'purpose' | 'algorithm' | 'hybridSigning'>,
  definition: KeyPurposeDefinition,
  incoming: readonly StoredKeySummary[]
): {
  readonly action: 'refuse';
  readonly reason: 'SPLIT_HYBRID_PAIR';
  readonly message: string;
} | null {
  const { purpose, algorithm } = input;
  const companion = definition.hybridCompanion;
  if (
    input.hybridSigning === true &&
    companion !== undefined &&
    algorithm === definition.defaultAlgorithm &&
    !incoming.some((key) => key.algorithm === companion)
  ) {
    return {
      action: 'refuse',
      reason: 'SPLIT_HYBRID_PAIR',
      message:
        `The next '${algorithm}' key for purpose '${purpose}' has no '${companion}' partner, ` +
        'and hybrid signing is on',
    };
  }
  return null;
}

/** When every key of `incoming` has been published, or created when unpublished, for `prepublishMs`. */
function windowEnd(incoming: readonly StoredKeySummary[], prepublishMs: number): number {
  let end = 0;
  for (const key of incoming) end = Math.max(end, (key.publishAt ?? key.createdAt) + prepublishMs);
  return end;
}

/**
 * The earliest moment of the switch to `incoming`, from an active key that
 * started at `startedAt`, and no earlier than `hold` ({@link previousKeyHold}).
 *
 * Every `next` key waits for its window. A `next` key that a manual rotation
 * made (#544) carries, as its `activateAt`, the moment it was planned to sign,
 * and the switch to it comes then: before the active key's period has run,
 * since the rotation was approved. Any other `next` key (the job's own, or one
 * an operator made by hand) waits for the period as well, so that only an
 * approved rotation cuts the period short.
 */
function switchNotBefore(
  incoming: readonly StoredKeySummary[],
  startedAt: number,
  hold: number,
  settings: Pick<ResolvedKeyRotationSettings, 'periodMs' | 'prepublishMs'>
): number {
  const window = Math.max(hold, windowEnd(incoming, settings.prepublishMs));
  const planned = incoming.every((key) => key.activateAt !== null)
    ? Math.max(...incoming.map((key) => key.activateAt ?? 0))
    : startedAt + settings.periodMs;
  return Math.max(window, planned);
}

/** What {@link planKeyRotationNow} decided for one purpose and algorithm. */
export type KeyRotationNowPlan =
  /** The realm holds no active key of the algorithm: there is nothing to rotate. */
  | { readonly action: 'none' }
  /** Create the `next` key now. `activatesAt` is the earliest moment it may sign. */
  | { readonly action: 'create'; readonly activatesAt: number }
  /**
   * A `next` key (or a hybrid pair of them) waits already: keep it, create no
   * second. `activatesAt` is the earliest moment it may sign.
   */
  | {
      readonly action: 'keep';
      readonly keys: readonly StoredKeySummary[];
      readonly activatesAt: number;
    }
  | {
      readonly action: 'refuse';
      readonly reason: 'AMBIGUOUS_KEYS' | 'SPLIT_HYBRID_PAIR';
      readonly message: string;
    };

/**
 * What a manual rotation (#544) does for one purpose and algorithm of a realm,
 * before the rotation is due. Pure, like {@link planKeyRotation}, and with its
 * windows: the new key is published at once and signs only after the
 * pre-publication window, once the scheduled rotation writes the switch.
 *
 * - `none` — the realm holds no active key of the algorithm.
 * - `create` — no `next` key waits: create one now.
 * - `keep` — a `next` key waits already: it is the rotation's key, and no
 *   second one is created. It signs when the scheduled rotation switches to
 *   it: once its window has run if a manual rotation made it, and once the
 *   active key's period has run as well if the job or an operator did.
 * - `refuse` — two active or two `next` keys, or a waiting `next` key that
 *   would split a hybrid pair.
 *
 * The earliest moment a new key may sign is the end of its window, and no
 * earlier than a switch to the active key still ahead or, for the cookie key,
 * the end of the previous cookie key's retention. The rotation writes that
 * moment as the new key's `activateAt` (`createPlannedNextKey`), which is
 * how the scheduled rotation knows the key's switch was approved early.
 */
export function planKeyRotationNow(input: PlanKeyRotationInput): KeyRotationNowPlan {
  const { purpose, algorithm, keys, settings, now } = input;
  const definition: KeyPurposeDefinition = KEY_PURPOSES[purpose];
  const ofAlgorithm = keys.filter((key) => key.algorithm === algorithm);
  const active = ofAlgorithm.filter((key) => key.status === 'active');
  if (active.length === 0) return { action: 'none' };
  if (active.length > 1) {
    return {
      action: 'refuse',
      reason: 'AMBIGUOUS_KEYS',
      message: `The realm holds ${active.length} active '${algorithm}' keys for purpose '${purpose}'`,
    };
  }
  const next = ofAlgorithm.filter((key) => key.status === 'next');
  if (next.length > 1) {
    return {
      action: 'refuse',
      reason: 'AMBIGUOUS_KEYS',
      message: `The realm holds ${next.length} next '${algorithm}' keys for purpose '${purpose}'`,
    };
  }
  const [current] = active;
  const startedAt = current.activateAt ?? current.createdAt;
  const hold = previousKeyHold(purpose, ofAlgorithm);
  if (next.length === 0) {
    return {
      action: 'create',
      activatesAt: Math.max(startedAt, hold, now + settings.prepublishMs),
    };
  }
  const incoming = incomingKeys(next[0], keys);
  const split = splitPairRefusal(input, definition, incoming);
  if (split !== null) return split;
  return {
    action: 'keep',
    keys: incoming,
    activatesAt: Math.max(startedAt, switchNotBefore(incoming, startedAt, hold, settings)),
  };
}
