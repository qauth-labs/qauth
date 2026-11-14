import { ROTATING_KEY_ALGORITHMS, ROTATING_KEY_PURPOSES } from '@qauth-labs/shared-events';
import { InvalidConfigurationError } from '@qauth-labs/shared-errors';
import { describe, expect, it } from 'vitest';

import {
  DEFAULT_KEY_PREPUBLISH_DAYS,
  DEFAULT_KEY_RETIRED_RETENTION_DAYS,
  DEFAULT_KEY_ROTATION_PERIOD_DAYS,
  KEY_PURPOSES,
} from './key-purposes';
import {
  AUTOMATIC_ROTATION_PURPOSES,
  DEFAULT_KEY_ROTATION_SETTINGS,
  KEY_ACTIVATION_DELAY_MS,
  keyRotationSettingsFromDays,
  planKeyRotation,
  type PlanKeyRotationInput,
  resolveKeyRotationSettings,
} from './key-rotation-plan';
import type { StoredKeySummary } from './key-store';
import { DEFAULT_PUBLISHED_KEY_REFRESH_INTERVAL_MS } from './published-keys';

const DAY = 86_400_000;
const T0 = 1_800_000_000_000;
const SETTINGS = resolveKeyRotationSettings(DEFAULT_KEY_ROTATION_SETTINGS);

/** A stored key, active since `T0` unless the overrides say otherwise. */
function key(overrides: Partial<StoredKeySummary> & { kid: string }): StoredKeySummary {
  return {
    algorithm: 'EdDSA',
    status: 'active',
    pairId: null,
    publishAt: T0,
    activateAt: T0,
    retireAt: null,
    unpublishAt: null,
    createdAt: T0,
    ...overrides,
  };
}

function plan(overrides: Partial<PlanKeyRotationInput> & { now: number }) {
  return planKeyRotation({
    purpose: 'token_signing',
    algorithm: 'EdDSA',
    keys: [key({ kid: 'old' })],
    settings: SETTINGS,
    hybridSigning: false,
    ...overrides,
  });
}

describe('rotation settings', () => {
  it('defaults to 90, 7 and 14 days, and a switch two key-cache intervals ahead', () => {
    expect(SETTINGS).toEqual({
      periodMs: DEFAULT_KEY_ROTATION_PERIOD_DAYS * DAY,
      prepublishMs: DEFAULT_KEY_PREPUBLISH_DAYS * DAY,
      retiredRetentionMs: DEFAULT_KEY_RETIRED_RETENTION_DAYS * DAY,
      activationDelayMs: KEY_ACTIVATION_DELAY_MS,
    });
    expect(KEY_ACTIVATION_DELAY_MS).toBe(2 * DEFAULT_PUBLISHED_KEY_REFRESH_INTERVAL_MS);
  });

  it('refuses a period shorter than the pre-publication window', () => {
    expect(() =>
      resolveKeyRotationSettings(
        keyRotationSettingsFromDays({ periodDays: 6, prepublishDays: 7, retiredRetentionDays: 14 })
      )
    ).toThrow(InvalidConfigurationError);
    // As long as the window is allowed: the next key is created as the old one starts.
    expect(() =>
      resolveKeyRotationSettings(
        keyRotationSettingsFromDays({ periodDays: 7, prepublishDays: 7, retiredRetentionDays: 0 })
      )
    ).not.toThrow();
  });

  it.each([
    ['a zero period', { periodMs: 0, prepublishMs: 0, retiredRetentionMs: 0 }],
    ['a negative window', { periodMs: DAY, prepublishMs: -1, retiredRetentionMs: 0 }],
    ['a fraction of a ms', { periodMs: DAY, prepublishMs: 0.5, retiredRetentionMs: 0 }],
    ['a NaN', { periodMs: DAY, prepublishMs: 0, retiredRetentionMs: Number.NaN }],
    [
      'a negative activation delay',
      { periodMs: DAY, prepublishMs: 0, retiredRetentionMs: 0, activationDelayMs: -1 },
    ],
  ])('refuses %s', (_name, settings) => {
    expect(() => resolveKeyRotationSettings(settings)).toThrow(InvalidConfigurationError);
  });
});

describe('the rotating purposes', () => {
  it('are the automatic, unscoped purposes', () => {
    expect(AUTOMATIC_ROTATION_PURPOSES).toEqual([
      'token_signing',
      'event_signing',
      'oid4vp_response_encryption',
      'data_at_rest',
      'cookie_hmac',
      'agent_wrap',
    ]);
  });

  it('are the purposes and algorithms the key events name', () => {
    expect([...AUTOMATIC_ROTATION_PURPOSES].sort()).toEqual([...ROTATING_KEY_PURPOSES].sort());
    const algorithms = new Set(
      AUTOMATIC_ROTATION_PURPOSES.flatMap((purpose) => KEY_PURPOSES[purpose].algorithms)
    );
    expect([...algorithms].sort()).toEqual([...ROTATING_KEY_ALGORITHMS].sort());
  });
});

describe('planKeyRotation', () => {
  it('does nothing before the active key has served its period less the window', () => {
    expect(plan({ now: T0 + 83 * DAY - 1 })).toEqual({ action: 'none' });
  });

  it('creates the next key once the active key has served its period less the window', () => {
    expect(plan({ now: T0 + 83 * DAY })).toEqual({ action: 'create', activatesAt: T0 + 90 * DAY });
  });

  it('counts the period from the activation, not the creation', () => {
    const keys = [key({ kid: 'old', createdAt: T0 - 50 * DAY, activateAt: T0 })];
    expect(plan({ keys, now: T0 + 83 * DAY - 1 })).toEqual({ action: 'none' });
  });

  it('after a missed due date, creates the next key now and puts the switch a full window ahead', () => {
    expect(plan({ now: T0 + 100 * DAY })).toEqual({
      action: 'create',
      activatesAt: T0 + 107 * DAY,
    });
  });

  it('waits for the next key to have been published for the whole window', () => {
    const next = key({
      kid: 'new',
      status: 'next',
      activateAt: null,
      publishAt: T0 + 100 * DAY,
      createdAt: T0 + 100 * DAY,
    });
    const keys = [key({ kid: 'old' }), next];
    expect(plan({ keys, now: T0 + 107 * DAY - 1 })).toEqual({ action: 'none' });
    expect(plan({ keys, now: T0 + 107 * DAY })).toEqual({
      action: 'activate',
      incoming: [next],
      outgoing: [keys[0]],
    });
  });

  it('waits for the period even when the next key has been published long enough', () => {
    const next = key({ kid: 'new', status: 'next', activateAt: null, publishAt: T0 });
    const keys = [key({ kid: 'old' }), next];
    expect(plan({ keys, now: T0 + 90 * DAY - 1 })).toEqual({ action: 'none' });
    expect(plan({ keys, now: T0 + 90 * DAY }).action).toBe('activate');
  });

  it('does nothing while a written switch is still ahead', () => {
    const keys = [
      key({ kid: 'old', status: 'retired', retireAt: T0 + DAY, unpublishAt: T0 + 15 * DAY }),
      key({ kid: 'new', activateAt: T0 + DAY }),
    ];
    expect(plan({ keys, now: T0 + DAY - 1 })).toEqual({ action: 'none' });
  });

  it('does nothing for a realm without an active key of the algorithm', () => {
    expect(plan({ keys: [], now: T0 + 400 * DAY })).toEqual({ action: 'none' });
    expect(plan({ algorithm: 'RS256', now: T0 + 400 * DAY })).toEqual({ action: 'none' });
  });

  it('measures a key without an activation time from its creation', () => {
    const keys = [key({ kid: 'old', activateAt: null, createdAt: T0 })];
    expect(plan({ keys, now: T0 + 83 * DAY }).action).toBe('create');
  });

  it('moves a hybrid pair together, and the old pair with it', () => {
    const keys = [
      key({ kid: 'old-ed', pairId: 'p1' }),
      key({ kid: 'old-ml', algorithm: 'ML-DSA-65', pairId: 'p1' }),
      key({ kid: 'new-ed', status: 'next', activateAt: null, pairId: 'p2' }),
      key({
        kid: 'new-ml',
        algorithm: 'ML-DSA-65',
        status: 'next',
        activateAt: null,
        pairId: 'p2',
      }),
    ];
    const result = plan({ keys, hybridSigning: true, now: T0 + 90 * DAY });
    expect(result).toEqual({
      action: 'activate',
      incoming: [keys[2], keys[3]],
      outgoing: [keys[0], keys[1]],
    });
  });

  it('refuses a next key that would split a hybrid pair', () => {
    const keys = [key({ kid: 'old' }), key({ kid: 'new', status: 'next', activateAt: null })];
    expect(plan({ keys, hybridSigning: true, now: T0 + 90 * DAY })).toMatchObject({
      action: 'refuse',
      reason: 'SPLIT_HYBRID_PAIR',
    });
  });

  it('retires a lone active key of an incoming algorithm, which the one-active index would refuse', () => {
    const keys = [
      key({ kid: 'old-ed' }),
      key({ kid: 'stray-ml', algorithm: 'ML-DSA-65' }),
      key({ kid: 'new-ed', status: 'next', activateAt: null, pairId: 'p2' }),
      key({
        kid: 'new-ml',
        algorithm: 'ML-DSA-65',
        status: 'next',
        activateAt: null,
        pairId: 'p2',
      }),
    ];
    const result = plan({ keys, hybridSigning: true, now: T0 + 90 * DAY });
    expect(result).toMatchObject({ action: 'activate', outgoing: [keys[0], keys[1]] });
  });

  it.each([
    ['two active keys', [key({ kid: 'a' }), key({ kid: 'b' })]],
    [
      'two next keys',
      [
        key({ kid: 'old' }),
        key({ kid: 'n1', status: 'next', activateAt: null }),
        key({ kid: 'n2', status: 'next', activateAt: null }),
      ],
    ],
  ])('refuses %s rather than choose', (_name, keys) => {
    expect(plan({ keys, now: T0 + 90 * DAY })).toMatchObject({
      action: 'refuse',
      reason: 'AMBIGUOUS_KEYS',
    });
  });

  it("holds a cookie key's switch until the previous cookie key's retention has run", () => {
    const keys = [
      key({
        kid: 'older',
        algorithm: 'HS256',
        status: 'retired',
        publishAt: null,
        retireAt: T0,
        unpublishAt: T0 + 120 * DAY,
      }),
      key({ kid: 'old', algorithm: 'HS256', publishAt: null }),
      key({ kid: 'new', algorithm: 'HS256', status: 'next', publishAt: null, activateAt: null }),
    ];
    const cookie = { purpose: 'cookie_hmac' as const, algorithm: 'HS256' as const, keys };
    expect(plan({ ...cookie, now: T0 + 120 * DAY - 1 })).toEqual({ action: 'none' });
    expect(plan({ ...cookie, now: T0 + 120 * DAY }).action).toBe('activate');
    // A data-at-rest key decrypts with any retired key it keeps: no hold.
    const data = keys.map((stored) => ({ ...stored, algorithm: 'A256GCM' }));
    expect(
      plan({ purpose: 'data_at_rest', algorithm: 'A256GCM', keys: data, now: T0 + 90 * DAY }).action
    ).toBe('activate');
  });
});
