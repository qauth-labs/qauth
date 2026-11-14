import type {
  KeyRotationReport,
  KeyRotationStep,
  ScheduledKeyRotation,
  ScheduledKeyRotationRun,
} from '@qauth-labs/fastify-plugin-signer';
import { MAX_ACCESS_TOKEN_LIFESPAN_SECONDS } from '@qauth-labs/server-config';
import { getEventType, parseEvent } from '@qauth-labs/shared-events';
import type { FastifyBaseLogger } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import {
  createKeyRotationJob,
  KEY_ROTATION_INTERVAL_MS,
  KEY_ROTATION_JOB_NAME,
  KEY_ROTATION_ROLE,
  keyLifetimeOf,
  type KeyRotationJobDependencies,
  LONGEST_TOKEN_LIFETIME_MS,
} from './key-rotation';

const REALM = '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e01';
const DAY = 86_400_000;
const T0 = 1_800_000_000_000;
const TX = { transaction: 'of the step' };

const NEXT_CREATED: KeyRotationStep = {
  kind: 'next_created',
  realmId: REALM,
  purpose: 'token_signing',
  keys: [
    { kid: 'ed-2', algorithm: 'EdDSA' },
    { kid: 'ml-2', algorithm: 'ML-DSA-65' },
  ],
  activatesAt: T0 + 7 * DAY,
};

const ROTATED: KeyRotationStep = {
  kind: 'rotated',
  realmId: REALM,
  purpose: 'cookie_hmac',
  activated: [{ kid: 'cookie-2', algorithm: 'HS256' }],
  retired: [{ kid: 'cookie-1', algorithm: 'HS256' }],
  switchAt: T0 + 120_000,
  retainedUntil: T0 + 120_000 + 14 * DAY,
};

const KEPT: KeyRotationStep = {
  kind: 'rotated',
  realmId: REALM,
  purpose: 'data_at_rest',
  activated: [{ kid: 'data-2', algorithm: 'A256GCM' }],
  retired: [{ kid: 'data-1', algorithm: 'A256GCM' }],
  switchAt: T0 + 120_000,
  retainedUntil: null,
};

/** A scheduled rotation that reports `steps` through the hook, in the step's transaction. */
function rotation(steps: readonly KeyRotationStep[], failures: KeyRotationReport['failures'] = []) {
  const calls: ScheduledKeyRotationRun[] = [];
  const fake: Pick<ScheduledKeyRotation, 'run'> = {
    run: vi.fn(async (run: ScheduledKeyRotationRun) => {
      calls.push(run);
      for (const step of steps) await run.onStep?.(step, TX as never);
      return { realms: 1, steps, failures };
    }),
  };
  return { fake, calls };
}

function deps(overrides: Partial<KeyRotationJobDependencies> = {}) {
  const emitted: { tx: unknown; event: unknown }[] = [];
  const events = {
    emit: vi.fn(async (tx: unknown, event: unknown) => {
      // As the event store does: the event must pass the registry.
      const definition = getEventType((event as { type: string }).type);
      parseEvent({
        id: '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e99',
        time: new Date(T0).toISOString(),
        category: definition?.category,
        ...(event as object),
      });
      emitted.push({ tx, event });
      return 'event-id';
    }),
  };
  const realms = {
    findById: vi.fn(async (): Promise<{ ssoMaxLifespan: number | null } | undefined> => ({
      ssoMaxLifespan: null,
    })),
  };
  return {
    emitted,
    events,
    realms,
    deps: {
      rotation: rotation([]).fake,
      events: events as unknown as KeyRotationJobDependencies['events'],
      realms: realms as unknown as KeyRotationJobDependencies['realms'],
      sessionCookieTtlSeconds: 86_400,
      ...overrides,
    } satisfies KeyRotationJobDependencies,
  };
}

function context(signal = new AbortController().signal) {
  const log = { info: vi.fn(), error: vi.fn() };
  return {
    signal,
    now: () => T0,
    log: log as unknown as FastifyBaseLogger,
    info: log.info,
    error: log.error,
  };
}

describe('key-rotation (#542)', () => {
  it('runs every hour on the signer role', () => {
    const job = createKeyRotationJob(deps().deps);

    expect(job.name).toBe(KEY_ROTATION_JOB_NAME);
    expect(job.role).toBe(KEY_ROTATION_ROLE);
    expect(KEY_ROTATION_ROLE).toBe('signer');
    expect(job.intervalMs).toBe(KEY_ROTATION_INTERVAL_MS);
    expect(KEY_ROTATION_INTERVAL_MS).toBe(60 * 60_000);
  });

  it("runs the signer's rotation with the run's clock and signal", async () => {
    const { fake, calls } = rotation([]);
    const ctx = context();
    await createKeyRotationJob(deps({ rotation: fake }).deps).run(ctx);

    expect(calls).toHaveLength(1);
    expect(calls[0].signal).toBe(ctx.signal);
    expect(calls[0].now()).toBe(T0);
  });

  it("writes each step's audit event in the step's transaction", async () => {
    const { fake } = rotation([NEXT_CREATED, ROTATED, KEPT]);
    const world = deps({ rotation: fake });
    await createKeyRotationJob(world.deps).run(context());

    expect(world.emitted.map(({ tx }) => tx)).toEqual([TX, TX, TX]);
    expect(world.emitted.map(({ event }) => event)).toEqual([
      {
        type: 'urn:qauth:event:key.next_created:v1-rc.0',
        realm: REALM,
        actor: { type: 'system' },
        data: {
          purpose: 'token_signing',
          created: [
            { keyId: 'ed-2', algorithm: 'EdDSA' },
            { keyId: 'ml-2', algorithm: 'ML-DSA-65' },
          ],
          activatesAt: new Date(T0 + 7 * DAY).toISOString(),
        },
      },
      {
        type: 'urn:qauth:event:key.rotated:v1-rc.0',
        realm: REALM,
        actor: { type: 'system' },
        data: {
          purpose: 'cookie_hmac',
          activated: [{ keyId: 'cookie-2', algorithm: 'HS256' }],
          retired: [{ keyId: 'cookie-1', algorithm: 'HS256' }],
          activatesAt: new Date(T0 + 120_000).toISOString(),
          retainedUntil: new Date(T0 + 120_000 + 14 * DAY).toISOString(),
        },
      },
      {
        type: 'urn:qauth:event:key.rotated:v1-rc.0',
        realm: REALM,
        actor: { type: 'system' },
        data: {
          purpose: 'data_at_rest',
          activated: [{ keyId: 'data-2', algorithm: 'A256GCM' }],
          retired: [{ keyId: 'data-1', algorithm: 'A256GCM' }],
          activatesAt: new Date(T0 + 120_000).toISOString(),
        },
      },
    ]);
  });

  it('logs each failed purpose and fails the run, so the runner records it', async () => {
    const failure = { realmId: REALM, purpose: 'token_signing' as const, error: new Error('busy') };
    const { fake } = rotation([NEXT_CREATED], [failure]);
    const ctx = context();

    await expect(createKeyRotationJob(deps({ rotation: fake }).deps).run(ctx)).rejects.toThrow(
      'Key rotation failed for 1 purpose(s)'
    );
    expect(ctx.error).toHaveBeenCalledWith(
      { realmId: REALM, purpose: 'token_signing', err: failure.error },
      expect.any(String)
    );
  });

  it('refuses to be built without the scheduled rotation', () => {
    expect(() => createKeyRotationJob(deps({ rotation: null }).deps)).toThrow(
      'fastify.keyRotation'
    );
    expect(() => createKeyRotationJob(deps({ rotation: undefined }).deps)).toThrow(
      'fastify.keyRotation'
    );
  });
});

describe('keyLifetimeOf (#542)', () => {
  it('keeps a retired signing key for the longest token lifetime, a day', async () => {
    const { deps: d } = deps();
    expect(LONGEST_TOKEN_LIFETIME_MS).toBe(MAX_ACCESS_TOKEN_LIFESPAN_SECONDS * 1000);
    expect(LONGEST_TOKEN_LIFETIME_MS).toBe(DAY);
    for (const purpose of [
      'token_signing',
      'event_signing',
      'oid4vp_response_encryption',
    ] as const) {
      expect(await keyLifetimeOf(d, REALM, purpose)).toBe(DAY);
    }
  });

  it("keeps a retired cookie key for the realm's longest browser session", async () => {
    const world = deps();
    expect(await keyLifetimeOf(world.deps, REALM, 'cookie_hmac')).toBe(DAY);
    expect(world.realms.findById).toHaveBeenCalledWith(REALM);

    world.realms.findById.mockResolvedValueOnce({ ssoMaxLifespan: 30 * 86_400 });
    expect(await keyLifetimeOf(world.deps, REALM, 'cookie_hmac')).toBe(30 * DAY);
    // A realm lifespan shorter than SESSION_COOKIE_TTL does not shorten it.
    world.realms.findById.mockResolvedValueOnce({ ssoMaxLifespan: 600 });
    expect(await keyLifetimeOf(world.deps, REALM, 'cookie_hmac')).toBe(DAY);
    world.realms.findById.mockResolvedValueOnce(undefined);
    expect(await keyLifetimeOf(world.deps, REALM, 'cookie_hmac')).toBe(DAY);
  });

  it('keeps a retired data-at-rest key, and an agent wrapping key, with no end', async () => {
    const { deps: d } = deps();
    expect(await keyLifetimeOf(d, REALM, 'data_at_rest')).toBeNull();
    expect(await keyLifetimeOf(d, REALM, 'agent_wrap')).toBeNull();
  });
});
