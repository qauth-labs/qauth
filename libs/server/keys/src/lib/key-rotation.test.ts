import { randomUUID } from 'node:crypto';

import type { SignatureAlgorithm } from '@qauth-labs/core-crypto';
import { compactVerify, decodeProtectedHeader, importJWK, type JWK } from 'jose';
import { describe, expect, it, vi } from 'vitest';

import { KEK_A, localProvider } from '../testing/keks';
import {
  createMemoryKeyStore,
  type MemoryKeyStore,
  type MemoryTx,
} from '../testing/memory-key-store';
import { createMemorySignerStore, type MemorySignerStore } from '../testing/memory-signer-store';
import {
  type ApprovedOperation,
  KEY_ROTATE_OPERATION,
  type KeyRotateOperation,
  keyRotationOperation,
  newOperationNonce,
  OperationApprovalError,
  operationDigest,
  type SecurityOperationActor,
} from './approved-operation';
import { DATA_AT_REST_CONSUMERS, dataAtRestLifetimeMs } from './data-at-rest-consumers';
import { createInProcessSigner, signingKeyOf } from './in-process-signer';
import { KeyChangeRefusedError } from './key-creation-errors';
import { createKeyFactory } from './key-factory';
import { KEY_PURPOSES, type KeyPurpose } from './key-purposes';
import {
  createKeyRotation,
  type KeyRotation,
  type KeyRotationNowRecord,
  type KeyRotationReport,
  type KeyRotationRunOptions,
  type RotateNowInput,
} from './key-rotation';
import {
  KEY_ACTIVATION_DELAY_MS,
  type KeyRotationSettings,
  type KeyRotationStep,
  type KeysRotatedStep,
  type NextKeyCreatedStep,
} from './key-rotation-plan';
import type { Signer } from './signer';
import type { SignerKeyRecord } from './signer-key-store';
import * as policy from './signer-policy';

const DAY = 86_400_000;
const T0 = 1_800_000_000_000;
const REALM = '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e01';
const OTHER_REALM = '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e02';
const ISSUER = 'https://a.example.test';
const ED25519_ONLY: readonly SignatureAlgorithm[] = ['EdDSA'];
const HYBRID: readonly SignatureAlgorithm[] = ['EdDSA', 'ML-DSA-65'];
const REFRESH_MS = 60_000;

/** The default rule of the tests: a day for published purposes and cookies, kept for data at rest. */
function defaultLifetime(purpose: KeyPurpose): number | null {
  if (KEY_PURPOSES[purpose].published || purpose === 'cookie_hmac') return DAY;
  return null;
}

interface WorldOptions {
  readonly hybrid?: boolean;
  readonly settings?: KeyRotationSettings;
  readonly lifetime?: (purpose: KeyPurpose) => number | null;
  readonly realms?: readonly string[];
}

interface World {
  readonly keys: MemoryKeyStore;
  readonly store: MemorySignerStore;
  readonly rotation: KeyRotation<MemoryTx>;
  readonly steps: KeyRotationStep[];
  readonly clock: { now: number };
  /** One run of the job at the clock's time. */
  run(overrides?: Partial<KeyRotationRunOptions<MemoryTx>>): Promise<KeyRotationReport>;
  /** A signer of its own, with its own key caches, as on another node. */
  signer(refreshIntervalMs?: number): Signer;
}

async function world(options: WorldOptions = {}): Promise<World> {
  const hybrid = options.hybrid === true;
  const enabled = hybrid ? HYBRID : ED25519_ONLY;
  const keys = createMemoryKeyStore();
  const kekProvider = localProvider({ KEK: KEK_A });
  const clock = { now: T0 };
  const factory = createKeyFactory({
    store: keys,
    kekProvider,
    enabledSignatureAlgorithms: enabled,
    hybridSigning: hybrid,
    now: () => clock.now,
  });
  for (const realmId of options.realms ?? [REALM]) await factory.provisionRealmKeys(realmId);
  const store = createMemorySignerStore(keys, { [REALM]: ISSUER, [OTHER_REALM]: ISSUER });
  const rotation = createKeyRotation({
    store: keys,
    kekProvider,
    enabledSignatureAlgorithms: enabled,
    hybridSigning: hybrid,
    ...(options.settings === undefined ? {} : { settings: options.settings }),
  });
  const steps: KeyRotationStep[] = [];
  const lifetime = options.lifetime ?? defaultLifetime;
  return {
    keys,
    store,
    rotation,
    steps,
    clock,
    run: (overrides = {}) =>
      rotation.rotateAll({
        now: () => clock.now,
        lifetimeOf: async (_realmId, purpose) => lifetime(purpose),
        onStep: async (step) => {
          steps.push(step);
        },
        ...overrides,
      }),
    signer: (refreshIntervalMs = REFRESH_MS) =>
      createInProcessSigner({
        store,
        kekProvider,
        enabledSignatureAlgorithms: enabled,
        hybridSigning: hybrid,
        refreshIntervalMs,
        now: () => clock.now,
      }),
  };
}

function accessToken(at: number) {
  return {
    realmId: REALM,
    purpose: 'token_signing' as const,
    typ: 'at+jwt',
    claims: { sub: 'user-1', aud: 'client-1', iat: at / 1000, exp: at / 1000 + 300 },
  };
}

async function kidOf(token: string): Promise<string> {
  return decodeProtectedHeader(token).kid as string;
}

/** Verify `token` with the keys `signer` accepts, as a verifier would; `false` when none is its key. */
async function verifies(signer: Signer, token: string): Promise<boolean> {
  const { kid, alg } = decodeProtectedHeader(token);
  const keys = await signer.getVerificationKeys('local', REALM, 'token_signing');
  const found = keys.find((key) => key.kid === kid);
  if (found === undefined) return false;
  await compactVerify(token, await importJWK(found.publicJwk as JWK, alg));
  return true;
}

async function jwksKids(signer: Signer): Promise<string[]> {
  return (await signer.getJwks('local', REALM)).keys.map((key) => key.kid as string);
}

function stepOf(
  steps: readonly KeyRotationStep[],
  purpose: KeyPurpose,
  kind: KeyRotationStep['kind']
) {
  return steps.filter((step) => step.purpose === purpose && step.kind === kind);
}

function rotatedStep(steps: readonly KeyRotationStep[], purpose: KeyPurpose): KeysRotatedStep {
  const [step] = stepOf(steps, purpose, 'rotated');
  if (step === undefined || step.kind !== 'rotated') throw new Error(`no rotation of ${purpose}`);
  return step;
}

describe('the scheduled rotation, over a fake clock', () => {
  it('on day 83 creates a next key that is in the JWKS, while the old key still signs', async () => {
    const w = await world();
    const signer = w.signer();
    const oldKid = await kidOf(await signer.signJws('local', accessToken(T0)));

    w.clock.now = T0 + 83 * DAY - 1;
    expect((await w.run()).steps).toEqual([]);

    w.clock.now = T0 + 83 * DAY;
    const report = await w.run();
    expect(report.failures).toEqual([]);
    const [created] = stepOf(report.steps, 'token_signing', 'next_created');
    expect(created).toMatchObject({ realmId: REALM, activatesAt: T0 + 90 * DAY });
    // Every rotating purpose the realm holds a key of gets one.
    expect(report.steps.map((step) => step.purpose).sort()).toEqual(
      ['cookie_hmac', 'data_at_rest', 'event_signing', 'token_signing'].sort()
    );

    const newKid = created.kind === 'next_created' ? created.keys[0].kid : '';
    w.clock.now += REFRESH_MS;
    expect(await jwksKids(signer)).toContain(newKid);
    expect(await kidOf(await signer.signJws('local', accessToken(w.clock.now)))).toBe(oldKid);
    // A next key never verifies (#899).
    const verification = await signer.getVerificationKeys('local', REALM, 'token_signing');
    expect(verification.map((key) => key.kid)).not.toContain(newKid);
    // The next SET key is in the SSF transmitter's JWKS, for receivers to fetch first.
    const [event] = stepOf(report.steps, 'event_signing', 'next_created');
    const eventKid = event.kind === 'next_created' ? event.keys[0].kid : '';
    const ssf = await signer.getJwks('local', REALM, 'event_signing');
    expect(ssf.keys.map((key) => key.kid)).toContain(eventKid);
  });

  it('on day 90 switches to the new key, and tokens of the old key still verify', async () => {
    const w = await world();
    const signer = w.signer();
    w.clock.now = T0 + 83 * DAY;
    await w.run();
    const oldToken = await signer.signJws('local', accessToken(w.clock.now));

    w.clock.now = T0 + 90 * DAY;
    const report = await w.run();
    const step = rotatedStep(report.steps, 'token_signing');
    expect(step.switchAt).toBe(T0 + 90 * DAY + KEY_ACTIVATION_DELAY_MS);
    expect(step.retainedUntil).toBe(step.switchAt + 14 * DAY);

    // Until the switch takes effect, the old key signs on.
    w.clock.now = step.switchAt - 1;
    expect(await kidOf(await signer.signJws('local', accessToken(w.clock.now)))).toBe(
      step.retired[0].kid
    );
    w.clock.now = step.switchAt;
    const newToken = await signer.signJws('local', accessToken(w.clock.now));
    expect(await kidOf(newToken)).toBe(step.activated[0].kid);
    expect(await verifies(signer, newToken)).toBe(true);
    expect(await verifies(signer, oldToken)).toBe(true);
  });

  it('on day 104 takes the old key out of the JWKS and the verification set', async () => {
    const w = await world();
    const signer = w.signer();
    w.clock.now = T0 + 83 * DAY;
    await w.run();
    const oldToken = await signer.signJws('local', accessToken(w.clock.now));
    w.clock.now = T0 + 90 * DAY;
    const step = rotatedStep((await w.run()).steps, 'token_signing');
    const oldKid = step.retired[0].kid;

    w.clock.now = step.retainedUntil! - 1;
    expect(await jwksKids(signer)).toContain(oldKid);
    expect(await verifies(signer, oldToken)).toBe(true);

    w.clock.now = step.retainedUntil!;
    expect(step.retainedUntil! - T0).toBeLessThanOrEqual(104 * DAY + KEY_ACTIVATION_DELAY_MS);
    expect(await jwksKids(signer)).not.toContain(oldKid);
    expect(await verifies(signer, oldToken)).toBe(false);
    // Repeating the run changes nothing.
    expect((await w.run()).steps).toEqual([]);
  });

  it('keeps a retired key published until the longest token it signed has expired', async () => {
    // A 30-day token lifetime and no retention of its own: the lifetime decides.
    const w = await world({
      settings: { periodMs: 90 * DAY, prepublishMs: 7 * DAY, retiredRetentionMs: 0 },
      lifetime: (purpose) => (purpose === 'token_signing' ? 30 * DAY : defaultLifetime(purpose)),
    });
    const signer = w.signer();
    w.clock.now = T0 + 83 * DAY;
    await w.run();
    const longLived = await signer.signJws('local', accessToken(w.clock.now));
    w.clock.now = T0 + 90 * DAY;
    const step = rotatedStep((await w.run()).steps, 'token_signing');
    expect(step.retainedUntil).toBe(step.switchAt + 30 * DAY);

    w.clock.now = step.switchAt + 30 * DAY - 1;
    expect(await verifies(signer, longLived)).toBe(true);
    w.clock.now = step.switchAt + 30 * DAY;
    expect(await verifies(signer, longLived)).toBe(false);
  });

  it('flips a hybrid pair in one transaction, and the JWKS never shows half a pair', async () => {
    const w = await world({ hybrid: true });
    const signer = w.signer();
    const pairsShown = async () => {
      const kids = await jwksKids(signer);
      const tokenKeys = w.keys.rows
        .map((row) => row.key)
        .filter((key) => key.purpose === 'token_signing' && kids.includes(key.kid));
      const byPair = new Map<string | null, string[]>();
      for (const key of tokenKeys)
        byPair.set(key.pairId, [...(byPair.get(key.pairId) ?? []), key.algorithm]);
      return [...byPair.values()].map((algorithms) => algorithms.sort());
    };

    w.clock.now = T0 + 83 * DAY;
    const [created] = stepOf((await w.run()).steps, 'token_signing', 'next_created');
    expect(created.kind === 'next_created' && created.keys.map((key) => key.algorithm)).toEqual([
      'EdDSA',
      'ML-DSA-65',
    ]);

    w.clock.now = T0 + 90 * DAY;
    const callsBefore = w.keys.calls.length;
    const step = rotatedStep((await w.run()).steps, 'token_signing');
    expect(step.activated.map((key) => key.algorithm)).toEqual(['EdDSA', 'ML-DSA-65']);
    expect(step.retired.map((key) => key.algorithm).sort()).toEqual(['EdDSA', 'ML-DSA-65']);
    // All four moves ran in the one transaction of the token_signing step.
    const moves = w.keys.calls.slice(callsBefore).filter((call) => call.method === 'updateStatus');
    const tokenMoves = moves.slice(0, 4);
    expect(new Set(tokenMoves.map((call) => call.tx?.id)).size).toBe(1);

    for (const at of [
      T0 + 83 * DAY + REFRESH_MS,
      step.switchAt - 1,
      step.switchAt,
      step.retainedUntil! - 1,
      step.retainedUntil!,
    ]) {
      w.clock.now = at;
      for (const pair of await pairsShown())
        expect(pair, `at ${at - T0}`).toEqual(['EdDSA', 'ML-DSA-65']);
    }

    // The hybrid carrier uses one pair before the switch and the other after.
    w.clock.now = step.switchAt - 1;
    const hybridRequest = () => {
      const { realmId, typ, claims } = accessToken(w.clock.now);
      return { realmId, typ, claims };
    };
    const before = await signer.signHybrid('local', hybridRequest());
    w.clock.now = step.switchAt;
    const after = await signer.signHybrid('local', hybridRequest());
    expect(await kidOf(before.token)).toBe(
      step.retired.find((key) => key.algorithm === 'EdDSA')?.kid
    );
    expect(await kidOf(after.token)).toBe(step.activated[0].kid);
  });

  it('after 100 days down, creates the next key, waits the whole window, then switches', async () => {
    const w = await world();
    const signer = w.signer();
    const oldKid = await kidOf(await signer.signJws('local', accessToken(T0)));

    w.clock.now = T0 + 100 * DAY;
    const [created] = stepOf((await w.run()).steps, 'token_signing', 'next_created');
    expect(created).toMatchObject({ activatesAt: T0 + 107 * DAY });

    w.clock.now = T0 + 107 * DAY - 1;
    expect(stepOf((await w.run()).steps, 'token_signing', 'rotated')).toEqual([]);
    expect(await kidOf(await signer.signJws('local', accessToken(w.clock.now)))).toBe(oldKid);

    w.clock.now = T0 + 107 * DAY;
    const step = rotatedStep((await w.run()).steps, 'token_signing');
    expect(step.retired[0].kid).toBe(oldKid);
  });

  it('rotates once when two nodes run the job at the same time', async () => {
    const w = await world();
    // The realm's key lock, as the advisory lock serializes the two nodes.
    let held = Promise.resolve();
    const locked: MemoryKeyStore = {
      ...w.keys,
      transaction<T>(work: (tx: MemoryTx) => Promise<T>, outer?: MemoryTx): Promise<T> {
        if (outer !== undefined) return w.keys.transaction(work, outer);
        const run = held.then(() => w.keys.transaction(work));
        held = run.then(
          () => undefined,
          () => undefined
        );
        return run;
      },
    };
    const kekProvider = localProvider({ KEK: KEK_A });
    const nodes = [0, 1].map(() =>
      createKeyRotation({
        store: locked,
        kekProvider,
        enabledSignatureAlgorithms: ED25519_ONLY,
        hybridSigning: false,
      })
    );
    const runAll = () =>
      Promise.all(
        nodes.map((node) =>
          node.rotateAll({
            now: () => w.clock.now,
            lifetimeOf: async (_realmId, purpose) => defaultLifetime(purpose),
          })
        )
      );

    w.clock.now = T0 + 83 * DAY;
    const created = (await runAll()).flatMap((report) => report.steps);
    expect(stepOf(created, 'token_signing', 'next_created')).toHaveLength(1);
    w.clock.now = T0 + 90 * DAY;
    const rotated = (await runAll()).flatMap((report) => report.steps);
    expect(stepOf(rotated, 'token_signing', 'rotated')).toHaveLength(1);
    const tokenKeys = w.keys.rows.filter((row) => row.key.purpose === 'token_signing');
    expect(tokenKeys.map((row) => row.key.status).sort()).toEqual(['active', 'retired']);
  });

  it('verifies cookies of the old cookie key during its retention and not after', async () => {
    const w = await world();
    const signer = w.signer();
    const first = await signer.getCookieSecrets('local', REALM);
    expect(first.previous).toBeNull();

    w.clock.now = T0 + 83 * DAY;
    await w.run();
    w.clock.now = T0 + 90 * DAY;
    const step = rotatedStep((await w.run()).steps, 'cookie_hmac');
    expect(step.retainedUntil).toBe(step.switchAt + 14 * DAY);

    // Before the switch: the old key signs, the new one already verifies.
    w.clock.now = step.switchAt - 1;
    const during = await signer.getCookieSecrets('local', REALM);
    expect(during.current.kid).toBe(first.current.kid);
    expect(during.previous?.kid).toBe(step.activated[0].kid);

    w.clock.now = step.switchAt;
    const after = await signer.getCookieSecrets('local', REALM);
    expect(after.current.kid).toBe(step.activated[0].kid);
    expect(after.previous?.kid).toBe(first.current.kid);
    expect(after.previous?.secret.equals(first.current.secret)).toBe(true);

    w.clock.now = step.retainedUntil! - 1;
    expect((await signer.getCookieSecrets('local', REALM)).previous?.kid).toBe(first.current.kid);
    w.clock.now = step.retainedUntil!;
    expect((await signer.getCookieSecrets('local', REALM)).previous).toBeNull();
    // A cookie that names the old key finds it no more, even on a forced read.
    expect(
      (await signer.getCookieSecrets('local', REALM, { kid: first.current.kid })).previous
    ).toBeNull();
  });

  it('keeps cookies of a realm whose sessions outlive the retention for the whole session', async () => {
    const w = await world({
      lifetime: (purpose) => (purpose === 'cookie_hmac' ? 30 * DAY : defaultLifetime(purpose)),
    });
    w.clock.now = T0 + 83 * DAY;
    await w.run();
    w.clock.now = T0 + 90 * DAY;
    const step = rotatedStep((await w.run()).steps, 'cookie_hmac');
    expect(step.retainedUntil).toBe(step.switchAt + 30 * DAY);
  });

  it('keeps a retired data-at-rest key while its ciphertexts may live, and switches encryption', async () => {
    const w = await world();
    const signer = w.signer();
    const sealed = await signer.encrypt('local', {
      realmId: REALM,
      plaintext: Buffer.from('stored secret'),
      context: 'test:1',
    });
    w.clock.now = T0 + 83 * DAY;
    await w.run();
    w.clock.now = T0 + 90 * DAY;
    const step = rotatedStep((await w.run()).steps, 'data_at_rest');
    // A stored secret has no end, so the key is kept with none.
    expect(step.retainedUntil).toBeNull();

    w.clock.now = step.switchAt + 400 * DAY;
    const resealed = await signer.encrypt('local', {
      realmId: REALM,
      plaintext: Buffer.from('stored secret'),
      context: 'test:1',
    });
    // The second part of a ciphertext names the key that sealed it.
    expect(sealed.split('.')[1]).toBe(step.retired[0].kid);
    expect(resealed.split('.')[1]).toBe(step.activated[0].kid);
    expect(
      (
        await signer.decrypt('local', { realmId: REALM, ciphertext: sealed, context: 'test:1' })
      ).toString()
    ).toBe('stored secret');
  });

  it('stops decrypting with a retired data-at-rest key once its retention has run', async () => {
    const w = await world({
      settings: { periodMs: 90 * DAY, prepublishMs: 7 * DAY, retiredRetentionMs: 0 },
      lifetime: (purpose) => (purpose === 'data_at_rest' ? DAY : defaultLifetime(purpose)),
    });
    const signer = w.signer();
    const sealed = await signer.encrypt('local', {
      realmId: REALM,
      plaintext: Buffer.from('short-lived'),
    });
    w.clock.now = T0 + 83 * DAY;
    await w.run();
    w.clock.now = T0 + 90 * DAY;
    const step = rotatedStep((await w.run()).steps, 'data_at_rest');
    expect(step.retainedUntil).toBe(step.switchAt + DAY);

    w.clock.now = step.retainedUntil! - 1;
    expect((await signer.decrypt('local', { realmId: REALM, ciphertext: sealed })).toString()).toBe(
      'short-lived'
    );
    w.clock.now = step.retainedUntil!;
    await expect(signer.decrypt('local', { realmId: REALM, ciphertext: sealed })).rejects.toThrow();
  });

  it('rotates every realm that holds keys, paging through them', async () => {
    const w = await world({ realms: [REALM, OTHER_REALM] });
    w.clock.now = T0 + 83 * DAY;
    const report = await w.run({ pageSize: 1 });
    expect(report.realms).toBe(2);
    expect(
      new Set(stepOf(report.steps, 'token_signing', 'next_created').map((step) => step.realmId))
    ).toEqual(new Set([REALM, OTHER_REALM]));
  });

  it('reports a purpose that fails and goes on with the others; the failed step changes nothing', async () => {
    const w = await world();
    w.clock.now = T0 + 83 * DAY;
    const before = w.keys.rows.length;
    const report = await w.run({
      onStep: async (step) => {
        if (step.purpose === 'token_signing') throw new Error('audit store down');
        w.steps.push(step);
      },
    });
    expect(report.failures).toEqual([
      expect.objectContaining({ realmId: REALM, purpose: 'token_signing' }),
    ]);
    // The other purposes moved; the token key's next key was rolled back.
    expect(report.steps.map((step) => step.purpose)).not.toContain('token_signing');
    expect(report.steps.length).toBe(3);
    expect(w.keys.rows.length).toBe(before + 3);
    // The next run creates it.
    const retry = await w.run();
    expect(stepOf(retry.steps, 'token_signing', 'next_created')).toHaveLength(1);
  });

  it('refuses to retire a published key without an end to its lifetime', async () => {
    const w = await world({ lifetime: () => null });
    w.clock.now = T0 + 83 * DAY;
    // Creating the next key needs no lifetime.
    expect((await w.run()).failures).toEqual([]);
    w.clock.now = T0 + 90 * DAY;
    const report = await w.run();
    expect(report.failures.map((failure) => failure.purpose).sort()).toEqual([
      'event_signing',
      'token_signing',
    ]);
    expect(report.failures[0].error).toBeInstanceOf(TypeError);
  });

  it('stops between purposes when the run is aborted', async () => {
    const w = await world();
    w.clock.now = T0 + 83 * DAY;
    const controller = new AbortController();
    controller.abort(new Error('stopped'));
    await expect(w.run({ signal: controller.signal })).rejects.toThrow('stopped');
    expect(w.steps).toEqual([]);
  });

  it('refuses a malformed realm id for one realm', async () => {
    const w = await world();
    await expect(
      w.rotation.rotateRealm('not-a-realm', { lifetimeOf: async () => DAY })
    ).rejects.toBeInstanceOf(KeyChangeRefusedError);
  });
});

describe('verifiers learn of a new key before it signs (the review of #899)', () => {
  /**
   * A signing node and a verifying node, each with its own key cache. The
   * verifier last read its keys just before the switch was written, while
   * the new key was still `next`.
   */
  async function nodes(activationDelayMs?: number) {
    const w = await world({
      settings: {
        periodMs: 90 * DAY,
        prepublishMs: 7 * DAY,
        retiredRetentionMs: 14 * DAY,
        ...(activationDelayMs === undefined ? {} : { activationDelayMs }),
      },
    });
    // The signing node reads its keys on every call, the worst case.
    const signing = w.signer(0);
    const verifying = w.signer(REFRESH_MS);
    w.clock.now = T0 + 83 * DAY;
    await w.run();
    w.clock.now = T0 + 90 * DAY - 1;
    await verifying.getVerificationKeys('local', REALM, 'token_signing');
    w.clock.now = T0 + 90 * DAY;
    await w.run();
    return { w, signing, verifying };
  }

  it('refuses no token across an automatic rotation', async () => {
    const { w, signing, verifying } = await nodes();
    const kids = new Set<string>();
    for (let at = T0 + 90 * DAY; at <= T0 + 90 * DAY + 5 * REFRESH_MS; at += 5_000) {
      w.clock.now = at;
      const token = await signing.signJws('local', accessToken(at));
      kids.add(await kidOf(token));
      expect(await verifies(verifying, token), `at +${at - T0 - 90 * DAY} ms`).toBe(true);
    }
    // The run did cross the switch.
    expect(kids.size).toBe(2);
  });

  it('would refuse fresh tokens if the switch took effect at once', async () => {
    const { w, signing, verifying } = await nodes(0);
    w.clock.now = T0 + 90 * DAY + 1;
    const token = await signing.signJws('local', accessToken(w.clock.now));
    expect(await verifies(verifying, token)).toBe(false);
  });
});

describe('signingKeyOf', () => {
  const record = (overrides: Partial<SignerKeyRecord> & { kid: string }): SignerKeyRecord => ({
    algorithm: 'EdDSA',
    status: 'active',
    pairId: null,
    activateAt: T0,
    retireAt: null,
    unpublishAt: null,
    createdAt: T0,
    ...overrides,
  });

  it('is the active key once its activation has passed', () => {
    const active = record({ kid: 'a' });
    expect(signingKeyOf([active], 'EdDSA', T0)).toBe(active);
    expect(signingKeyOf([record({ kid: 'a', activateAt: null })], 'EdDSA', T0)?.kid).toBe('a');
  });

  it('is the key the active one replaces until the switch takes effect', () => {
    const outgoing = record({ kid: 'old', status: 'retired', retireAt: T0 + 10 });
    const incoming = record({ kid: 'new', activateAt: T0 + 10 });
    expect(signingKeyOf([outgoing, incoming], 'EdDSA', T0 + 9)).toBe(outgoing);
    expect(signingKeyOf([outgoing, incoming], 'EdDSA', T0 + 10)).toBe(incoming);
  });

  it('is the active key when nothing else can sign, and none for two active keys', () => {
    expect(signingKeyOf([record({ kid: 'new', activateAt: T0 + 10 })], 'EdDSA', T0)?.kid).toBe(
      'new'
    );
    expect(signingKeyOf([record({ kid: 'a' }), record({ kid: 'b' })], 'EdDSA', T0)).toBeUndefined();
    expect(signingKeyOf([record({ kid: 'a' })], 'RS256', T0)).toBeUndefined();
  });
});

describe('DATA_AT_REST_CONSUMERS', () => {
  it("names every context prefix the signer's policy grants", () => {
    const prefixes = Object.entries(policy)
      .filter(([name]) => name.endsWith('_CONTEXT_PREFIX'))
      .map(([, value]) => value as string);
    expect(prefixes.length).toBeGreaterThan(0);
    expect(DATA_AT_REST_CONSUMERS.map((consumer) => consumer.contextPrefix).sort()).toEqual(
      [...prefixes].sort()
    );
  });

  it('keeps a retired key for good while one consumer stores ciphertexts with no end', () => {
    expect(dataAtRestLifetimeMs()).toBeNull();
    expect(
      dataAtRestLifetimeMs([
        { contextPrefix: 'a:', description: 'a', longestLifetimeMs: 1_000 },
        { contextPrefix: 'b:', description: 'b', longestLifetimeMs: 5_000 },
      ])
    ).toBe(5_000);
  });
});

describe('rotateNow: a manual rotation under an approval (#544)', () => {
  const ADMIN: SecurityOperationActor = Object.freeze({
    kind: 'human',
    realmId: OTHER_REALM,
    accountId: '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6eaa',
  });

  /** An approval of a test, single use, filed for one rotation by `requester`. */
  interface TestApproval extends ApprovedOperation<KeyRotateOperation, MemoryTx> {
    /** The digest and transaction of each successful use. */
    readonly uses: { readonly digest: Buffer; readonly tx: MemoryTx }[];
  }

  function approvalOf(
    filedFor: { readonly realmId: string; readonly purpose: KeyPurpose },
    requester: SecurityOperationActor = ADMIN
  ): TestApproval {
    const nonce = newOperationNonce();
    const filed = operationDigest(
      keyRotationOperation({
        realmId: filedFor.realmId,
        purpose: filedFor.purpose,
        requester,
        nonce,
      })
    );
    const uses: { digest: Buffer; tx: MemoryTx }[] = [];
    return {
      id: randomUUID(),
      operation: KEY_ROTATE_OPERATION,
      requester,
      nonce,
      uses,
      async consume(digest, tx) {
        if (uses.length > 0) throw new OperationApprovalError('refused', 'used already');
        if (!digest.equals(filed)) {
          throw new OperationApprovalError('refused', 'filed for another operation');
        }
        uses.push({ digest, tx });
      },
    };
  }

  /** A manual rotation of `purpose` in the realm at the clock's time, with an approval of it. */
  function rotateNow(
    w: World,
    purpose: KeyPurpose,
    overrides: Partial<RotateNowInput<MemoryTx>> = {}
  ): Promise<KeyRotationNowRecord> {
    return w.rotation.rotateNow({
      realmId: REALM,
      purpose,
      now: () => w.clock.now,
      onAudit: async () => undefined,
      ...overrides,
      approval: overrides.approval ?? approvalOf({ realmId: REALM, purpose }),
    });
  }

  /** Every stored key's lifecycle, to show that a refused call changed nothing. */
  function snapshot(w: World) {
    return w.keys.rows.map((row) => ({
      kid: row.key.kid,
      purpose: row.key.purpose,
      status: row.key.status,
      activateAt: row.key.activateAt,
      retireAt: row.key.retireAt,
      unpublishAt: row.key.unpublishAt,
    }));
  }

  /** The realm's keys of `purpose`, as the store holds them. */
  function stored(w: World, purpose: KeyPurpose) {
    return w.keys.rows
      .filter((row) => row.key.realmId === REALM && row.key.purpose === purpose)
      .map((row) => ({ kid: row.key.kid, algorithm: row.key.algorithm, status: row.key.status }));
  }

  it('fails without a valid approval, at compile time and at run time, and changes nothing', async () => {
    const w = await world();
    const before = snapshot(w);
    const base = {
      realmId: REALM,
      purpose: 'token_signing' as const,
      onAudit: async () => undefined,
    };

    // @ts-expect-error -- a manual rotation does not compile without an approval
    await expect(w.rotation.rotateNow(base)).rejects.toMatchObject({
      name: 'OperationApprovalError',
      reason: 'missing',
    });
    const retire: ApprovedOperation<'keys.retire', MemoryTx> = {
      ...approvalOf({ realmId: REALM, purpose: 'token_signing' }),
      operation: 'keys.retire',
    };
    // @ts-expect-error -- nor with the approval of another operation
    await expect(w.rotation.rotateNow({ ...base, approval: retire })).rejects.toMatchObject({
      reason: 'other_operation',
    });
    const anyOperation: ApprovedOperation<string, MemoryTx> = approvalOf({
      realmId: REALM,
      purpose: 'token_signing',
    });
    // @ts-expect-error -- nor with one whose operation is any string, though it is this one
    const typedLoosely = w.rotation.rotateNow({ ...base, approval: anyOperation });
    await expect(
      (await world()).rotation.rotateNow({ ...base, approval: retire as never })
    ).rejects.toMatchObject({ reason: 'other_operation' });
    // At run time, an approval of exactly this rotation is one, whatever its static type.
    await expect(typedLoosely).resolves.toMatchObject({ approvalId: anyOperation.id });

    const afterLoose = snapshot(w);
    const valid = approvalOf({ realmId: REALM, purpose: 'token_signing' });
    for (const malformed of [
      'approved',
      { ...valid, id: 'approval-1' },
      { ...valid, nonce: 'short' },
      { ...valid, requester: { kind: 'human' } },
      { ...valid, consume: undefined },
      { ...valid, operation: undefined },
    ]) {
      await expect(
        w.rotation.rotateNow({ ...base, approval: malformed as never }),
        JSON.stringify(malformed)
      ).rejects.toMatchObject({ name: 'OperationApprovalError', reason: 'malformed' });
    }
    const noAudit = { ...base, approval: valid, onAudit: undefined };
    // @ts-expect-error -- nor without its audit hook
    await expect(w.rotation.rotateNow(noAudit)).rejects.toThrow(TypeError);
    expect(valid.uses).toEqual([]);
    expect(snapshot(w)).toEqual(afterLoose);
    expect(afterLoose).toHaveLength(before.length + 1);
  });

  it('refuses an approval filed for another realm, purpose or requester, and changes nothing', async () => {
    const w = await world();
    const before = snapshot(w);
    for (const approval of [
      approvalOf({ realmId: OTHER_REALM, purpose: 'token_signing' }),
      approvalOf({ realmId: REALM, purpose: 'event_signing' }),
      {
        ...approvalOf({ realmId: REALM, purpose: 'token_signing' }),
        requester: { ...ADMIN, accountId: 'other' },
      },
    ]) {
      const refused = rotateNow(w, 'token_signing', { approval });
      await expect(refused).rejects.toBeInstanceOf(OperationApprovalError);
      await expect(refused).rejects.toMatchObject({ reason: 'refused', statusCode: 403 });
    }
    // A used approval approves nothing more.
    const once = approvalOf({ realmId: REALM, purpose: 'token_signing' });
    await rotateNow(w, 'token_signing', { approval: once });
    const after = snapshot(w);
    await expect(rotateNow(w, 'token_signing', { approval: once })).rejects.toMatchObject({
      reason: 'refused',
    });
    expect(snapshot(w)).toEqual(after);
    expect(after.length).toBe(before.length + 1);
  });

  it('passes a fault of the approval on as it is, and takes a refusal from any copy of the module', async () => {
    const w = await world();
    const before = snapshot(w);
    const failing = (error: Error): TestApproval => ({
      ...approvalOf({ realmId: REALM, purpose: 'token_signing' }),
      consume: async () => {
        throw error;
      },
    });
    // A serialization failure is no refusal: the caller may retry it.
    const fault = Object.assign(new Error('could not serialize access'), { code: '40001' });
    await expect(rotateNow(w, 'token_signing', { approval: failing(fault) })).rejects.toBe(fault);
    const foreign = Object.assign(new Error('used already'), {
      code: 'OPERATION_APPROVAL_REFUSED',
    });
    await expect(
      rotateNow(w, 'token_signing', { approval: failing(foreign) })
    ).rejects.toMatchObject({ name: 'OperationApprovalError', reason: 'refused', cause: foreign });
    expect(snapshot(w)).toEqual(before);
  });

  it('creates the next key at once and publishes it; it signs only after the pre-publication window', async () => {
    const w = await world();
    const signer = w.signer();
    w.clock.now = T0 + 10 * DAY;
    const oldKid = await kidOf(await signer.signJws('local', accessToken(w.clock.now)));

    const record = await rotateNow(w, 'token_signing');
    expect(record.next).toEqual([
      {
        algorithm: 'EdDSA',
        keys: [{ kid: expect.any(String), algorithm: 'EdDSA' }],
        created: true,
        activatesAt: T0 + 17 * DAY,
      },
    ]);
    const newKid = record.next[0].keys[0].kid;
    expect(stored(w, 'token_signing')).toEqual([
      { kid: oldKid, algorithm: 'EdDSA', status: 'active' },
      { kid: newKid, algorithm: 'EdDSA', status: 'next' },
    ]);
    // The key carries the moment it was approved to sign: the scheduled rotation reads it.
    expect(w.keys.rows.find((row) => row.key.kid === newKid)?.key.activateAt).toBe(T0 + 17 * DAY);
    // Published at once, and signs nothing yet; no verifier accepts it before it signs (#899).
    w.clock.now += REFRESH_MS;
    expect(await jwksKids(signer)).toContain(newKid);
    expect(await kidOf(await signer.signJws('local', accessToken(w.clock.now)))).toBe(oldKid);
    const verification = await signer.getVerificationKeys('local', REALM, 'token_signing');
    expect(verification.map((key) => key.kid)).not.toContain(newKid);

    // The scheduled rotation writes the switch once the window has run, long before day 90.
    w.clock.now = T0 + 17 * DAY - 1;
    expect(stepOf((await w.run()).steps, 'token_signing', 'rotated')).toEqual([]);
    w.clock.now = T0 + 17 * DAY;
    const step = rotatedStep((await w.run()).steps, 'token_signing');
    expect(step).toMatchObject({
      activated: [{ kid: newKid }],
      retired: [{ kid: oldKid }],
      switchAt: T0 + 17 * DAY + KEY_ACTIVATION_DELAY_MS,
      retainedUntil: T0 + 17 * DAY + KEY_ACTIVATION_DELAY_MS + 14 * DAY,
    });
    w.clock.now = step.switchAt - 1;
    expect(await kidOf(await signer.signJws('local', accessToken(w.clock.now)))).toBe(oldKid);
    w.clock.now = step.switchAt;
    expect(await kidOf(await signer.signJws('local', accessToken(w.clock.now)))).toBe(newKid);
  });

  it('returns the next key that waits already, and creates no second one', async () => {
    const w = await world();
    w.clock.now = T0 + 10 * DAY;
    const first = await rotateNow(w, 'token_signing');
    w.clock.now = T0 + 11 * DAY;
    const second = await rotateNow(w, 'token_signing');
    expect(second.next).toEqual([{ ...first.next[0], created: false }]);
    expect(stored(w, 'token_signing').filter((key) => key.status === 'next')).toHaveLength(1);
    // The scheduled rotation's own next key is the rotation's key too.
    w.clock.now = T0 + 83 * DAY;
    const job = await w.run();
    const [created] = stepOf(job.steps, 'event_signing', 'next_created');
    const waiting = await rotateNow(w, 'event_signing');
    expect(waiting.next).toEqual([
      {
        algorithm: 'EdDSA',
        keys: created.kind === 'next_created' ? created.keys : [],
        created: false,
        activatesAt: T0 + 90 * DAY,
      },
    ]);
  });

  it('keeps a next key an operator made by hand to its own schedule: it waits for the period', async () => {
    const w = await world();
    w.clock.now = T0 + 10 * DAY;
    const byHand = createKeyFactory({
      store: w.keys,
      kekProvider: localProvider({ KEK: KEK_A }),
      enabledSignatureAlgorithms: ED25519_ONLY,
      hybridSigning: false,
      now: () => w.clock.now,
    });
    const [made] = await byHand.createKey({
      realmId: REALM,
      purpose: 'token_signing',
      status: 'next',
    });
    expect(made.activateAt).toBeNull();
    // No approval cut the period short, so its window alone does not switch it (#542).
    w.clock.now = T0 + 17 * DAY;
    expect(stepOf((await w.run()).steps, 'token_signing', 'rotated')).toEqual([]);

    w.clock.now = T0 + 20 * DAY;
    const kept = await rotateNow(w, 'token_signing');
    expect(kept.next).toEqual([
      {
        algorithm: 'EdDSA',
        keys: [{ kid: made.kid, algorithm: 'EdDSA' }],
        created: false,
        activatesAt: T0 + 90 * DAY,
      },
    ]);
    w.clock.now = T0 + 90 * DAY - 1;
    expect(stepOf((await w.run()).steps, 'token_signing', 'rotated')).toEqual([]);
    w.clock.now = T0 + 90 * DAY;
    expect(rotatedStep((await w.run()).steps, 'token_signing')).toMatchObject({
      activated: [{ kid: made.kid }],
    });
  });

  it('rotates both keys of a hybrid pair together', async () => {
    const w = await world({ hybrid: true });
    w.clock.now = T0 + DAY;
    const steps: NextKeyCreatedStep[] = [];
    const record = await rotateNow(w, 'token_signing', {
      onStep: async (step) => {
        steps.push(step);
      },
    });
    expect(record.next).toHaveLength(1);
    expect(record.next[0].keys.map((key) => key.algorithm)).toEqual(['EdDSA', 'ML-DSA-65']);
    expect(steps).toEqual([
      {
        kind: 'next_created',
        realmId: REALM,
        purpose: 'token_signing',
        keys: record.next[0].keys,
        activatesAt: T0 + 8 * DAY,
      },
    ]);
    const next = w.keys.rows.filter(
      (row) => row.key.purpose === 'token_signing' && row.key.status === 'next'
    );
    expect(next).toHaveLength(2);
    expect(next[0].key.pairId).not.toBeNull();
    expect(next[0].key.pairId).toBe(next[1].key.pairId);

    w.clock.now = T0 + 8 * DAY;
    const step = rotatedStep((await w.run()).steps, 'token_signing');
    expect(step.activated.map((key) => key.kid)).toEqual(record.next[0].keys.map((key) => key.kid));
    expect(step.retired.map((key) => key.algorithm).sort()).toEqual(['EdDSA', 'ML-DSA-65']);
  });

  it('calls the audit hook once per operation, with the actor and the approval id, in its transaction', async () => {
    const w = await world();
    w.clock.now = T0 + DAY;
    const approval = approvalOf({ realmId: REALM, purpose: 'cookie_hmac' });
    const calls: string[] = [];
    const audits: { entry: KeyRotationNowRecord; tx: MemoryTx }[] = [];
    const record = await rotateNow(w, 'cookie_hmac', {
      approval,
      onStep: async () => {
        calls.push('step');
      },
      onAudit: async (entry, tx) => {
        calls.push('audit');
        audits.push({ entry, tx });
      },
    });
    expect(audits).toHaveLength(1);
    const [{ entry, tx }] = audits;
    expect(entry).toBe(record);
    expect(entry).toMatchObject({
      operation: 'keys.rotate',
      approvalId: approval.id,
      actor: ADMIN,
      realmId: REALM,
      purpose: 'cookie_hmac',
      scopeId: null,
    });
    // The digest the approval was consumed for, in the same transaction.
    expect(approval.uses).toEqual([{ digest: entry.operationDigest, tx }]);
    expect(calls).toEqual(['step', 'audit']);

    // A second operation is audited once more, though it creates nothing.
    const again = vi.fn<(entry: KeyRotationNowRecord, tx: MemoryTx) => Promise<void>>(
      async () => undefined
    );
    await rotateNow(w, 'cookie_hmac', { onAudit: again });
    expect(again).toHaveBeenCalledTimes(1);
    expect(again.mock.calls[0][0]).toMatchObject({ next: [{ created: false }] });
  });

  it('rolls the new key back when the audit hook fails', async () => {
    const w = await world();
    const before = snapshot(w);
    await expect(
      rotateNow(w, 'token_signing', {
        onAudit: async () => {
          throw new Error('audit write failed');
        },
      })
    ).rejects.toThrow('audit write failed');
    expect(snapshot(w)).toEqual(before);
  });

  it.each([
    ['a scoped purpose', 'webhook_signing', {}, 'NOT_A_ROTATING_PURPOSE'],
    [
      'a purpose that rotates by its own operation',
      'federation_entity',
      {},
      'NOT_A_ROTATING_PURPOSE',
    ],
    ['a scope id', 'token_signing', { scopeId: 'sub-1' }, 'SCOPE_NOT_ALLOWED'],
    ['a realm with no key of the purpose', 'oid4vp_response_encryption', {}, 'NO_ACTIVE_KEY'],
    ['an unknown purpose', 'signing', {}, 'UNKNOWN_PURPOSE'],
    ['a malformed realm id', 'token_signing', { realmId: 'realm-1' }, 'INVALID_REALM_ID'],
  ] as const)('refuses %s, with the approval unused', async (_name, purpose, overrides, reason) => {
    const w = await world();
    const before = snapshot(w);
    const approval = approvalOf({
      realmId: REALM,
      purpose: purpose === 'signing' ? 'token_signing' : purpose,
    });
    await expect(
      rotateNow(w, purpose as KeyPurpose, { approval, ...overrides })
    ).rejects.toMatchObject({ name: 'KeyChangeRefusedError', reason });
    expect(approval.uses).toEqual([]);
    expect(snapshot(w)).toEqual(before);
  });
});
