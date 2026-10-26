import { randomBytes } from 'node:crypto';

import { isKeyCustodyError } from '@qauth-labs/server-keys';
import { KEY_AAD_VERSION, type KeyAad } from '@qauth-labs/server-keys/custody';
import { createManualClock, type ManualClock } from '@qauth-labs/shared-testing';
import { afterAll, describe, expect, it, vi } from 'vitest';

import {
  appRoleEnv,
  createSecretFiles,
  DOUBLE_KEY,
  doubleProvider,
  tokenFileEnv,
} from '../testing/double-provider';
import { createVaultDouble, signerPolicy, type VaultDouble } from '../testing/vault-double';
import { createVaultClient, type VaultClock } from './vault-client';
import { createTokenSession, RENEW_AT_FRACTION, tokenFileCredentials } from './vault-token';

const files = createSecretFiles();
afterAll(() => files.cleanup());

const AAD: KeyAad = Object.freeze({
  realmId: '7b0e9a52-6f7c-4c55-9e43-2d7f1c0a9b11',
  purpose: 'token_signing',
  scopeId: null,
  kid: 'kid-1',
  algorithm: 'EdDSA',
  version: KEY_AAD_VERSION,
});

const START = Date.parse('2026-10-26T00:00:00Z');
const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

function vault(): { double: VaultDouble; clock: ManualClock } {
  const clock = createManualClock(START);
  const double = createVaultDouble(clock);
  double.createKey(DOUBLE_KEY);
  return { double, clock };
}

function paths(double: VaultDouble, path: string) {
  return double.requests.filter((request) => request.path === path);
}

/** Wait for the work a timer started, which runs on real I/O promises. */
async function flush(): Promise<void> {
  for (let i = 0; i < 5; i++) await new Promise((resolve) => setImmediate(resolve));
}

describe('logging in', () => {
  it('makes no Vault call when the provider is created; the first wrap logs in', async () => {
    const { double, clock } = vault();
    const provider = doubleProvider(double, { env: tokenFileEnv(double, files).env, clock });

    expect(double.requests).toEqual([]);
    await provider.wrap(randomBytes(32), AAD);
    expect(paths(double, 'auth/token/lookup-self')).toHaveLength(1);
  });

  it('logs in once for calls that arrive together', async () => {
    const { double, clock } = vault();
    const provider = doubleProvider(double, { env: appRoleEnv(double, files).env, clock });
    const sealed = await provider.wrap(randomBytes(32), AAD);
    const restarted = doubleProvider(double, { env: appRoleEnv(double, files).env, clock });
    double.requests.length = 0;

    await Promise.all(
      Array.from({ length: 10 }, () => restarted.unwrap(sealed.wrapped, AAD, sealed.kekRef))
    );

    expect(paths(double, 'auth/approle/login')).toHaveLength(1);
    expect(paths(double, `transit/keys/${DOUBLE_KEY}`)).toHaveLength(1);
  });

  it('reads the AppRole secret ID from its file at each login, and logs in on the configured mount', async () => {
    const clock = createManualClock(START);
    const double = createVaultDouble(clock);
    double.createKey(DOUBLE_KEY);
    const role = double.createAppRole({
      tokenTtlMs: HOUR,
      tokenMaxTtlMs: HOUR,
      policy: signerPolicy(DOUBLE_KEY),
      mount: 'machines/approle',
    });
    const secretIdFile = files.write('not-the-secret-id');
    const provider = doubleProvider(double, {
      env: {
        KEK_VAULT_ROLE_ID: role.roleId,
        KEK_VAULT_SECRET_ID_FILE: secretIdFile,
        KEK_VAULT_APPROLE_MOUNT: 'machines/approle',
      },
      clock,
    });

    const error = await provider.wrap(randomBytes(32), AAD).catch((reason: unknown) => reason);
    expect(isKeyCustodyError(error, 'KEK_ACCESS_DENIED')).toBe(true);

    files.rewrite(secretIdFile, role.secretId);
    await provider.wrap(randomBytes(32), AAD);
    const logins = paths(double, 'auth/machines/approle/login');
    expect(logins).toHaveLength(2);
    expect(logins[1].body).toEqual({ role_id: role.roleId, secret_id: role.secretId });
    expect(logins[1].token).toBeUndefined();
  });
});

describe('renewing the token', () => {
  it('renews a token from a file once two thirds of its TTL have passed, and keeps it alive while idle', async () => {
    const { double, clock } = vault();
    const login = tokenFileEnv(double, files, { ttlMs: HOUR, maxTtlMs: 24 * HOUR });
    const provider = doubleProvider(double, { env: login.env, clock });
    await provider.wrap(randomBytes(32), AAD);

    await clock.advanceBy(HOUR * RENEW_AT_FRACTION - MINUTE);
    await flush();
    expect(paths(double, 'auth/token/renew-self')).toHaveLength(0);
    await clock.advanceBy(2 * MINUTE);
    await flush();
    expect(paths(double, 'auth/token/renew-self')).toHaveLength(1);
    expect(double.tokenExpiry(login.token)).toBe(clock.now() + HOUR - MINUTE);

    // Five idle hours: the timer keeps renewing, and the token still works.
    for (let hour = 0; hour < 5 * 6; hour++) {
      await clock.advanceBy(10 * MINUTE);
      await flush();
    }
    await provider.wrap(randomBytes(32), AAD);
    expect(paths(double, 'auth/token/lookup-self')).toHaveLength(1);
    expect(paths(double, 'auth/token/renew-self').length).toBeGreaterThanOrEqual(7);
    expect(new Set(double.requests.map((request) => request.token))).toEqual(
      new Set([login.token])
    );
  });

  it('logs in again with AppRole when a renewal no longer extends the token, before it expires', async () => {
    const { double, clock } = vault();
    const provider = doubleProvider(double, {
      env: appRoleEnv(double, files, { tokenTtlMs: 10 * MINUTE, tokenMaxTtlMs: 30 * MINUTE }).env,
      clock,
    });
    await provider.wrap(randomBytes(32), AAD);
    const first = paths(double, 'auth/approle/login');
    expect(first).toHaveLength(1);

    for (let step = 0; step < 45; step++) {
      await clock.advanceBy(MINUTE);
      await flush();
    }

    expect(paths(double, 'auth/approle/login').length).toBeGreaterThanOrEqual(2);
    // No call ever went out with an expired token.
    expect(double.requests.filter((request) => request.status === 403)).toEqual([]);
    double.requests.length = 0;
    await provider.wrap(randomBytes(32), AAD);
    expect(paths(double, 'auth/approle/login')).toHaveLength(0);
  });

  it('replaces an expired token at its next use: AppRole logs in again and the call succeeds', async () => {
    const { double, clock } = vault();
    const provider = doubleProvider(double, {
      env: appRoleEnv(double, files, { tokenTtlMs: 10 * MINUTE, tokenMaxTtlMs: HOUR }).env,
      clock,
    });
    await provider.wrap(randomBytes(32), AAD);
    // Vault cannot be reached for renewals or logins while the token runs out.
    double.failNext(
      { error: Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }) },
      { times: 1_000, path: /renew-self|login/ }
    );
    for (let step = 0; step < 15; step++) {
      await clock.advanceBy(MINUTE);
      await flush();
    }
    double.clearFaults();
    double.requests.length = 0;

    await provider.wrap(randomBytes(32), AAD);

    expect(double.requests[0].path).toBe('auth/approle/login');
    expect(double.requests.filter((request) => request.status === 403)).toEqual([]);
  });

  it('reads a token file again at its maximum TTL, so a token the agent rewrote is used', async () => {
    const { double, clock } = vault();
    const login = tokenFileEnv(double, files, { ttlMs: 10 * MINUTE, maxTtlMs: 20 * MINUTE });
    const provider = doubleProvider(double, { env: login.env, clock });
    await provider.wrap(randomBytes(32), AAD);

    const next = double.createToken({
      ttlMs: HOUR,
      maxTtlMs: 24 * HOUR,
      policy: signerPolicy(DOUBLE_KEY),
    });
    files.rewrite(login.path, next);
    for (let step = 0; step < 25; step++) {
      await clock.advanceBy(MINUTE);
      await flush();
    }
    double.requests.length = 0;

    await provider.wrap(randomBytes(32), AAD);

    expect(new Set(double.requests.map((request) => request.token))).toEqual(new Set([next]));
  });

  it('keeps a token from a file it cannot extend until it expires, then fails with KEK_ACCESS_DENIED', async () => {
    const { double, clock } = vault();
    const login = tokenFileEnv(double, files, { ttlMs: 10 * MINUTE, maxTtlMs: 20 * MINUTE });
    const provider = doubleProvider(double, { env: login.env, clock });
    await provider.wrap(randomBytes(32), AAD);

    await clock.advanceBy(15 * MINUTE);
    await flush();
    await provider.wrap(randomBytes(32), AAD);
    for (let step = 0; step < 10; step++) {
      await clock.advanceBy(MINUTE);
      await flush();
    }

    const error = await provider.wrap(randomBytes(32), AAD).catch((reason: unknown) => reason);
    expect(isKeyCustodyError(error, 'KEK_ACCESS_DENIED')).toBe(true);
    expect(JSON.stringify(error) + String(error) + String((error as Error).cause)).not.toContain(
      login.token
    );
  });

  it('never renews a token that does not expire, such as a root token', async () => {
    const { double, clock } = vault();
    const provider = doubleProvider(double, {
      env: { KEK_VAULT_TOKEN_FILE: files.write(double.rootToken) },
      clock,
    });
    await provider.wrap(randomBytes(32), AAD);

    expect(clock.pending()).toEqual([]);
  });

  it('tries a renewal Vault could not answer again while the token lasts', async () => {
    const { double, clock } = vault();
    const login = tokenFileEnv(double, files, { ttlMs: HOUR, maxTtlMs: 24 * HOUR });
    const provider = doubleProvider(double, { env: login.env, clock });
    await provider.wrap(randomBytes(32), AAD);
    double.failNext({ status: 503 }, { times: 3, path: /renew-self/ });

    for (let step = 0; step < 50; step++) {
      await clock.advanceBy(MINUTE);
      await flush();
    }

    const renewals = paths(double, 'auth/token/renew-self');
    expect(renewals.map((request) => request.status).slice(0, 4)).toEqual([503, 503, 503, 200]);
    expect(double.tokenExpiry(login.token)).toBeGreaterThan(START + HOUR);
  });
});

describe('the token session', () => {
  it('arms its renewal timer unreferenced, so it never holds the process open', async () => {
    const { double, clock } = vault();
    const unref = vi.fn();
    const timers = new Map<object, unknown>();
    const watched: VaultClock = {
      now: () => clock.now(),
      setTimeout(callback, delayMs) {
        const handle = { unref };
        timers.set(handle, clock.setTimeout(callback, delayMs));
        return handle;
      },
      clearTimeout(handle) {
        clock.clearTimeout(timers.get(handle as object));
      },
    };
    const login = tokenFileEnv(double, files, { ttlMs: HOUR });
    const session = createTokenSession({
      client: createVaultClient({ transport: double.transport, clock: watched }),
      credentials: tokenFileCredentials(login.path, 'KEK_VAULT_TOKEN_FILE'),
      clock: watched,
    });

    expect(await session.token()).toBe(login.token);

    expect(unref).toHaveBeenCalledTimes(1);
    session.close();
    expect(clock.pending()).toEqual([]);
  });

  it('drops a refused token only when it is the one it holds', async () => {
    const { double, clock } = vault();
    const login = tokenFileEnv(double, files);
    const session = createTokenSession({
      client: createVaultClient({ transport: double.transport, clock }),
      credentials: tokenFileCredentials(login.path, 'KEK_VAULT_TOKEN_FILE'),
      clock,
    });
    await session.token();

    // Another token: the caller may retry with the one held, which is kept.
    expect(await session.refused('hvs.some-other-token')).toBe(true);
    expect(await session.token()).toBe(login.token);
    expect(paths(double, 'auth/token/lookup-self')).toHaveLength(1);

    // A token Vault still accepts: the policy refused the call, nothing changes.
    expect(await session.refused(login.token)).toBe(false);
    expect(await session.token()).toBe(login.token);
    expect(paths(double, 'auth/token/lookup-self')).toHaveLength(2);

    // A token Vault no longer accepts: dropped, and the next use logs in again.
    double.revokeToken(login.token);
    expect(await session.refused(login.token)).toBe(true);
    const next = double.createToken({ ttlMs: HOUR, policy: signerPolicy(DOUBLE_KEY) });
    files.rewrite(login.path, next);
    expect(await session.token()).toBe(next);
    session.close();
  });

  it('holds a token from a file in its last second as expiring, not as one that never expires', async () => {
    const answers: Array<Record<string, unknown>> = [
      { ttl: 0, renewable: false, expire_time: '2026-10-26T00:00:01Z' },
      { ttl: 0, renewable: false, expire_time: null },
    ];
    const client = {
      send: vi.fn(async () => ({ status: 200, body: { data: answers.shift() } })),
    };
    const credentials = tokenFileCredentials(
      files.write('hvs.last-second'),
      'KEK_VAULT_TOKEN_FILE'
    );

    expect((await credentials.login(client)).ttlMs).toBe(1);
    expect((await credentials.login(client)).ttlMs).toBe(0);
  });
});
