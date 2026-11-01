import {
  NO_HARD_ACTION,
  type PasswordHardAction,
  SignInStoreUnavailableError,
} from '@qauth-labs/server-sign-in-engine';
import { createMemoryLadder } from '@qauth-labs/server-sign-in-engine/src/testing/memory-ladder';
import { describe, expect, it, vi } from 'vitest';

import { createPasswordAttempts } from './password-attempts';
import {
  createHardActionArming,
  createPasswordHardAction,
  type HardActionCredentials,
  PASSWORD_DISABLED_ALERT,
  type PasswordDisabledNotices,
} from './password-hard-action';

const REALM = '0199fa20-0000-7000-8000-00000000aaaa';
const USER = '0199fa20-5e1a-7000-8000-000000000001';
const IDENTIFIER = 'alice@example.com';
const TARGET = { realmId: REALM, userId: USER, identifier: IDENTIFIER };

function credentials(marked = true) {
  return {
    setDisabledAt: vi.fn<HardActionCredentials['setDisabledAt']>(async () =>
      marked ? { id: 'cred-1' } : undefined
    ),
    clearDisabledAt: vi.fn<HardActionCredentials['clearDisabledAt']>(async () => ({
      id: 'cred-1',
    })),
  };
}

function notices(canSend = true): PasswordDisabledNotices & {
  passwordDisabled: ReturnType<typeof vi.fn>;
} {
  return {
    canSend: vi.fn(async () => canSend),
    passwordDisabled: vi.fn(async () => undefined),
  };
}

function log() {
  return { warn: vi.fn(), error: vi.fn() };
}

/** Every value a log call carried, as text: none may be the identifier. */
const logged = (sink: ReturnType<typeof log>) =>
  JSON.stringify([...sink.warn.mock.calls, ...sink.error.mock.calls]);

describe('the hard action’s arming', () => {
  it('is armed only while the hosted reset is on and the notice can be sent', async () => {
    const on = notices();
    expect(await createHardActionArming({ hostedReset: () => true, notices: on })(REALM)).toBe(
      true
    );
    expect(on.canSend).toHaveBeenCalledWith(REALM);
    expect(await createHardActionArming({ hostedReset: () => true })(REALM)).toBe(false);
    expect(await createHardActionArming({ hostedReset: () => false, notices: on })(REALM)).toBe(
      false
    );
    expect(
      await createHardActionArming({ hostedReset: async () => true, notices: notices(false) })(
        REALM
      )
    ).toBe(false);
  });

  it('asks at every call, so turning either off disarms it at once', async () => {
    let reset = true;
    const armed = createHardActionArming({ hostedReset: () => reset, notices: notices() });
    expect(await armed(REALM)).toBe(true);
    reset = false;
    expect(await armed(REALM)).toBe(false);
  });

  it('rejects when a source fails, so the caller fails closed', async () => {
    const armed = createHardActionArming({
      hostedReset: () => {
        throw new Error('settings unreadable');
      },
      notices: notices(),
    });
    await expect(armed(REALM)).rejects.toThrow('settings unreadable');
  });
});

describe('the password hard action', () => {
  it('changes nothing while unarmed, and warns', async () => {
    const stores = credentials();
    const sink = log();
    const action = createPasswordHardAction({
      credentials: stores,
      armed: async () => false,
      notices: notices(),
      log: sink,
    });
    await action.ceilingReached(TARGET);
    expect(stores.setDisabledAt).not.toHaveBeenCalled();
    expect(sink.warn).toHaveBeenCalledWith(
      expect.objectContaining({ realmId: REALM, userId: USER, reason: 'hard_action_unarmed' }),
      expect.any(String)
    );
    expect(sink.error).not.toHaveBeenCalled();
  });

  it('marks the password, alerts the operator and notifies the owner once, while armed', async () => {
    const stores = credentials();
    const notice = notices();
    const sink = log();
    const action = createPasswordHardAction({
      credentials: stores,
      armed: async () => true,
      notices: notice,
      log: sink,
      now: () => 1_793_491_200_000,
    });
    await action.ceilingReached(TARGET);
    expect(stores.setDisabledAt).toHaveBeenCalledWith(
      REALM,
      'password',
      IDENTIFIER,
      1_793_491_200_000
    );
    expect(sink.error).toHaveBeenCalledWith(
      { realmId: REALM, userId: USER, credentialId: 'cred-1' },
      PASSWORD_DISABLED_ALERT
    );
    expect(notice.passwordDisabled).toHaveBeenCalledWith(TARGET);

    // A later failure past the ceiling finds the mark there: no second alert or notice.
    stores.setDisabledAt.mockResolvedValueOnce(undefined);
    await action.ceilingReached(TARGET);
    expect(sink.error).toHaveBeenCalledTimes(1);
    expect(notice.passwordDisabled).toHaveBeenCalledTimes(1);
    expect(logged(sink)).not.toContain(IDENTIFIER);
  });

  it('alerts a notice that could not be sent, and keeps the mark', async () => {
    const stores = credentials();
    const notice = notices();
    notice.passwordDisabled.mockRejectedValueOnce(new Error('smtp down'));
    const sink = log();
    const action = createPasswordHardAction({
      credentials: stores,
      armed: async () => true,
      notices: notice,
      log: sink,
    });
    await expect(action.ceilingReached(TARGET)).resolves.toBeUndefined();
    expect(sink.error).toHaveBeenCalledTimes(2);
    expect(sink.error.mock.calls[1][1]).toMatch(/not told/);
    expect(stores.clearDisabledAt).not.toHaveBeenCalled();
  });

  it('lets a store failure reject, for the caller to report', async () => {
    const stores = credentials();
    stores.setDisabledAt.mockRejectedValueOnce(new Error('db down'));
    const action = createPasswordHardAction({
      credentials: stores,
      armed: async () => true,
      notices: notices(),
      log: log(),
    });
    await expect(action.ceilingReached(TARGET)).rejects.toThrow('db down');
  });

  it('clears a mark the lookup ignored', async () => {
    const stores = credentials();
    const sink = log();
    const action = createPasswordHardAction({
      credentials: stores,
      armed: async () => false,
      log: sink,
    });
    await action.clearIgnoredMark(TARGET);
    expect(stores.clearDisabledAt).toHaveBeenCalledWith(REALM, 'password', IDENTIFIER);
    expect(sink.warn).toHaveBeenCalledTimes(1);
    expect(logged(sink)).not.toContain(IDENTIFIER);
  });
});

describe('the legacy routes’ gate onto the ladder', () => {
  function gate(
    overrides: Partial<{
      hardAction: PasswordHardAction;
      digest: () => Promise<string>;
    }> = {}
  ) {
    let clock = 1_793_491_200_000;
    const ladder = createMemoryLadder(() => clock);
    const hardAction = overrides.hardAction ?? {
      ceilingReached: vi.fn(async () => undefined),
      clearIgnoredMark: vi.fn(async () => undefined),
    };
    const sink = { error: vi.fn() };
    const attempts = createPasswordAttempts({
      identifierDigest: overrides.digest ?? (async ({ identifier }) => `hmac-${identifier.length}`),
      ladder,
      hardAction,
      hardActionArmed: async () => false,
      log: sink,
    });
    const reserve = (endUserIp?: string) =>
      attempts.reserve({
        realmId: REALM,
        identifier: IDENTIFIER,
        ...(endUserIp === undefined ? {} : { endUserIp }),
      });
    return {
      ladder,
      hardAction,
      sink,
      attempts,
      reserve,
      advance: (ms: number) => {
        clock += ms;
      },
    };
  }

  it('makes the sixth consecutive failure wait, and counts nothing it refuses', async () => {
    const { reserve, ladder } = gate();
    for (let i = 0; i < 5; i += 1) {
      const attempt = await reserve();
      if (attempt.kind !== 'reserved') throw new Error('expected a reservation');
      await attempt.failed(async () => null);
    }
    expect(await reserve()).toEqual({ kind: 'wait', retryAfterSeconds: 1 });
    expect(ladder.counter(REALM, `hmac-${IDENTIFIER.length}`, 'password')?.failures).toBe(5);
  });

  it('fails closed on a digest or ladder failure, before any credential is read', async () => {
    const failing = gate({
      digest: async () => {
        throw new Error('signer down');
      },
    });
    await expect(failing.reserve()).rejects.toBeInstanceOf(SignInStoreUnavailableError);
    const { attempts } = gate();
    const broken = createPasswordAttempts({
      identifierDigest: async () => 'hmac',
      ladder: {
        reserve: async () => {
          throw new Error('redis down');
        },
      },
      hardAction: NO_HARD_ACTION,
      hardActionArmed: attempts.hardActionArmed,
      log: { error: vi.fn() },
    });
    await expect(broken.reserve({ realmId: REALM, identifier: IDENTIFIER })).rejects.toMatchObject({
      port: 'ladder',
    });
  });

  it('asks for the account only at the hard ceiling, then calls the hard action', async () => {
    const { reserve, hardAction, advance } = gate();
    const account = vi.fn(async () => ({ userId: USER }));
    for (let n = 1; n <= 100; n += 1) {
      const attempt = await reserve();
      if (attempt.kind !== 'reserved') throw new Error(`attempt ${n} waited`);
      await attempt.failed(account);
      advance(15 * 60_000);
    }
    expect(account).toHaveBeenCalledTimes(1);
    expect(hardAction.ceilingReached).toHaveBeenCalledWith(TARGET);
  });

  it('calls no hard action for an account the route names as none', async () => {
    const { reserve, hardAction, advance } = gate();
    for (let n = 1; n <= 100; n += 1) {
      const attempt = await reserve();
      if (attempt.kind !== 'reserved') throw new Error(`attempt ${n} waited`);
      await attempt.failed(async () => null);
      advance(15 * 60_000);
    }
    expect(hardAction.ceilingReached).not.toHaveBeenCalled();
  });

  it('clears the counter on a success, and an ignored mark with it', async () => {
    const { reserve, ladder, hardAction } = gate();
    const first = await reserve();
    if (first.kind !== 'reserved') throw new Error('expected a reservation');
    await first.failed(async () => null);
    const second = await reserve('203.0.113.7');
    if (second.kind !== 'reserved') throw new Error('expected a reservation');
    await second.succeeded({ userId: USER, ignoredMark: true });
    expect(ladder.counter(REALM, `hmac-${IDENTIFIER.length}`, 'password')).toBeUndefined();
    expect(hardAction.clearIgnoredMark).toHaveBeenCalledWith(TARGET);
    expect([...ladder.knownIps(REALM, `hmac-${IDENTIFIER.length}`).keys()]).toEqual([
      '203.0.113.7',
    ]);
  });

  it('never throws from a settle or a hard action that fails, and logs it', async () => {
    const failingAction: PasswordHardAction = {
      ceilingReached: async () => {
        throw new Error('db down');
      },
      clearIgnoredMark: async () => {
        throw new Error('db down');
      },
    };
    const { reserve, sink, advance } = gate({ hardAction: failingAction });
    for (let n = 1; n < 100; n += 1) {
      const attempt = await reserve();
      if (attempt.kind !== 'reserved') throw new Error(`attempt ${n} waited`);
      await attempt.failed(async () => null);
      advance(15 * 60_000);
    }
    const hundredth = await reserve();
    if (hundredth.kind !== 'reserved') throw new Error('expected a reservation');
    await expect(hundredth.failed(async () => ({ userId: USER }))).resolves.toBeUndefined();
    advance(15 * 60_000);
    const success = await reserve();
    if (success.kind !== 'reserved') throw new Error('expected a reservation');
    await expect(success.succeeded({ userId: USER, ignoredMark: true })).resolves.toBeUndefined();
    expect(sink.error).toHaveBeenCalledTimes(2);
    await expect(success.succeeded({ userId: USER, ignoredMark: false })).rejects.toThrow(
      /settled twice/
    );
  });
});
