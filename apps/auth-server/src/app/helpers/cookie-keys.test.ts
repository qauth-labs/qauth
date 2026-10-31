import { createHmac, type KeyObject } from 'node:crypto';

import { TemporarilyUnavailableError } from '@qauth-labs/shared-errors';
import { describe, expect, it, vi } from 'vitest';

import { createFakeCookieSigner } from '../../testing/cookie-keys';
import {
  COOKIE_KEY_FORCED_REFRESH_INTERVAL_MS,
  COOKIE_KEY_REFRESH_INTERVAL_MS,
  cookieKeyRing,
  type CookieSecretSource,
  createCookieKeyRing,
} from './cookie-keys';

const REALM_A = '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e01';
const REALM_B = '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e02';

/** A clock the test moves by hand. */
function manualClock(start = 1_800_000_000_000) {
  let time = start;
  return {
    now: () => time,
    advance(ms: number) {
      time += ms;
    },
  };
}

function mac(key: { key: KeyObject }, text: string): string {
  return createHmac('sha256', key.key).update(text).digest('base64url');
}

describe('createCookieKeyRing (#493)', () => {
  it('asks the signer once per realm within the refresh interval, as the local caller', async () => {
    const signer = createFakeCookieSigner();
    const clock = manualClock();
    const ring = createCookieKeyRing(signer, { now: clock.now });

    await ring.keys(REALM_A);
    clock.advance(COOKIE_KEY_REFRESH_INTERVAL_MS - 1);
    await ring.keys(REALM_A);
    await ring.find(REALM_A, (await ring.keys(REALM_A)).current.kid);

    expect(signer.getCookieSecrets).toHaveBeenCalledTimes(1);
    expect(signer.getCookieSecrets).toHaveBeenCalledWith('local', REALM_A);
    await ring.keys(REALM_B);
    expect(signer.getCookieSecrets).toHaveBeenCalledTimes(2);
  });

  it('refreshes every 60 seconds by default and then sees a rotation', async () => {
    expect(COOKIE_KEY_REFRESH_INTERVAL_MS).toBe(60_000);
    const signer = createFakeCookieSigner();
    const clock = manualClock();
    const ring = createCookieKeyRing(signer, { now: clock.now });
    const before = await ring.keys(REALM_A);

    signer.rotate(REALM_A);
    expect((await ring.keys(REALM_A)).current.kid).toBe(before.current.kid);
    clock.advance(COOKIE_KEY_REFRESH_INTERVAL_MS);
    const after = await ring.keys(REALM_A);

    expect(signer.getCookieSecrets).toHaveBeenCalledTimes(2);
    expect(after.current.kid).not.toBe(before.current.kid);
    expect(after.previous?.kid).toBe(before.current.kid);
  });

  it('shares one signer read between concurrent callers', async () => {
    const signer = createFakeCookieSigner();
    const ring = createCookieKeyRing(signer);

    await Promise.all([ring.keys(REALM_A), ring.keys(REALM_A), ring.find(REALM_A, 'x')]);

    expect(signer.getCookieSecrets).toHaveBeenCalledTimes(1);
  });

  it('reads again for a kid it does not know, at most once per forced-refresh interval', async () => {
    const signer = createFakeCookieSigner();
    const clock = manualClock();
    const ring = createCookieKeyRing(signer, { now: clock.now });
    const before = await ring.keys(REALM_A);
    // Another process already signs with the next key.
    signer.rotate(REALM_A);
    const next = (await signer.getCookieSecrets('local', REALM_A)).current.kid;
    signer.getCookieSecrets.mockClear();

    // Within the forced-refresh interval of the last read: no read.
    expect(await ring.find(REALM_A, next)).toBeNull();
    expect(signer.getCookieSecrets).not.toHaveBeenCalled();

    clock.advance(COOKIE_KEY_FORCED_REFRESH_INTERVAL_MS);
    const found = await ring.find(REALM_A, next);
    expect(found?.kid).toBe(next);
    expect((await ring.find(REALM_A, before.current.kid))?.kid).toBe(before.current.kid);
    expect(signer.getCookieSecrets).toHaveBeenCalledTimes(1);

    // Made-up kids cost at most one read per interval.
    for (let i = 0; i < 20; i++) expect(await ring.find(REALM_A, `made-up-${i}`)).toBeNull();
    expect(signer.getCookieSecrets).toHaveBeenCalledTimes(1);
  });

  it('caches no failure: the next call asks the signer again', async () => {
    const signer = createFakeCookieSigner();
    signer.getCookieSecrets.mockRejectedValueOnce(new TemporarilyUnavailableError(60));
    const ring = createCookieKeyRing(signer);

    await expect(ring.keys(REALM_A)).rejects.toBeInstanceOf(TemporarilyUnavailableError);
    await expect(ring.keys(REALM_A)).resolves.toMatchObject({ current: expect.any(Object) });
    expect(signer.getCookieSecrets).toHaveBeenCalledTimes(2);
  });

  it('imports each secret and zeroes the buffer the signer handed out', async () => {
    const handedOut: Buffer[] = [];
    const secret = Buffer.alloc(32, 0x42);
    const source: CookieSecretSource = {
      getCookieSecrets: vi.fn(async () => {
        const copy = Buffer.from(secret);
        handedOut.push(copy);
        return { current: { kid: 'k1', secret: copy }, previous: null };
      }),
    };
    const ring = createCookieKeyRing(source);

    const { current } = await ring.keys(REALM_A);

    expect(handedOut[0].equals(Buffer.alloc(32))).toBe(true);
    // The imported key still holds the secret.
    expect(mac(current, 'x')).toBe(createHmac('sha256', secret).update('x').digest('base64url'));
  });
});

describe('cookieKeyRing', () => {
  it('keeps one ring per signer', async () => {
    const signer = createFakeCookieSigner();
    const other = createFakeCookieSigner();

    await cookieKeyRing({ signer }).keys(REALM_A);
    await cookieKeyRing({ signer }).keys(REALM_A);
    await cookieKeyRing({ signer: other }).keys(REALM_A);

    expect(signer.getCookieSecrets).toHaveBeenCalledTimes(1);
    expect(other.getCookieSecrets).toHaveBeenCalledTimes(1);
  });

  it('refuses an instance without a signer', () => {
    expect(() => cookieKeyRing({} as never)).toThrow(/fastify\.signer/);
  });
});
