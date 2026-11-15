import { createHmac } from 'node:crypto';

import {
  createCookieSecretIdentifierDigest,
  EMAIL_CODE_HMAC_LABEL,
  END_USER_IP_HMAC_LABEL,
  IDENTIFIER_HMAC_LABEL,
} from '@qauth-labs/fastify-plugin-sign-in-engine';
import { COOKIE_DERIVED_KEY_LABELS, deriveCookieKey } from '@qauth-labs/fastify-plugin-signer';
import { TemporarilyUnavailableError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { describe, expect, it } from 'vitest';

import { createFakeCookieSigner } from '../../testing/cookie-keys';
import {
  COOKIE_DERIVED_KEY_REFRESH_INTERVAL_MS,
  cookieDerivedKeyRing,
  createCookieDerivedKeyRing,
} from './cookie-derived-keys';
import { createServerDigests, createServerEmailCodeDigest } from './password-attempts';

const REALM = '00000000-0000-4000-8000-000000000001';

describe('the derived cookie keys (#497)', () => {
  it('names the labels the signer derives keys for, and no other', () => {
    // The sign-in engine's digests ask for these; the signer refuses any other.
    expect([IDENTIFIER_HMAC_LABEL, END_USER_IP_HMAC_LABEL, EMAIL_CODE_HMAC_LABEL]).toEqual([
      ...COOKIE_DERIVED_KEY_LABELS,
    ]);
  });

  it('reads a realm key once a minute per label, and shares a read in flight', async () => {
    let now = 1_000_000;
    const signer = createFakeCookieSigner();
    const ring = createCookieDerivedKeyRing(signer, { now: () => now });

    const [first, second] = await Promise.all([
      ring.derivedKey(REALM, IDENTIFIER_HMAC_LABEL),
      ring.derivedKey(REALM, IDENTIFIER_HMAC_LABEL),
    ]);
    expect(signer.getCookieDerivedKey).toHaveBeenCalledTimes(1);
    expect(signer.getCookieDerivedKey).toHaveBeenCalledWith('local', {
      realmId: REALM,
      label: IDENTIFIER_HMAC_LABEL,
    });
    // Each caller gets a buffer of its own, which it may zero.
    expect(first).toEqual(second);
    expect(first).not.toBe(second);
    first.fill(0);
    expect(await ring.derivedKey(REALM, IDENTIFIER_HMAC_LABEL)).toEqual(second);
    expect(signer.getCookieDerivedKey).toHaveBeenCalledTimes(1);

    await ring.derivedKey(REALM, END_USER_IP_HMAC_LABEL);
    expect(signer.getCookieDerivedKey).toHaveBeenCalledTimes(2);

    // A rotation reaches the key once the minute is up.
    signer.rotate(REALM);
    now += COOKIE_DERIVED_KEY_REFRESH_INTERVAL_MS - 1;
    expect(await ring.derivedKey(REALM, IDENTIFIER_HMAC_LABEL)).toEqual(second);
    now += 1;
    expect(await ring.derivedKey(REALM, IDENTIFIER_HMAC_LABEL)).not.toEqual(second);
  });

  it('zeroes the key the signer handed out, and keeps nothing when the read fails', async () => {
    const signer = createFakeCookieSigner();
    const handed: Buffer[] = [];
    const real = signer.getCookieDerivedKey.getMockImplementation();
    signer.getCookieDerivedKey.mockImplementation(async (caller, request) => {
      const answer = await real!(caller, request);
      handed.push(answer.key);
      return answer;
    });
    const ring = createCookieDerivedKeyRing(signer);
    const key = await ring.derivedKey(REALM, IDENTIFIER_HMAC_LABEL);
    expect(handed[0]?.every((byte) => byte === 0)).toBe(true);
    expect(key.some((byte) => byte !== 0)).toBe(true);

    signer.getCookieDerivedKey.mockRejectedValueOnce(new TemporarilyUnavailableError(60));
    await expect(ring.derivedKey(REALM, EMAIL_CODE_HMAC_LABEL)).rejects.toMatchObject({
      name: 'TemporarilyUnavailableError',
    });
    await expect(ring.derivedKey(REALM, EMAIL_CODE_HMAC_LABEL)).resolves.toBeInstanceOf(Buffer);
  });

  it("makes the server's digests as the cookie secret makes them, with no cookie secret read", async () => {
    const signer = createFakeCookieSigner();
    const fastify = { signer } as unknown as FastifyInstance;
    const { identifierDigest, ipDigest } = createServerDigests(fastify);
    const input = { realmId: REALM, identifier: 'someone@example.com' };

    const fromSecret = createFakeCookieSigner();
    expect(await identifierDigest(input)).toBe(
      await createCookieSecretIdentifierDigest(fromSecret, 'local')(input)
    );
    expect(await ipDigest(input)).toBe(
      await createCookieSecretIdentifierDigest(fromSecret, 'local', END_USER_IP_HMAC_LABEL)(input)
    );
    const code = { realmId: REALM, salt: 's'.repeat(22), code: '012345' };
    const { current } = await fromSecret.getCookieSecrets('local', REALM);
    expect(await createServerEmailCodeDigest(fastify)(code)).toBe(
      createHmac('sha256', deriveCookieKey(current.secret, EMAIL_CODE_HMAC_LABEL))
        .update(`${REALM}\u0000${code.salt}\u0000${code.code}`)
        .digest('base64url')
    );
    expect(signer.getCookieSecrets).not.toHaveBeenCalled();
    // One ring per signer: the digests share its cache.
    expect(cookieDerivedKeyRing(fastify)).toBe(cookieDerivedKeyRing(fastify));
  });
});
