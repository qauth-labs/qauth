import { describe, expect, it } from 'vitest';

import {
  ANDROID_APK_KEY_HASH_ORIGIN_PREFIX,
  InvalidWebAuthnOriginError,
  type InvalidWebAuthnOriginReason,
  isAndroidAppOrigin,
  isWebAuthnOriginForRpId,
  normaliseWebAuthnOrigin,
  rpIdCoversHost,
} from './webauthn-origin';

/** The reason `normaliseWebAuthnOrigin` gives for refusing `input`. */
function reasonFor(input: string): InvalidWebAuthnOriginReason {
  try {
    normaliseWebAuthnOrigin(input);
  } catch (error) {
    expect(error).toBeInstanceOf(InvalidWebAuthnOriginError);
    return (error as InvalidWebAuthnOriginError).reason;
  }
  throw new Error(`expected "${input}" to be refused`);
}

/** The base64url SHA-256 the Android documentation shows for a debug key. */
const APK_KEY_HASH = 'sYUC8p5I9SxqFernBPHmDxz_YVZXmVJdW8s-m3RTTqE';

describe('normaliseWebAuthnOrigin', () => {
  describe('web origins', () => {
    it('writes the origin as a browser does: lower case, default port dropped', () => {
      expect(normaliseWebAuthnOrigin('https://Auth.Example.com')).toBe('https://auth.example.com');
      expect(normaliseWebAuthnOrigin('https://auth.example.com:443')).toBe(
        'https://auth.example.com'
      );
      expect(normaliseWebAuthnOrigin('https://auth.example.com:8443')).toBe(
        'https://auth.example.com:8443'
      );
    });

    it('writes an internationalised name in punycode', () => {
      expect(normaliseWebAuthnOrigin('https://bücher.example')).toBe(
        'https://xn--bcher-kva.example'
      );
    });

    it('accepts plain http on localhost and names under it only', () => {
      expect(normaliseWebAuthnOrigin('http://localhost:5173')).toBe('http://localhost:5173');
      expect(normaliseWebAuthnOrigin('http://auth.localhost')).toBe('http://auth.localhost');
      expect(reasonFor('http://auth.example.com')).toBe('scheme');
      expect(reasonFor('ftp://auth.example.com')).toBe('scheme');
    });

    it('refuses anything beyond scheme, host and port, even a bare slash', () => {
      expect(reasonFor('https://auth.example.com/')).toBe('not_origin');
      expect(reasonFor('https://auth.example.com/ui/login')).toBe('not_origin');
      expect(reasonFor('https://auth.example.com?x=1')).toBe('not_origin');
      expect(reasonFor('https://auth.example.com#x')).toBe('not_origin');
      expect(reasonFor('https://user@auth.example.com')).toBe('not_origin');
    });

    it('refuses an IP address, which no RP ID can cover', () => {
      expect(reasonFor('https://192.0.2.1')).toBe('ip_literal');
      expect(reasonFor('https://[2001:db8::1]')).toBe('ip_literal');
    });

    it('refuses what is not a URL, and white space', () => {
      expect(reasonFor('auth.example.com')).toBe('malformed');
      expect(reasonFor('https://auth .example.com')).toBe('malformed');
      expect(reasonFor('')).toBe('malformed');
      expect(reasonFor(`https://${'a'.repeat(300)}.example`)).toBe('malformed');
    });
  });

  describe('Android app origins', () => {
    it('accepts the base64url SHA-256 of the signing certificate', () => {
      const origin = `${ANDROID_APK_KEY_HASH_ORIGIN_PREFIX}${APK_KEY_HASH}`;
      expect(normaliseWebAuthnOrigin(origin)).toBe(origin);
      expect(isAndroidAppOrigin(origin)).toBe(true);
    });

    it('refuses a hash of the wrong length, with padding, or in hex', () => {
      expect(reasonFor(`${ANDROID_APK_KEY_HASH_ORIGIN_PREFIX}${APK_KEY_HASH}=`)).toBe(
        'android_hash'
      );
      expect(reasonFor(`${ANDROID_APK_KEY_HASH_ORIGIN_PREFIX}${APK_KEY_HASH.slice(1)}`)).toBe(
        'android_hash'
      );
      expect(reasonFor(`${ANDROID_APK_KEY_HASH_ORIGIN_PREFIX}${'AB:'.repeat(31)}AB`)).toBe(
        'android_hash'
      );
    });

    it('refuses a 43-character value that cannot be 32 bytes', () => {
      // The last character of 32 bytes in base64url carries two zero bits.
      expect(reasonFor(`${ANDROID_APK_KEY_HASH_ORIGIN_PREFIX}${APK_KEY_HASH.slice(0, 42)}B`)).toBe(
        'android_hash'
      );
    });
  });

  it('never repeats the value in its message', () => {
    const error = (() => {
      try {
        normaliseWebAuthnOrigin('https://secret.example.com/path');
      } catch (caught) {
        return caught;
      }
      return undefined;
    })();
    expect(error).toBeInstanceOf(InvalidWebAuthnOriginError);
    expect((error as Error).message).not.toContain('secret');
    expect((error as InvalidWebAuthnOriginError).input).toBe('https://secret.example.com/path');
  });
});

describe('rpIdCoversHost', () => {
  it('covers the RP ID itself and names under it, label by label', () => {
    expect(rpIdCoversHost('example.com', 'example.com')).toBe(true);
    expect(rpIdCoversHost('example.com', 'auth.example.com')).toBe(true);
    expect(rpIdCoversHost('example.com', 'a.b.example.com')).toBe(true);
    expect(rpIdCoversHost('example.com', 'badexample.com')).toBe(false);
    expect(rpIdCoversHost('auth.example.com', 'example.com')).toBe(false);
  });
});

describe('isWebAuthnOriginForRpId', () => {
  it('takes a web origin whose host the RP ID covers, and any Android app origin', () => {
    expect(isWebAuthnOriginForRpId('https://auth.example.com', 'auth.example.com')).toBe(true);
    expect(isWebAuthnOriginForRpId('https://app.example.com', 'example.com')).toBe(true);
    expect(isWebAuthnOriginForRpId('https://app.example.com', 'auth.example.com')).toBe(false);
    expect(
      isWebAuthnOriginForRpId(
        `${ANDROID_APK_KEY_HASH_ORIGIN_PREFIX}${APK_KEY_HASH}`,
        'auth.example.com'
      )
    ).toBe(true);
    expect(isWebAuthnOriginForRpId('not a url', 'auth.example.com')).toBe(false);
  });
});
