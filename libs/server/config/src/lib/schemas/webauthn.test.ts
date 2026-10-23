import { describe, expect, it } from 'vitest';

import { WEBAUTHN_ENABLED_REFUSAL, webauthnEnvSchema } from './webauthn';

/**
 * The passkey settings (ADR-017 Decision 14, ADR-019 Decision 2, issue #467).
 * The relation of the RP ID to the realm host is checked at boot, where the
 * realm exists; this schema checks what each value is on its own.
 */

/** The boot errors for `env`, as the operator reads them. */
function bootErrors(env: Record<string, string>): string[] {
  const result = webauthnEnvSchema.safeParse(env);
  if (result.success) return [];
  return result.error.issues.map((issue) => `${issue.path.join('.')}: ${issue.message}`);
}

const FINGERPRINT =
  'FA:C6:17:45:DC:09:03:78:6F:B9:ED:E6:2A:96:2B:39:9F:73:48:F0:BB:6F:89:9B:83:32:66:75:91:03:3B:9C';

describe('webauthnEnvSchema', () => {
  describe('WEBAUTHN_ENABLED', () => {
    it('is off when unset or blank, and false is accepted', () => {
      expect(webauthnEnvSchema.parse({}).WEBAUTHN_ENABLED).toBe(false);
      expect(webauthnEnvSchema.parse({ WEBAUTHN_ENABLED: '' }).WEBAUTHN_ENABLED).toBe(false);
      expect(webauthnEnvSchema.parse({ WEBAUTHN_ENABLED: 'false' }).WEBAUTHN_ENABLED).toBe(false);
    });

    it('refuses true at boot until ADR-017 phase F2b is complete, saying what to do', () => {
      expect(bootErrors({ WEBAUTHN_ENABLED: 'true' })).toEqual([
        `WEBAUTHN_ENABLED: ${WEBAUTHN_ENABLED_REFUSAL}`,
      ]);
      expect(WEBAUTHN_ENABLED_REFUSAL).toContain('ADR-017 phase F2b');
      expect(WEBAUTHN_ENABLED_REFUSAL).toContain('Unset WEBAUTHN_ENABLED or set it to false');
    });

    it('refuses a value that is not true or false', () => {
      expect(bootErrors({ WEBAUTHN_ENABLED: 'yes' })).toHaveLength(1);
      expect(bootErrors({ WEBAUTHN_ENABLED: 'TRUE' })).toHaveLength(1);
    });
  });

  describe('WEBAUTHN_RP_ID', () => {
    it("is unset by default, which means the realm's host", () => {
      expect(webauthnEnvSchema.parse({}).WEBAUTHN_RP_ID).toBeUndefined();
      expect(webauthnEnvSchema.parse({ WEBAUTHN_RP_ID: '  ' }).WEBAUTHN_RP_ID).toBeUndefined();
    });

    it('comes out in the stored host form', () => {
      expect(webauthnEnvSchema.parse({ WEBAUTHN_RP_ID: 'Auth.Example.COM.' }).WEBAUTHN_RP_ID).toBe(
        'auth.example.com'
      );
    });

    it.each(['https://auth.example.com', '192.0.2.10', '*.example.com', 'auth example.com'])(
      'refuses %s, naming the variable',
      (raw) => {
        expect(bootErrors({ WEBAUTHN_RP_ID: raw })).toEqual([
          expect.stringMatching(/^WEBAUTHN_RP_ID: WEBAUTHN_RP_ID ".*" is not a host name/),
        ]);
      }
    );
  });

  it('takes the parent-domain opt-in as an explicit true only', () => {
    expect(webauthnEnvSchema.parse({}).WEBAUTHN_RP_ID_ALLOW_PARENT_DOMAIN).toBe(false);
    expect(
      webauthnEnvSchema.parse({ WEBAUTHN_RP_ID_ALLOW_PARENT_DOMAIN: 'true' })
        .WEBAUTHN_RP_ID_ALLOW_PARENT_DOMAIN
    ).toBe(true);
    expect(bootErrors({ WEBAUTHN_RP_ID_ALLOW_PARENT_DOMAIN: '1' })).toHaveLength(1);
  });

  describe('WEBAUTHN_APPLE_APP_IDS', () => {
    it('lists Team ID and bundle id pairs, comma-separated, once each', () => {
      expect(webauthnEnvSchema.parse({}).WEBAUTHN_APPLE_APP_IDS).toEqual([]);
      expect(
        webauthnEnvSchema.parse({
          WEBAUTHN_APPLE_APP_IDS: ' ABCDE12345.com.example.app, ABCDE12345.com.example.app ,',
        }).WEBAUTHN_APPLE_APP_IDS
      ).toEqual(['ABCDE12345.com.example.app']);
    });

    it.each(['com.example.app', 'abcde12345.com.example.app', 'ABCDE12345.', 'ABCDE1234.com.x'])(
      'refuses %s',
      (raw) => {
        expect(bootErrors({ WEBAUTHN_APPLE_APP_IDS: raw })).toEqual([
          expect.stringContaining('is not an Apple app identifier'),
        ]);
      }
    );
  });

  describe('WEBAUTHN_ANDROID_APPS', () => {
    it('maps package names to upper-case fingerprints, once each', () => {
      expect(webauthnEnvSchema.parse({}).WEBAUTHN_ANDROID_APPS).toEqual({});
      expect(
        webauthnEnvSchema.parse({
          WEBAUTHN_ANDROID_APPS: JSON.stringify({
            'com.example.app': [FINGERPRINT.toLowerCase(), FINGERPRINT],
          }),
        }).WEBAUTHN_ANDROID_APPS
      ).toEqual({ 'com.example.app': [FINGERPRINT] });
    });

    it.each([
      ['not JSON', 'not json', 'is not JSON'],
      ['an array', '[]', 'must be a JSON object'],
      [
        'a bad package name',
        JSON.stringify({ app: [FINGERPRINT] }),
        'is not an Android package name',
      ],
      ['no fingerprint', JSON.stringify({ 'com.example.app': [] }), 'must list 1 to 10'],
      [
        'a short fingerprint',
        JSON.stringify({ 'com.example.app': ['FA:C6'] }),
        'is not a SHA-256 fingerprint',
      ],
      [
        'a base64 fingerprint',
        JSON.stringify({ 'com.example.app': ['sYUC8p5I9SxqFernBPHmDxz_YVZXmVJdW8s-m3RTTqE'] }),
        'is not a SHA-256 fingerprint',
      ],
    ])('refuses %s', (_name, raw, message) => {
      expect(bootErrors({ WEBAUTHN_ANDROID_APPS: raw })).toEqual([
        expect.stringContaining(message),
      ]);
    });

    it('refuses a __proto__ key as a package name, and builds a prototype-less map', () => {
      expect(
        bootErrors({
          WEBAUTHN_ANDROID_APPS: `{"com.example.app":["${FINGERPRINT}"],"__proto__":["${FINGERPRINT}"]}`,
        })
      ).toEqual([expect.stringContaining('"__proto__" is not an Android package name')]);
      const apps = webauthnEnvSchema.parse({
        WEBAUTHN_ANDROID_APPS: JSON.stringify({ 'com.example.app': [FINGERPRINT] }),
      }).WEBAUTHN_ANDROID_APPS;
      expect(Object.getPrototypeOf(apps)).toBeNull();
      expect(Object.isFrozen(apps)).toBe(true);
    });
  });
});
