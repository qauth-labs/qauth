import { describe, expect, it } from 'vitest';

import { adminApiEnvSchema } from './admin-api';

/** The admin API's listener (issues #511, #520). */

describe('adminApiEnvSchema', () => {
  it('is off by default, on loopback port 3002, unset and blank alike', () => {
    for (const env of [
      {},
      { ADMIN_API_ENABLED: '', ADMIN_API_HOST: ' ', ADMIN_API_PORT: '' },
    ] as Record<string, string>[]) {
      expect(adminApiEnvSchema.parse({ ...env, ADMIN_API_BASE_URL: '' })).toEqual({
        ADMIN_API_ENABLED: false,
        ADMIN_API_HOST: '127.0.0.1',
        ADMIN_API_PORT: 3002,
        ADMIN_API_BASE_URL: undefined,
      });
    }
  });

  it('takes a switch, an address and a port', () => {
    expect(
      adminApiEnvSchema.parse({
        ADMIN_API_ENABLED: 'true',
        ADMIN_API_HOST: '10.0.4.12',
        ADMIN_API_PORT: '9443',
      })
    ).toEqual({ ADMIN_API_ENABLED: true, ADMIN_API_HOST: '10.0.4.12', ADMIN_API_PORT: 9443 });
  });

  it('refuses a switch that is not true or false', () => {
    for (const value of ['yes', 'TRUE', '1']) {
      expect(adminApiEnvSchema.safeParse({ ADMIN_API_ENABLED: value }).success).toBe(false);
    }
  });

  it('refuses a port outside 1 to 65535, or not a whole number', () => {
    for (const value of ['0', '65536', '30.5', 'admin']) {
      expect(adminApiEnvSchema.safeParse({ ADMIN_API_PORT: value }).success).toBe(false);
    }
  });

  it('takes the base URL the listener is called at, a path included, without trailing slashes', () => {
    for (const [value, parsed] of [
      ['https://admin.auth.example.com', 'https://admin.auth.example.com'],
      ['https://admin.auth.example.com/', 'https://admin.auth.example.com'],
      ['http://127.0.0.1:3002', 'http://127.0.0.1:3002'],
      [' https://ops.example.com/qauth-admin// ', 'https://ops.example.com/qauth-admin'],
    ]) {
      expect(adminApiEnvSchema.parse({ ADMIN_API_BASE_URL: value }).ADMIN_API_BASE_URL).toBe(
        parsed
      );
    }
  });

  it.each([
    ['a relative URL', '/admin', 'an absolute http or https URL'],
    ['another scheme', 'ftp://admin.example.com', 'an absolute http or https URL'],
    ['a user name', 'https://admin@admin.example.com', 'a user name or a password'],
    ['a query', 'https://admin.example.com/?realm=a', 'a query or a fragment'],
    ['a fragment', 'https://admin.example.com/#top', 'a query or a fragment'],
  ])('refuses a base URL with %s', (_what, value, message) => {
    const result = adminApiEnvSchema.safeParse({ ADMIN_API_BASE_URL: value });
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.message).toContain(message);
  });
});
