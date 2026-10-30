import { describe, expect, it } from 'vitest';

import { adminApiEnvSchema } from './admin-api';

/** The admin API's listener (issue #511). */

describe('adminApiEnvSchema', () => {
  it('runs on loopback port 3002 by default, unset and blank alike', () => {
    for (const env of [
      {},
      { ADMIN_API_ENABLED: '', ADMIN_API_HOST: ' ', ADMIN_API_PORT: '' },
    ] as Record<string, string>[]) {
      expect(adminApiEnvSchema.parse(env)).toEqual({
        ADMIN_API_ENABLED: true,
        ADMIN_API_HOST: '127.0.0.1',
        ADMIN_API_PORT: 3002,
      });
    }
  });

  it('takes a switch, an address and a port', () => {
    expect(
      adminApiEnvSchema.parse({
        ADMIN_API_ENABLED: 'false',
        ADMIN_API_HOST: '10.0.4.12',
        ADMIN_API_PORT: '9443',
      })
    ).toEqual({ ADMIN_API_ENABLED: false, ADMIN_API_HOST: '10.0.4.12', ADMIN_API_PORT: 9443 });
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
});
