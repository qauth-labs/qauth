import { describe, expect, it } from 'vitest';

import { databaseEnvSchema } from './database';

const URL = 'postgresql://qauth:pw@localhost:5432/qauth';

/**
 * DB_MIGRATION_WAIT_MS (#474): how long the auth server waits at boot for
 * the migration runner before it exits naming the missing migrations.
 */
describe('databaseEnvSchema DB_MIGRATION_WAIT_MS', () => {
  const wait = (raw?: string) =>
    databaseEnvSchema.parse(
      raw === undefined ? { DATABASE_URL: URL } : { DATABASE_URL: URL, DB_MIGRATION_WAIT_MS: raw }
    ).DB_MIGRATION_WAIT_MS;

  it('defaults to 60 seconds', () => {
    expect(wait()).toBe(60_000);
  });

  it('accepts 0, which checks once, and up to an hour', () => {
    expect(wait('0')).toBe(0);
    expect(wait('5000')).toBe(5_000);
    expect(wait('3600000')).toBe(3_600_000);
  });

  it('refuses a negative, fractional or longer wait', () => {
    for (const raw of ['-1', '1.5', '3600001', 'forever']) {
      expect(() => wait(raw), raw).toThrow();
    }
  });
});
