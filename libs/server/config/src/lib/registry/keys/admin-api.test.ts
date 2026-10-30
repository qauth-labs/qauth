import { describe, expect, it } from 'vitest';

import { adminApiEnvSchema } from '../../schemas/admin-api';
import { CONFIG_KEY_REGISTRY, SERVER_CONFIG_KEYS } from '.';

/** The admin API's listener keys (issue #511) in the configuration registry (ADR-018 §5). */

describe('the admin listener keys', () => {
  const entries = ['ADMIN_API_ENABLED', 'ADMIN_API_HOST', 'ADMIN_API_PORT'].map((name) =>
    CONFIG_KEY_REGISTRY.find((key) => key.name === name)
  );

  it('registers all three as stable deployment keys of the server, read since 0.2.0', () => {
    for (const entry of entries) {
      expect(entry).toMatchObject({
        tier: 'stable',
        role: 'deployment',
        owner: 'server',
        since: '0.2.0',
        secret: false,
      });
    }
    expect(entries.map((entry) => entry?.name)).toEqual(
      SERVER_CONFIG_KEYS.filter((key) => key.name.startsWith('ADMIN_API_')).map((key) => key.name)
    );
  });

  it('gives each the default its schema falls back to: off, loopback, 3002', () => {
    const parsed = adminApiEnvSchema.parse({});
    expect(entries.map((entry) => entry?.default)).toEqual([
      String(parsed.ADMIN_API_ENABLED),
      parsed.ADMIN_API_HOST,
      String(parsed.ADMIN_API_PORT),
    ]);
    expect(entries.map((entry) => entry?.default)).toEqual(['false', '127.0.0.1', '3002']);
  });
});
