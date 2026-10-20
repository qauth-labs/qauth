import {
  AUTH_SERVER_KEYS,
  CONFIG_KEY_REGISTRY,
  cryptoEnvSchema,
  envSchemaShape,
  findRegistryDrift,
  jwtEnvSchema,
  SERVER_CONFIG_KEYS,
} from '@qauth-labs/server-config';
import { describe, expect, it } from 'vitest';

import { envSchema } from './env-schema';

/**
 * The auth server's half of the configuration key registry contract
 * (ADR-018 §5). `server-config`'s own test covers the schemas it defines; it
 * cannot see this app, so the keys this app adds are checked here.
 */
describe('the auth server env schema and the configuration key registry', () => {
  const read = [
    ...Object.keys(envSchemaShape(envSchema)),
    ...Object.keys(envSchemaShape(jwtEnvSchema)),
    ...Object.keys(envSchemaShape(cryptoEnvSchema)),
  ];

  it('registers every key the auth server reads', () => {
    expect(findRegistryDrift(read, CONFIG_KEY_REGISTRY).unregistered).toEqual([]);
  });

  it("registers this app's own keys as AUTH_SERVER_KEYS, and nothing else there", () => {
    const library = new Set(SERVER_CONFIG_KEYS.map((key) => key.name));
    const own = read.filter((name) => !library.has(name));

    expect(findRegistryDrift(own, AUTH_SERVER_KEYS)).toEqual({ unregistered: [], orphaned: [] });
  });
});
