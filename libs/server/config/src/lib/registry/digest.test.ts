/**
 * The configuration digest's classes and builder (ADR-019 Decision 8, issue
 * #499): every registry key has a digest class, and the digest of the shared
 * keys depends on their values, not on the order of the keys or of the values.
 */
import { describe, expect, it } from 'vitest';

import { SERVICE_ROLE_NAMES } from '../schemas/service-roles';
import {
  configurationDigest,
  differingKeys,
  digestClassificationProblems,
  digestedKeys,
  UnclassifiedConfigKeyError,
} from './digest';
import { AUTH_SERVER_KEYS, CONFIG_KEY_REGISTRY, SERVER_CONFIG_KEYS } from './keys';
import { type ConfigKey, type ConfigKeyInput, defineKeys, KEY_DIGEST_CLASSES } from './types';

const AUTH_KEYS: readonly ConfigKey[] = [...SERVER_CONFIG_KEYS, ...AUTH_SERVER_KEYS];

const key = (name: string, extra: Partial<ConfigKeyInput> = {}): ConfigKey =>
  defineKeys([
    {
      name,
      tier: 'advanced',
      role: 'deployment',
      owner: 'server',
      default: null,
      since: '0.3.0',
      docs: 'A key of the test.',
      ...extra,
    },
  ])[0] as ConfigKey;

/** Each auth server key at its registry default, as the environment reads it unset. */
function defaultValues(keys: readonly ConfigKey[]): Record<string, unknown> {
  return Object.fromEntries(
    keys.map((entry) => [entry.name, typeof entry.default === 'string' ? entry.default : undefined])
  );
}

function registryKey(name: string): ConfigKey {
  const found = CONFIG_KEY_REGISTRY.find((entry) => entry.name === name);
  if (found === undefined) throw new Error(`no registry key ${name}`);
  return found;
}

describe('the digest classes of the registry', () => {
  it('classifies every key consistently', () => {
    expect(digestClassificationProblems(CONFIG_KEY_REGISTRY)).toEqual([]);
  });

  it.each(CONFIG_KEY_REGISTRY.map((entry) => [entry.name, entry] as const))(
    '%s has a digest class',
    (_name, entry) => {
      expect(KEY_DIGEST_CLASSES).toContain(entry.digest);
    }
  );

  it('fails on a key with no class, and the digest refuses to read one', () => {
    const unclassified = key('UNCLASSIFIED_KEY');
    expect(unclassified.digest).toBeUndefined();
    expect(digestClassificationProblems([unclassified])).toEqual([
      'UNCLASSIFIED_KEY has no digest class',
    ]);
    expect(() => configurationDigest([unclassified], {}, SERVICE_ROLE_NAMES)).toThrow(
      UnclassifiedConfigKeyError
    );
    expect(() => digestedKeys([key('A', { digest: 'shared' }), unclassified], ['web'])).toThrow(
      /UNCLASSIFIED_KEY/
    );
  });

  it('derives the class of a secret and of a realm seed, which no entry repeats', () => {
    expect(key('A_SECRET', { secret: true }).digest).toBe('secret');
    expect(key('A_SEED', { role: 'realm-seed', seeds: 'tokens.lifespan' }).digest).toBe(
      'realm-seed'
    );
    expect(
      key('A_SECRET_SEED', { role: 'realm-seed', seeds: 'mail.password', secret: true }).digest
    ).toBe('secret');
  });

  it('refuses a class that contradicts the key', () => {
    expect(
      digestClassificationProblems([
        key('SHARED_SECRET', { secret: true, digest: 'shared' }),
        key('NOT_A_SECRET', { digest: 'secret' }),
        key('SEED_AS_NODE', { role: 'realm-seed', seeds: 'a.b', digest: 'node' }),
        key('NOT_A_SEED', { digest: 'realm-seed' }),
        key('NODE_WITH_ROLES', { digest: 'node', digestRoles: ['signer'] }),
        key('NO_ROLES', { digest: 'shared', digestRoles: [] }),
      ])
    ).toEqual([
      'SHARED_SECRET is a secret, so its digest class is secret, not shared',
      'NOT_A_SECRET is not a secret, so its digest class cannot be secret',
      'SEED_AS_NODE seeds a realm policy, so its digest class is realm-seed, not node',
      'NOT_A_SEED seeds no realm policy, so its digest class cannot be realm-seed',
      'NODE_WITH_ROLES names digest roles but is not shared',
      'NO_ROLES names an empty list of digest roles',
    ]);
  });

  it('compares the deployment-wide settings the issue names', () => {
    for (const name of [
      'JWT_ISSUER',
      'DEFAULT_REALM_NAME',
      'SIGNING_ALGORITHM_MODE',
      'HYBRID_SIGNING_ENABLED',
      'TRUST_PROXY',
      'KEK_PROVIDER',
      'WALLET_FEDERATION_ENABLED',
      'ID_JAG_ENABLED',
      'DPOP_ENABLED',
      'WEBAUTHN_ENABLED',
      'SSF_TRANSMITTER_ENABLED',
      'NODE_ENV',
    ]) {
      expect(registryKey(name).digest, name).toBe('shared');
    }
    // CIMD's switch seeds each realm's policy since #534: the realm row owns it.
    expect(registryKey('CIMD_ENABLED').digest).toBe('realm-seed');
  });

  it('leaves out what may differ from node to node, and every secret', () => {
    for (const name of [
      'HOST',
      'PORT',
      'SERVICE_ROLES',
      'LOG_LEVEL',
      'INTERNAL_TLS_CERT_PATH',
      'DB_POOL_MAX',
      'CONFIG_DIGEST_ROLLOUT',
    ]) {
      expect(registryKey(name).digest, name).toBe('node');
    }
    for (const name of ['DATABASE_URL', 'KEK', 'JWT_PRIVATE_KEY', 'SESSION_COOKIE_SECRET']) {
      expect(registryKey(name).digest, name).toBe('secret');
    }
  });

  it('compares KEK_PROVIDER only between nodes that hold the signer', () => {
    expect(registryKey('KEK_PROVIDER').digestRoles).toEqual(['signer']);
    const names = (roles: Parameters<typeof digestedKeys>[1]) =>
      digestedKeys(AUTH_KEYS, roles).map((entry) => entry.name);
    expect(names(['signer'])).toContain('KEK_PROVIDER');
    expect(names(SERVICE_ROLE_NAMES)).toContain('KEK_PROVIDER');
    expect(names(['web', 'api'])).not.toContain('KEK_PROVIDER');
    expect(names(['web', 'api'])).toContain('JWT_ISSUER');
  });

  it('compares the admin listener keys between admin nodes, and the plugin keys where plugins load', () => {
    const names = (roles: Parameters<typeof digestedKeys>[1]) =>
      digestedKeys(AUTH_KEYS, roles).map((entry) => entry.name);
    for (const name of ['ADMIN_API_ENABLED', 'ADMIN_API_BASE_URL']) {
      expect(registryKey(name).digestRoles, name).toEqual(['admin']);
      expect(names(['admin']), name).toContain(name);
      expect(names(['web', 'api', 'signer', 'delivery']), name).not.toContain(name);
    }
    for (const name of ['AUTH_METHOD_PLUGINS', 'PLUGIN_API_ENABLED']) {
      expect(registryKey(name).digestRoles, name).toEqual(['web', 'admin']);
      expect(names(['web']), name).toContain(name);
      expect(names(['admin']), name).toContain(name);
      expect(names(['api', 'signer', 'delivery']), name).not.toContain(name);
    }
    // DPoP binds the admin tokens the token endpoint issues: every node.
    expect(registryKey('DPOP_ENABLED').digestRoles).toBeUndefined();
  });
});

describe('configurationDigest', () => {
  const values = defaultValues(AUTH_KEYS);
  values['JWT_ISSUER'] = 'https://auth.example.com';

  it('is the same whatever the order of the keys and of the values', () => {
    const forward = configurationDigest(AUTH_KEYS, values, SERVICE_ROLE_NAMES);
    const reversedValues = Object.fromEntries(Object.entries(values).reverse());
    const backward = configurationDigest([...AUTH_KEYS].reverse(), reversedValues, [
      ...SERVICE_ROLE_NAMES,
    ]);
    expect(backward).toEqual(forward);
    expect(Object.keys(forward.keys)).toEqual(Object.keys(forward.keys).sort());
    expect(forward.digest).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is the same whatever the order of the properties inside a value', () => {
    const shared = [key('JSON_KEY', { digest: 'shared' })];
    const one = configurationDigest(
      shared,
      { JSON_KEY: { realm: { b: 2, a: [1, 'x'] }, other: true } },
      ['web']
    );
    const two = configurationDigest(
      shared,
      { JSON_KEY: { other: true, realm: { a: [1, 'x'], b: 2 } } },
      ['web']
    );
    expect(two).toEqual(one);
  });

  it('changes when a deployment-wide value changes, and names that key alone', () => {
    const before = configurationDigest(AUTH_KEYS, values, SERVICE_ROLE_NAMES);
    const after = configurationDigest(
      AUTH_KEYS,
      { ...values, HYBRID_SIGNING_ENABLED: true },
      SERVICE_ROLE_NAMES
    );
    expect(after.digest).not.toBe(before.digest);
    expect(differingKeys(after.keys, before.keys)).toEqual(['HYBRID_SIGNING_ENABLED']);
  });

  it('does not change with a setting of the node, or with a secret', () => {
    const before = configurationDigest(AUTH_KEYS, values, SERVICE_ROLE_NAMES);
    const after = configurationDigest(
      AUTH_KEYS,
      {
        ...values,
        PORT: '4000',
        LOG_LEVEL: 'debug',
        SERVICE_ROLES: ['web'],
        DATABASE_URL: 'postgresql://other',
        KEK: 'another',
      },
      SERVICE_ROLE_NAMES
    );
    expect(after).toEqual(before);
    for (const name of ['PORT', 'LOG_LEVEL', 'SERVICE_ROLES', 'DATABASE_URL', 'KEK']) {
      expect(before.keys, name).not.toHaveProperty(name);
    }
  });

  it('never reads a secret, even one an entry marks shared', () => {
    const mislabelled = [key('A_SECRET', { secret: true, digest: 'shared' })];
    expect(configurationDigest(mislabelled, { A_SECRET: 'x' }, ['web']).keys).toEqual({});
  });

  it('tells an unset value from an empty one', () => {
    const shared = [key('LIST', { digest: 'shared' })];
    const unset = configurationDigest(shared, {}, ['web']);
    const empty = configurationDigest(shared, { LIST: '' }, ['web']);
    const emptyList = configurationDigest(shared, { LIST: [] }, ['web']);
    expect(new Set([unset.digest, empty.digest, emptyList.digest]).size).toBe(3);
  });

  it('reads sets, maps, dates and URLs, and refuses what it cannot read without its value', () => {
    const shared = [key('ODD', { digest: 'shared' })];
    expect(configurationDigest(shared, { ODD: new Set(['b', 'a']) }, ['web'])).toEqual(
      configurationDigest(shared, { ODD: new Set(['a', 'b']) }, ['web'])
    );
    expect(() =>
      configurationDigest(
        shared,
        {
          ODD: [new Map([['k', 1]]), new Date(0), new URL('https://example.com/')],
        },
        ['web']
      )
    ).not.toThrow();
    const secretLooking = 'value-that-must-not-be-printed';
    for (const value of [() => secretLooking, Buffer.from(secretLooking), Symbol(secretLooking)]) {
      let message = '';
      try {
        configurationDigest(shared, { ODD: value }, ['web']);
      } catch (error) {
        message = (error as Error).message;
      }
      expect(message).toMatch(/ODD/);
      expect(message).not.toContain(secretLooking);
    }
  });
});

describe('differingKeys', () => {
  it('names only the keys both nodes compare whose digests differ, sorted', () => {
    expect(
      differingKeys(
        { B: '2', A: '1', KEK_PROVIDER: 'x', SAME: 's' },
        { A: 'other', B: 'other', SAME: 's', ONLY_THEIRS: 'y' }
      )
    ).toEqual(['A', 'B']);
  });
});
