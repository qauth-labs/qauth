import { readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import * as schemas from '../schemas';
import { envSchemaShape, findRegistryDrift } from './drift';
import {
  AUTH_SERVER_KEYS,
  CONFIG_KEY_REGISTRY,
  DEVELOPER_PORTAL_KEYS,
  SERVER_CONFIG_KEYS,
} from './keys';
import { type ConfigKey, defineKeys } from './types';

/**
 * The configuration key registry is a contract (ADR-018 §5): every key a
 * schema reads has exactly one entry, and every entry has a key. These tests
 * hold that down for this library's schemas and for the developer portal.
 * The auth server's own keys are checked by its `env-schema.test.ts`, the
 * one place that can import its schema.
 */

const REPO_ROOT = resolve(__dirname, '../../../../../..');

/** Every `*EnvSchema` this library exports, found by name so a new one is never missed. */
const LIBRARY_SCHEMAS: ReadonlyArray<readonly [string, z.ZodType]> = Object.entries(schemas)
  .filter(([name]) => name.endsWith('EnvSchema'))
  .map(([name, schema]) => [name, schema as z.ZodType] as const);

function libraryKeys(): Map<string, z.ZodType> {
  const fields = new Map<string, z.ZodType>();
  for (const [, schema] of LIBRARY_SCHEMAS) {
    for (const [name, field] of Object.entries(envSchemaShape(schema))) {
      fields.set(name, field);
    }
  }
  return fields;
}

/** The variables the developer portal's shipped source reads from `process.env`. */
function portalKeys(): Set<string> {
  const root = join(REPO_ROOT, 'apps/developer-portal/src');
  const keys = new Set<string>();
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(path);
      } else if (/\.tsx?$/.test(entry.name) && !/\.(test|spec)\.tsx?$/.test(entry.name)) {
        const source = readFileSync(path, 'utf8');
        for (const match of source.matchAll(
          /process\.env(?:\[\s*['"]([A-Z0-9_]+)['"]\s*\]|\.([A-Z0-9_]+))/g
        )) {
          keys.add(match[1] ?? match[2]);
        }
      }
    }
  };
  walk(root);
  return keys;
}

const entry = (name: string, extra: Partial<ConfigKey> = {}): ConfigKey => ({
  ...defineKeys([
    {
      name,
      tier: 'advanced',
      role: 'deployment',
      owner: 'server',
      default: null,
      since: '0.1.0',
      docs: 'A key for this test.',
    },
  ])[0],
  ...extra,
});

describe('findRegistryDrift', () => {
  it('reports a key a schema reads that no entry registers', () => {
    expect(findRegistryDrift(['A', 'B'], [entry('A')])).toEqual({
      unregistered: ['B'],
      orphaned: [],
    });
  });

  it('reports an entry whose key no schema reads', () => {
    expect(findRegistryDrift(['A'], [entry('A'), entry('GONE')])).toEqual({
      unregistered: [],
      orphaned: ['GONE'],
    });
  });

  it('counts an old name left in a schema as unregistered, since an alias never reaches a schema', () => {
    const renamed = entry('NEW', { aliases: [{ name: 'OLD', deprecatedSince: '0.1.0' }] });

    expect(findRegistryDrift(['NEW', 'OLD'], [renamed]).unregistered).toEqual(['OLD']);
  });

  it('reports nothing when keys and entries match', () => {
    expect(findRegistryDrift(['B', 'A'], [entry('A'), entry('B')])).toEqual({
      unregistered: [],
      orphaned: [],
    });
  });
});

describe('envSchemaShape', () => {
  it('reads a plain object, a refined object and a transformed one', () => {
    const plain = z.object({ A: z.string() });
    const refined = plain.superRefine(() => undefined);
    const transformed = plain.superRefine(() => undefined).transform((env) => ({ b: env.A }));

    expect(Object.keys(envSchemaShape(plain))).toEqual(['A']);
    expect(Object.keys(envSchemaShape(refined))).toEqual(['A']);
    expect(Object.keys(envSchemaShape(transformed))).toEqual(['A']);
  });

  it('reads the inner object of jwtEnvSchema and cryptoEnvSchema, which have no .shape', () => {
    expect('shape' in schemas.jwtEnvSchema).toBe(false);
    expect(Object.keys(envSchemaShape(schemas.jwtEnvSchema))).toContain('JWT_ISSUER');
    expect(Object.keys(envSchemaShape(schemas.cryptoEnvSchema))).toContain(
      'SIGNING_ALGORITHM_MODE'
    );
  });

  it('refuses a schema that is not an object', () => {
    expect(() => envSchemaShape(z.string())).toThrow(TypeError);
  });
});

describe('the registry covers every key, and only keys that exist', () => {
  it('finds the library schemas by name', () => {
    expect(LIBRARY_SCHEMAS.map(([name]) => name)).toEqual(
      expect.arrayContaining(['baseEnvSchema', 'authEnvSchema', 'jwtEnvSchema', 'cryptoEnvSchema'])
    );
  });

  it("matches this library's env schemas in both directions", () => {
    expect(findRegistryDrift(libraryKeys().keys(), SERVER_CONFIG_KEYS)).toEqual({
      unregistered: [],
      orphaned: [],
    });
  });

  it('matches the keys the developer portal reads in both directions', () => {
    const keys = portalKeys();

    expect(keys.size).toBeGreaterThan(0);
    expect(findRegistryDrift(keys, DEVELOPER_PORTAL_KEYS)).toEqual({
      unregistered: [],
      orphaned: [],
    });
  });

  it('registers each key once, and no old name doubles as a key', () => {
    const names = CONFIG_KEY_REGISTRY.map((key) => key.name);
    const aliases = CONFIG_KEY_REGISTRY.flatMap((key) => key.aliases.map((alias) => alias.name));

    expect(names.length).toBe(new Set(names).size);
    expect(aliases.length).toBe(new Set(aliases).size);
    expect(aliases.filter((alias) => names.includes(alias))).toEqual([]);
  });

  it('keeps the auth server and portal entries apart from the library ones', () => {
    const library = new Set(SERVER_CONFIG_KEYS.map((key) => key.name));

    expect(
      [...AUTH_SERVER_KEYS, ...DEVELOPER_PORTAL_KEYS].filter((key) => library.has(key.name))
    ).toEqual([]);
  });
});

describe('every entry is complete', () => {
  const VERSION = /^\d+\.\d+\.\d+$/;

  it.each(CONFIG_KEY_REGISTRY.map((key) => [key.name, key] as const))('%s', (_name, key) => {
    expect(key.name).toMatch(/^[A-Z][A-Z0-9_]*$/);
    expect(key.since).toMatch(VERSION);
    for (const alias of key.aliases) {
      expect(alias.name).toMatch(/^[A-Z][A-Z0-9_]*$/);
      expect(alias.deprecatedSince).toMatch(VERSION);
    }

    // One sentence: it ends with a full stop and no other sentence starts.
    expect(key.docs).toMatch(/^[A-Z`].*\.$/);
    expect(key.docs).not.toMatch(/[.!?] [A-Z]/);
    expect(key.docs).not.toMatch(/\n/);

    // A realm-seed key names the policy it seeds; a deployment key seeds none.
    if (key.role === 'realm-seed') {
      expect(key.seeds).toMatch(/^[a-z][A-Za-z]*(\.[a-z][A-Za-z]*)+$/);
    } else {
      expect(key.seeds).toBeUndefined();
    }

    // A secret's default is never written down, so nothing can print it.
    if (key.secret) {
      expect(typeof key.default).not.toBe('string');
    }

    // An experimental key has no separate experimental values, and a switch
    // for test stacks is never part of the stable promise.
    if (key.tier === 'experimental') expect(key.experimentalValues).toEqual([]);
    if (key.developmentOnly) expect(key.tier).not.toBe('stable');
  });
});

/**
 * The registry's default is what the page prints, so it must be what the
 * schema actually does when the key is unset.
 */
describe("every library entry's default matches its schema", () => {
  const fields = libraryKeys();

  // `false` is not empty here: a flag that is off when unset states the
  // literal `'false'`, so the page says so instead of "unset".
  function isEmpty(value: unknown): boolean {
    return (
      value === undefined ||
      (Array.isArray(value) && value.length === 0) ||
      (typeof value === 'object' && value !== null && Object.keys(value).length === 0)
    );
  }

  it.each(SERVER_CONFIG_KEYS.map((key) => [key.name, key] as const))('%s', (name, key) => {
    const field = fields.get(name);
    expect(field).toBeDefined();
    if (field === undefined) return;

    const unset = field.safeParse(undefined);
    if (key.default === null) {
      // Unset leaves the setting off or absent.
      expect(unset.success).toBe(true);
      expect(isEmpty(unset.data)).toBe(true);
    } else if (typeof key.default === 'string') {
      expect(unset.success).toBe(true);
      expect(field.parse(key.default)).toEqual(unset.data);
    } else if ('required' in key.default) {
      expect(unset.success).toBe(false);
    }
    // A computed default depends on other keys or on the consumer; the
    // registry states it in words.
  });
});
