import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import Ajv2020 from 'ajv/dist/2020';
import addFormats from 'ajv-formats';
import { describe, expect, it } from 'vitest';

import {
  fixtures,
  invalidExpectations,
  readRepoJson,
  REPO_ROOT,
  SHIPPED_SEED_MANIFESTS,
} from '../testing/fixtures';
import { URL_CREDENTIALS_MESSAGE, URL_CREDENTIALS_PATTERN } from './credentials';
import {
  REALM_FILE_EXPORT_COMMAND,
  REALM_FILE_FORMAT,
  REALM_FILE_SCHEMA_ID,
  REALM_FILE_SCHEMA_PATH,
} from './format';
import { realmFileJsonSchema, realmFileJsonSchemaText } from './json-schema';
import { safeParseRealmFile } from './realm-file';
import { REALM_FILE_SECTIONS } from './sections';

/**
 * The published JSON Schema against the Zod schema (#515): the file is what
 * the schema generates, it is a registered stable surface, and both accept
 * and refuse the same fixtures, but for the ones the fixtures say only the
 * parser refuses.
 */

/** Ajv's draft 2020-12 engine, strict: an unknown keyword or format fails the compile. */
function validator() {
  const ajv = new Ajv2020({ strict: true, strictRequired: false, allErrors: true });
  addFormats(ajv);
  // The policy registry's annotations.
  ajv.addKeyword('x-qauth-policy');
  ajv.addKeyword('x-qauth-schema-version');
  return ajv.compile(JSON.parse(readFileSync(join(REPO_ROOT, REALM_FILE_SCHEMA_PATH), 'utf8')));
}

describe('the published JSON Schema', () => {
  it('is what the Zod schema generates (regenerate with `pnpm exec nx run realm-file:schema-export`)', () => {
    expect(readFileSync(join(REPO_ROOT, REALM_FILE_SCHEMA_PATH), 'utf8')).toBe(
      realmFileJsonSchemaText()
    );
  });

  it('is registered as a stable input surface, written by the export target', () => {
    const registry = readRepoJson('stable-surface/surfaces.json') as {
      surfaces: Array<Record<string, unknown>>;
    };
    expect(registry.surfaces.filter(({ path }) => path === REALM_FILE_SCHEMA_PATH)).toEqual([
      expect.objectContaining({
        name: 'realm-file-v1',
        format: 'json-schema',
        role: 'input',
        generator: REALM_FILE_EXPORT_COMMAND,
        stability: 'stable',
      }),
    ]);
  });

  it('names its format, its dialect and where it is served', () => {
    const schema = realmFileJsonSchema();
    expect(schema).toMatchObject({
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      $id: REALM_FILE_SCHEMA_ID,
      title: REALM_FILE_FORMAT,
      type: 'object',
      additionalProperties: false,
      required: ['realm'],
    });
    expect(Object.keys(schema['properties'] as object)).toEqual([
      'format',
      'realm',
      ...REALM_FILE_SECTIONS.map(({ name }) => name),
    ]);
  });

  it('refers only to its own $defs, as the stable-surface check requires', () => {
    const refs = [...realmFileJsonSchemaText().matchAll(/"\$ref": "([^"]*)"/g)].map(
      (match) => match[1]
    );
    for (const ref of refs) expect(ref).toMatch(/^#\/\$defs\//);
  });

  it('compiles under a strict validator', () => {
    expect(() => validator()).not.toThrow();
  });
});

// Acceptance criterion: the published JSON Schema and the Zod schema accept
// and reject the same fixtures.
describe('the JSON Schema and the Zod schema on the fixtures', () => {
  const validate = validator();
  const expected = invalidExpectations();

  it.each([
    ...fixtures('valid'),
    ...fixtures('seed-manifests'),
    ...SHIPPED_SEED_MANIFESTS.map((path) => ({ name: path, value: readRepoJson(path) })),
  ])('both accept $name', ({ value }) => {
    expect(safeParseRealmFile(value).success).toBe(true);
    expect(validate(value), JSON.stringify(validate.errors, null, 2)).toBe(true);
  });

  it.each(fixtures('invalid'))(
    'both refuse invalid/$name, unless only the parser can',
    ({ name, value }) => {
      expect(safeParseRealmFile(value).success).toBe(false);
      const accepts = expected[name]?.jsonSchema === 'accepts';
      expect(validate(value), JSON.stringify(validate.errors, null, 2)).toBe(accepts);
    }
  );

  it('says why of each file only the parser refuses', () => {
    const parserOnly = Object.entries(expected).filter(([, { jsonSchema }]) => jsonSchema);
    expect(parserOnly.length).toBeGreaterThan(0);
    for (const [name, { why }] of parserOnly) expect(why, name).toBeTruthy();
  });

  it('refuses a secret where the parser does: a client_secret, a private JWK member, a policy secret', () => {
    for (const name of ['client-secret.json', 'private-jwk.json', 'policy-secret.json']) {
      const fixture = fixtures('invalid').find((candidate) => candidate.name === name);
      expect(fixture, name).toBeDefined();
      expect(validate(fixture?.value), name).toBe(false);
    }
  });
});

describe('a URL with a user name or password', () => {
  const validate = validator();
  const credentialed = 'https://svc:Hunter2Pass@keys.example.com/jwks.json';

  /** Every string of `value`, by path. */
  function strings(value: unknown, path: (string | number)[] = []): (string | number)[][] {
    if (typeof value === 'string') return [path];
    if (Array.isArray(value))
      return value.flatMap((member, index) => strings(member, [...path, index]));
    if (typeof value === 'object' && value !== null) {
      return Object.entries(value).flatMap(([key, member]) => strings(member, [...path, key]));
    }
    return [];
  }

  const full = fixtures('valid').find(({ name }) => name === 'full.json')?.value;

  // Every string of the fullest valid file, in turn, made a URL with
  // credentials: the parser and the JSON Schema both refuse the file.
  it.each(strings(full).map((path) => [path.join('.'), path] as const))(
    'is refused by both at %s',
    (_, path) => {
      const value = structuredClone(full) as Record<string | number, unknown>;
      let parent: Record<string | number, unknown> = value;
      for (const token of path.slice(0, -1)) parent = parent[token] as typeof parent;
      parent[path[path.length - 1]] = credentialed;
      const result = safeParseRealmFile(value);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.issues).toContainEqual(
          expect.objectContaining({ path, message: URL_CREDENTIALS_MESSAGE })
        );
      }
      expect(validate(value)).toBe(false);
    }
  );

  it('is refused by the pattern the parser checks first', () => {
    expect(JSON.stringify(realmFileJsonSchema())).toContain(
      JSON.stringify(URL_CREDENTIALS_PATTERN)
    );
  });
});
