import { describe, expect, it } from 'vitest';

import { componentValidator, strictValidator } from '../testing/schema-validator';
import { ACCOUNT_API_PREFIX } from './identifiers';
import { ACCOUNT_OPENAPI, buildAccountOpenApi } from './openapi';
import { ACCOUNT_OPERATIONS } from './operations';

/**
 * The schema lint of #588: every schema in the document compiles under Ajv's
 * strict mode, and every reference resolves. The artifact tests make the
 * committed file equal to this document, so the lint holds for what the docs
 * site publishes and the client is generated from. The auth server's
 * `account-contract.test.ts` validates the same document against the official
 * OpenAPI 3.1 schema and the API conventions check.
 */

const document = ACCOUNT_OPENAPI as Record<string, unknown>;
const components = document['components'] as Record<string, Record<string, unknown>>;
const paths = document['paths'] as Record<string, Record<string, Record<string, unknown>>>;

/** Every `$ref` value anywhere in `value`. */
function refsOf(value: unknown, out: string[] = []): string[] {
  if (Array.isArray(value)) value.forEach((item) => refsOf(item, out));
  else if (typeof value === 'object' && value !== null) {
    for (const [key, inner] of Object.entries(value)) {
      if (key === '$ref' && typeof inner === 'string') out.push(inner);
      else refsOf(inner, out);
    }
  }
  return out;
}

/** Resolve a local JSON Pointer reference in `root`. */
function resolvePointer(root: unknown, ref: string): unknown {
  if (!ref.startsWith('#/')) return undefined;
  return ref
    .slice(2)
    .split('/')
    .map((part) => part.replace(/~1/g, '/').replace(/~0/g, '~'))
    .reduce<unknown>(
      (node, part) =>
        typeof node === 'object' && node !== null
          ? (node as Record<string, unknown>)[part]
          : undefined,
      root
    );
}

describe('the account API OpenAPI document', () => {
  it('declares OpenAPI 3.1', () => {
    expect(document['openapi']).toMatch(/^3\.1\.\d+$/);
  });

  it('is deterministic', () => {
    expect(JSON.stringify(buildAccountOpenApi())).toBe(JSON.stringify(ACCOUNT_OPENAPI));
  });

  it('resolves every reference inside itself', () => {
    const refs = refsOf(document);
    expect(refs.length).toBeGreaterThan(100);
    for (const ref of refs) {
      expect(ref, 'references stay inside the document').toMatch(/^#\//);
      expect(resolvePointer(document, ref), `${ref} resolves`).toBeDefined();
    }
  });

  it('uses every schema, header and example it declares', () => {
    const used = new Set(
      refsOf({ paths, schemas: components['schemas'] }).map((ref) =>
        ref.split('/').slice(0, 4).join('/')
      )
    );
    for (const section of ['schemas', 'headers', 'examples']) {
      for (const name of Object.keys(components[section] ?? {})) {
        expect(used.has(`#/components/${section}/${name}`), `${section}/${name} is used`).toBe(
          true
        );
      }
    }
  });

  it('compiles every component schema under strict mode', () => {
    const validator = componentValidator(document);
    expect(validator.names.length).toBeGreaterThan(30);
    for (const name of validator.names) {
      expect(() => validator.schema(name), name).not.toThrow();
    }
  });

  it('is refused by strict mode when a schema has a misspelt keyword', () => {
    expect(() => strictValidator().compile({ type: 'string', maxLenght: 3 })).toThrow(
      /unknown keyword/
    );
  });

  it('holds exactly the operations of the table, under the prefix', () => {
    const found: string[] = [];
    for (const [path, item] of Object.entries(paths)) {
      expect(path.startsWith(`${ACCOUNT_API_PREFIX}/`), path).toBe(true);
      for (const [method, operation] of Object.entries(item)) {
        found.push(`${method} ${path} ${String(operation['operationId'])}`);
      }
    }
    expect(found.sort()).toEqual(
      ACCOUNT_OPERATIONS.map(
        (operation) => `${operation.method} ${ACCOUNT_API_PREFIX}${operation.path} ${operation.id}`
      ).sort()
    );
  });

  it('gives every operation a unique account operationId, a summary, a description and one tag', () => {
    const tags = (document['tags'] as Array<{ name: string }>).map((tag) => tag.name);
    const ids: string[] = [];
    for (const [path, item] of Object.entries(paths)) {
      for (const [method, operation] of Object.entries(item)) {
        const at = `${method.toUpperCase()} ${path}`;
        expect(operation['operationId'], at).toMatch(/^account(?:\.[a-z][a-zA-Z]*)+$/);
        expect(operation['summary'], at).toEqual(expect.any(String));
        expect(operation['description'], at).toEqual(expect.any(String));
        expect(operation['tags'], at).toHaveLength(1);
        expect(tags, at).toContain((operation['tags'] as string[])[0]);
        ids.push(operation['operationId'] as string);
      }
    }
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('declares every path parameter its path names', () => {
    for (const [path, item] of Object.entries(paths)) {
      const names = [...path.matchAll(/\{([^}]+)\}/g)].map((match) => match[1]).sort();
      for (const operation of Object.values(item)) {
        const declared = ((operation['parameters'] ?? []) as Array<{ in: string; name: string }>)
          .filter((parameter) => parameter.in === 'path')
          .map((parameter) => parameter.name)
          .sort();
        expect(declared, path).toEqual(names);
      }
    }
  });
});
