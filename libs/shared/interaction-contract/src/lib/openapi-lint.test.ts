import { describe, expect, it } from 'vitest';

import {
  componentValidator,
  describeErrors,
  openApiDocumentValidator,
  strictValidator,
} from '../testing/schema-validator';
import { buildInteractionOpenApi, INTERACTION_OPENAPI } from './openapi';
import type { JsonSchema } from './schema-kit';
import { stepJsonSchema } from './step-schema';
import { STEPS } from './steps';

/**
 * The schema lint of #590: the document is a valid OpenAPI 3.1 document, every
 * schema in it compiles under Ajv's strict mode, and every reference resolves.
 * The artifact tests make the committed file equal to this document, so the
 * lint holds for what the docs site and the auth server publish.
 */

const document = INTERACTION_OPENAPI as Record<string, unknown>;
const components = (document['components'] as { schemas: Record<string, JsonSchema> }).schemas;
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

describe('the Interaction API OpenAPI document', () => {
  it('validates against the official OpenAPI 3.1 schema, Schema Objects included', () => {
    const validate = openApiDocumentValidator();
    expect(validate(document), describeErrors(validate)).toBe(true);
  });

  it('is refused by that schema when it is broken, so the check is not vacuous', () => {
    const validate = openApiDocumentValidator();
    const broken = structuredClone(document) as Record<string, unknown>;
    (broken['info'] as Record<string, unknown>)['version'] = 1;
    expect(validate(broken)).toBe(false);
    const badSchema = structuredClone(document) as {
      components: { schemas: Record<string, Record<string, unknown>> };
    };
    badSchema.components.schemas['Csrf']['minLength'] = 'forty-three';
    expect(validate(badSchema)).toBe(false);
  });

  it('declares OpenAPI 3.1', () => {
    expect(document['openapi']).toMatch(/^3\.1\.\d+$/);
  });

  it('is deterministic', () => {
    expect(JSON.stringify(buildInteractionOpenApi())).toBe(JSON.stringify(INTERACTION_OPENAPI));
  });

  it('resolves every reference inside itself', () => {
    const refs = refsOf(document);
    expect(refs.length).toBeGreaterThan(50);
    for (const ref of refs) {
      expect(ref, 'references stay inside the document').toMatch(/^#\//);
      expect(resolvePointer(document, ref), `${ref} resolves`).toBeDefined();
    }
  });

  it('uses every component it declares', () => {
    const used = new Set(
      refsOf({ paths, schemas: components }).map((ref) => ref.split('/').slice(0, 4).join('/'))
    );
    for (const name of Object.keys(components)) {
      expect(used.has(`#/components/schemas/${name}`), `${name} is referenced`).toBe(true);
    }
  });

  it('compiles every component schema under strict mode', () => {
    const validator = componentValidator(document);
    for (const name of validator.names) {
      expect(() => validator.schema(name), name).not.toThrow();
    }
  });

  it('is refused by strict mode when a schema has a misspelt keyword', () => {
    const ajv = strictValidator();
    expect(() => ajv.compile({ type: 'string', maxLenght: 3 })).toThrow(/unknown keyword/);
  });

  it('compiles every step schema file under strict mode', () => {
    for (const step of STEPS) {
      expect(() => strictValidator().compile(stepJsonSchema(step)), step.name).not.toThrow();
    }
  });

  it('maps each discriminator value to the variant whose constant it is', () => {
    const unions = Object.entries(components).filter(([, schema]) => 'discriminator' in schema);
    expect(unions.map(([name]) => name).sort()).toEqual(['AnswerRequest', 'AnswerResult']);
    for (const [name, schema] of unions) {
      const { propertyName, mapping } = schema['discriminator'] as {
        propertyName: string;
        mapping: Record<string, string>;
      };
      const variants = (schema['oneOf'] as Array<{ $ref: string }>).map((variant) => variant.$ref);
      expect(Object.values(mapping).sort(), name).toEqual([...variants].sort());
      for (const [value, target] of Object.entries(mapping)) {
        const variant = resolvePointer(document, target) as JsonSchema;
        const property = (variant['properties'] as Record<string, JsonSchema>)[propertyName];
        expect(property?.['const'], `${name}: ${value}`).toBe(value);
        expect(variant['required'], `${name}: ${value}`).toContain(propertyName);
      }
    }
  });

  it('gives every operation a unique conventions-style operationId, a summary and a tag', () => {
    const ids: string[] = [];
    for (const [path, item] of Object.entries(paths)) {
      for (const [method, operation] of Object.entries(item)) {
        const at = `${method.toUpperCase()} ${path}`;
        expect(operation['operationId'], at).toMatch(/^[a-z]+(?:\.[a-z]+)+$/);
        expect(operation['summary'], at).toEqual(expect.any(String));
        expect(operation['description'], at).toEqual(expect.any(String));
        expect(operation['tags'], at).toEqual(['Interaction']);
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
