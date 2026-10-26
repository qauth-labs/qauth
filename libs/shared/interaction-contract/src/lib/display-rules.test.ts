import { describe, expect, it } from 'vitest';

import { INTERACTION_OPENAPI, stepComponentNames } from './openapi';
import { DISPLAY_SOURCES, DISPLAY_TEXT_PATTERN, type JsonSchema } from './schema-kit';
import { stepJsonSchema } from './step-schema';
import { STEPS } from './steps';

/**
 * The display rule of ADR-019 Decision 6, as the acceptance criterion of #590
 * puts it: no response schema allows HTML or free end-user text, and every
 * string that reaches a screen is an enum or a bounded display value.
 *
 * The walk starts at every response of every operation, follows every
 * reference, and visits every schema a response can reach, the step params
 * and personal data included. Each string it finds must be an enum or a
 * constant, or carry a length cap and a pattern that refuses markup, control,
 * format and line-separator characters.
 */

const document = INTERACTION_OPENAPI as Record<string, unknown>;
const schemas = (document['components'] as { schemas: Record<string, JsonSchema> }).schemas;
const paths = document['paths'] as Record<string, Record<string, Record<string, unknown>>>;

/** Strings no response may carry: markup, a bidirectional override, controls, invisible format characters. */
const FORBIDDEN_SAMPLES = [
  '<b>bold</b>',
  'x<script>alert(1)</script>',
  'https://app.example.com/<img src=x>',
  `left${String.fromCodePoint(0x202e)}right`,
  `a${String.fromCodePoint(0x2066)}b`,
  `a${String.fromCodePoint(0x200b)}b`,
  `nul${String.fromCodePoint(0)}byte`,
  'two\nlines',
  `line${String.fromCodePoint(0x2028)}separator`,
];

/** The longest bounded string a response may carry. */
const MAX_LENGTH_CAP = 8192;

interface StringNode {
  readonly at: string;
  readonly schema: JsonSchema;
}

const SUBSCHEMA_LISTS = ['oneOf', 'anyOf', 'allOf', 'prefixItems'];
const SUBSCHEMAS = ['items', 'additionalProperties', 'propertyNames', 'not', 'contains'];

/** Every string schema reachable from `schema`, references followed once each. */
function collectStrings(
  schema: JsonSchema,
  at: string,
  out: StringNode[],
  seen: Set<string>
): StringNode[] {
  const ref = schema['$ref'];
  if (typeof ref === 'string') {
    const name = ref.replace('#/components/schemas/', '');
    if (seen.has(name)) return out;
    seen.add(name);
    const target = schemas[name];
    if (target === undefined) throw new Error(`${at}: ${ref} does not resolve`);
    return collectStrings(target, name, out, seen);
  }
  const isString =
    schema['type'] === 'string' ||
    typeof schema['const'] === 'string' ||
    (Array.isArray(schema['enum']) && schema['enum'].some((value) => typeof value === 'string'));
  if (isString) out.push({ at, schema });
  for (const [name, inner] of Object.entries(
    (schema['properties'] ?? {}) as Record<string, JsonSchema>
  )) {
    collectStrings(inner, `${at}.${name}`, out, seen);
  }
  for (const key of SUBSCHEMA_LISTS) {
    ((schema[key] ?? []) as JsonSchema[]).forEach((inner, index) =>
      collectStrings(inner, `${at}.${key}[${index}]`, out, seen)
    );
  }
  for (const key of SUBSCHEMAS) {
    const inner = schema[key];
    if (typeof inner === 'object' && inner !== null) {
      collectStrings(inner as JsonSchema, `${at}.${key}`, out, seen);
    }
  }
  return out;
}

/** The schemas of every response body of every operation. */
function responseSchemas(): Array<{ at: string; schema: JsonSchema; mediaType: string }> {
  const found: Array<{ at: string; schema: JsonSchema; mediaType: string }> = [];
  for (const [path, item] of Object.entries(paths)) {
    for (const [method, operation] of Object.entries(item)) {
      const responses = operation['responses'] as Record<
        string,
        { content?: Record<string, { schema: JsonSchema }> }
      >;
      for (const [status, response] of Object.entries(responses)) {
        for (const [mediaType, media] of Object.entries(response.content ?? {})) {
          found.push({
            at: `${method.toUpperCase()} ${path} ${status}`,
            schema: media.schema,
            mediaType,
          });
        }
      }
    }
  }
  return found;
}

/** Every string reachable from a response, and the components the walk reached. */
function walkResponses(): { strings: StringNode[]; reached: Set<string> } {
  const strings: StringNode[] = [];
  const reached = new Set<string>();
  for (const { at, schema } of responseSchemas()) collectStrings(schema, at, strings, reached);
  return { strings, reached };
}

const responseStrings = () => walkResponses().strings;

describe('the display rule (ADR-019 Decision 6)', () => {
  it('reaches every response body, the steps’ params and personal data included', () => {
    const { strings, reached } = walkResponses();
    expect(strings.length).toBeGreaterThan(80);
    for (const step of STEPS) {
      const names = stepComponentNames(step);
      expect(reached.has(names.params), names.params).toBe(true);
      expect(reached.has(names.personalData), names.personalData).toBe(true);
    }
  });

  it('answers only JSON and problem documents, never HTML', () => {
    for (const { at, mediaType } of responseSchemas()) {
      expect(['application/json', 'application/problem+json'], at).toContain(mediaType);
    }
    expect(JSON.stringify(document)).not.toMatch(/"text\/html"/);
  });

  it('carries no string that is not an enum, a constant or a bounded, patterned value', () => {
    for (const { at, schema } of responseStrings()) {
      const values = [
        ...(typeof schema['const'] === 'string' ? [schema['const']] : []),
        ...((schema['enum'] ?? []) as unknown[]).filter(
          (value): value is string => typeof value === 'string'
        ),
      ];
      if (values.length > 0) {
        for (const value of values) {
          for (const sample of ['<', '>', '\n'])
            expect(value.includes(sample), `${at}: ${value}`).toBe(false);
        }
        continue;
      }
      expect(schema['maxLength'], `${at} has a length cap`).toEqual(expect.any(Number));
      expect(schema['maxLength'] as number, at).toBeLessThanOrEqual(MAX_LENGTH_CAP);
      expect(schema['pattern'], `${at} has a pattern`).toEqual(expect.any(String));
      const pattern = new RegExp(String(schema['pattern']), 'u');
      for (const sample of FORBIDDEN_SAMPLES) {
        expect(pattern.test(sample), `${at} refuses ${JSON.stringify(sample)}`).toBe(false);
      }
    }
  });

  it('marks every display value with its source and the one display pattern', () => {
    const display = responseStrings().filter(({ schema }) => 'x-qauth-display' in schema);
    expect(display.length).toBeGreaterThan(10);
    for (const { at, schema } of display) {
      expect(DISPLAY_SOURCES, at).toContain(schema['x-qauth-display']);
      expect(schema['pattern'], at).toBe(DISPLAY_TEXT_PATTERN);
      expect(schema['minLength'], at).toBe(1);
    }
  });

  it('accepts ordinary display text, so the pattern is not a refusal of everything', () => {
    const pattern = new RegExp(DISPLAY_TEXT_PATTERN, 'u');
    for (const sample of [
      'Example Notes',
      'Read & write your notes',
      'Ünïcödé — 日本語',
      'alice@example.com',
    ]) {
      expect(pattern.test(sample), sample).toBe(true);
    }
  });

  it('lists a client-declared value only as declared', () => {
    const declared = responseStrings().filter(
      ({ schema }) => schema['x-qauth-display'] === 'declared'
    );
    expect(declared.map(({ at }) => at).sort()).toEqual(
      ['ClientDisplay.declaredName', 'DeviceConfirmPersonalData.user_agent'].sort()
    );
  });

  it('applies to the step schema files the same way', () => {
    for (const step of STEPS) {
      const file = stepJsonSchema(step);
      const defs = file['$defs'] as Record<string, JsonSchema>;
      const out: StringNode[] = [];
      collectStrings(defs['params'] as JsonSchema, `${step.name}.params`, out, new Set());
      collectStrings(defs['personal'] as JsonSchema, `${step.name}.personal`, out, new Set());
      for (const { at, schema } of out) {
        if ('const' in schema || 'enum' in schema) continue;
        expect(schema['maxLength'], at).toEqual(expect.any(Number));
        expect(schema['pattern'], at).toEqual(expect.any(String));
      }
    }
  });
});
