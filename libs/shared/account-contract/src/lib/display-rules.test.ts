import { describe, expect, it } from 'vitest';

import { ACCOUNT_OPENAPI } from './openapi';
import { DISPLAY_SOURCES, DISPLAY_TEXT_PATTERN, type JsonSchema } from './schema-kit';

/**
 * The acceptance criterion "no schema allows HTML or free end-user text", as
 * the display rule of ADR-019 Decision 6 puts it: every string a response or a
 * request carries is an enum, a constant, or a bounded value whose pattern
 * refuses markup, control, format and line-separator characters.
 *
 * The walk starts at every response and every request body of every
 * operation, follows every reference, and visits every schema they reach. The
 * one exception is a password, a credential rather than text: `format:
 * password` and `writeOnly`, reachable only from a request.
 */

const document = ACCOUNT_OPENAPI as Record<string, unknown>;
const schemas = (document['components'] as { schemas: Record<string, JsonSchema> }).schemas;
const paths = document['paths'] as Record<string, Record<string, Record<string, unknown>>>;

/** Strings no schema may admit: markup, a bidirectional override, controls, invisible format characters. */
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

/** The only object that may carry members it does not declare: the problem document (RFC 9457 §3.2). */
const OPEN_OBJECTS = ['Problem'];

/** The longest bounded string the API carries. */
const MAX_LENGTH_CAP = 2048;

interface StringNode {
  readonly at: string;
  readonly schema: JsonSchema;
}

const SUBSCHEMA_LISTS = ['oneOf', 'anyOf', 'allOf', 'prefixItems'];
/** `not` is left out: what it holds is a value never carried. */
const SUBSCHEMAS = ['items', 'additionalProperties', 'propertyNames', 'contains'];

const isStringSchema = (schema: JsonSchema) => {
  const type = schema['type'];
  return (
    type === 'string' ||
    (Array.isArray(type) && type.includes('string')) ||
    typeof schema['const'] === 'string' ||
    (Array.isArray(schema['enum']) && schema['enum'].some((value) => typeof value === 'string'))
  );
};

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
  if (isStringSchema(schema)) out.push({ at, schema });
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

type Body = { at: string; schema: JsonSchema; mediaType: string };

/** The schemas of every response body, or of every request body, of every operation. */
function bodies(kind: 'response' | 'request'): Body[] {
  const found: Body[] = [];
  for (const [path, item] of Object.entries(paths)) {
    for (const [method, operation] of Object.entries(item)) {
      const at = `${method.toUpperCase()} ${path}`;
      if (kind === 'request') {
        const body = operation['requestBody'] as
          | { content: Record<string, { schema: JsonSchema }> }
          | undefined;
        for (const [mediaType, media] of Object.entries(body?.content ?? {})) {
          found.push({ at: `${at} request`, schema: media.schema, mediaType });
        }
        continue;
      }
      const responses = operation['responses'] as Record<
        string,
        { content?: Record<string, { schema: JsonSchema }> }
      >;
      for (const [status, response] of Object.entries(responses)) {
        for (const [mediaType, media] of Object.entries(response.content ?? {})) {
          found.push({ at: `${at} ${status}`, schema: media.schema, mediaType });
        }
      }
    }
  }
  return found;
}

function walk(kind: 'response' | 'request'): { strings: StringNode[]; reached: Set<string> } {
  const strings: StringNode[] = [];
  const reached = new Set<string>();
  for (const { at, schema } of bodies(kind)) collectStrings(schema, at, strings, reached);
  return { strings, reached };
}

/** A password: the one string that takes any character. */
const isPassword = (schema: JsonSchema) =>
  schema['format'] === 'password' && schema['writeOnly'] === true;

function assertBoundedAndPatterned({ at, schema }: StringNode): void {
  const values = [
    ...(typeof schema['const'] === 'string' ? [schema['const']] : []),
    ...((schema['enum'] ?? []) as unknown[]).filter(
      (value): value is string => typeof value === 'string'
    ),
  ];
  if (values.length > 0) {
    for (const value of values) {
      for (const sample of ['<', '>', '\n']) {
        expect(value.includes(sample), `${at}: ${value}`).toBe(false);
      }
    }
    return;
  }
  expect(schema['maxLength'], `${at} has a length cap`).toEqual(expect.any(Number));
  expect(schema['maxLength'] as number, at).toBeLessThanOrEqual(MAX_LENGTH_CAP);
  expect(schema['pattern'], `${at} has a pattern`).toEqual(expect.any(String));
  const pattern = new RegExp(String(schema['pattern']), 'u');
  for (const sample of FORBIDDEN_SAMPLES) {
    expect(pattern.test(sample), `${at} refuses ${JSON.stringify(sample)}`).toBe(false);
  }
}

describe('the display rule (ADR-019 Decision 6)', () => {
  it('reaches every component from the operations', () => {
    const reached = new Set([...walk('response').reached, ...walk('request').reached]);
    expect([...reached].sort()).toEqual(Object.keys(schemas).sort());
  });

  it('answers only JSON and problem documents, never HTML', () => {
    for (const { at, mediaType } of bodies('response')) {
      expect(['application/json', 'application/problem+json'], at).toContain(mediaType);
    }
    for (const { at, mediaType } of bodies('request')) {
      expect(['application/json', 'application/merge-patch+json'], at).toContain(mediaType);
    }
    expect(JSON.stringify(document)).not.toMatch(/"text\/html"/);
  });

  it('carries no response string that is not an enum, a constant or a bounded, patterned value', () => {
    const { strings } = walk('response');
    expect(strings.length).toBeGreaterThan(60);
    for (const node of strings) {
      expect(isPassword(node.schema), `${node.at} is a password in a response`).toBe(false);
      assertBoundedAndPatterned(node);
    }
  });

  it('takes no request string that is not an enum, a constant or a bounded, patterned value, but a password', () => {
    const { strings } = walk('request');
    const passwords = strings.filter(({ schema }) => isPassword(schema)).map(({ at }) => at);
    expect(passwords.sort()).toEqual([
      'PasswordChangeRequest.currentPassword',
      'PasswordChangeRequest.newPassword',
    ]);
    for (const node of strings) {
      if (isPassword(node.schema)) {
        expect(node.schema['maxLength'], node.at).toBe(256);
        continue;
      }
      assertBoundedAndPatterned(node);
    }
  });

  it('marks every display value with its source and a pattern that refuses blank or padded text', () => {
    const display = [...walk('response').strings, ...walk('request').strings].filter(
      ({ schema }) => 'x-qauth-display' in schema
    );
    expect(display.length).toBeGreaterThan(15);
    for (const { at, schema } of display) {
      expect(DISPLAY_SOURCES, at).toContain(schema['x-qauth-display']);
      expect(schema['minLength'] as number, at).toBeGreaterThanOrEqual(1);
      const pattern = new RegExp(String(schema['pattern']), 'u');
      for (const sample of [' ', ' padded', 'padded ', String.fromCodePoint(0x3164)]) {
        expect(pattern.test(sample), `${at} refuses ${JSON.stringify(sample)}`).toBe(false);
      }
      if (!/address$/i.test(at)) expect(schema['pattern'], at).toBe(DISPLAY_TEXT_PATTERN);
    }
  });

  it('marks every value a client or a device declared as declared', () => {
    const declared = walk('response')
      .strings.filter(
        ({ schema }) =>
          schema['x-qauth-display'] === 'declared' || schema['x-qauth-declared'] === true
      )
      .map(({ at }) => at);
    expect(declared.sort()).toEqual(
      [
        'ClientReference.client_id',
        'ClientReference.client_name',
        'Consent.client_id',
        'Consent.client_name',
        'Device.label',
      ].sort()
    );
  });

  it('gives every schema a type, and closes every object but the problem document', () => {
    const typed = ['type', 'const', 'enum', '$ref', 'oneOf', 'not'];
    const problems: string[] = [];
    const seen = new Set<string>();
    let objects = 0;
    const visit = (schema: JsonSchema, at: string) => {
      const ref = schema['$ref'];
      if (typeof ref === 'string') {
        const name = ref.replace('#/components/schemas/', '');
        if (seen.has(name)) return;
        seen.add(name);
        visit(schemas[name] ?? {}, name);
        return;
      }
      if (!typed.some((keyword) => keyword in schema)) problems.push(`${at} has no type`);
      if (schema['type'] === 'object') {
        objects++;
        const additional = schema['additionalProperties'];
        const closed =
          additional === false ||
          (typeof additional === 'object' && additional !== null && 'propertyNames' in schema);
        if (!closed && !OPEN_OBJECTS.includes(at)) problems.push(`${at} is not closed`);
      }
      for (const [name, inner] of Object.entries(
        (schema['properties'] ?? {}) as Record<string, JsonSchema>
      )) {
        visit(inner, `${at}.${name}`);
      }
      for (const key of ['oneOf', 'anyOf', 'prefixItems']) {
        ((schema[key] ?? []) as JsonSchema[]).forEach((inner, index) =>
          visit(inner, `${at}.${key}[${index}]`)
        );
      }
      for (const key of ['items', 'additionalProperties']) {
        const inner = schema[key];
        if (typeof inner === 'object' && inner !== null) visit(inner as JsonSchema, `${at}.${key}`);
      }
    };
    for (const { at, schema } of [...bodies('response'), ...bodies('request')]) visit(schema, at);
    expect(problems).toEqual([]);
    expect(objects).toBeGreaterThan(30);
  });
});
