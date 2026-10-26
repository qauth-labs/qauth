import { describe, expect, it } from 'vitest';

import { componentValidator, describeErrors } from '../testing/schema-validator';
import {
  FLOW_COOKIE_NAME,
  INTERACTION_API_PREFIX,
  INTERACTION_OPENAPI_PATH,
  WALLET_RETURN_PREFIX,
} from './identifiers';
import { INTERACTION_OPENAPI } from './openapi';
import { INTERACTION_PROBLEM_CODES } from './problems';
import type { JsonSchema } from './schema-kit';

/**
 * The operations of #590 and what each needs: every operation lists its
 * success and error responses and says whether it needs the flow cookie and
 * the CSRF value (an acceptance criterion), and none takes a navigational
 * parameter (ADR-019 Decision 6).
 */

type Operation = Record<string, unknown> & {
  responses: Record<string, Record<string, unknown>>;
  requestBody?: { content: Record<string, { schema: JsonSchema }> };
};

const document = INTERACTION_OPENAPI as Record<string, unknown>;
const schemas = (document['components'] as { schemas: Record<string, JsonSchema> }).schemas;
const paths = document['paths'] as Record<string, Record<string, Operation>>;

const operations = Object.entries(paths).flatMap(([path, item]) =>
  Object.entries(item).map(([method, operation]) => ({
    at: `${method.toUpperCase()} ${path}`,
    path,
    method,
    operation,
  }))
);

const resolve = (schema: JsonSchema): JsonSchema => {
  const ref = schema['$ref'];
  return typeof ref === 'string'
    ? (schemas[ref.replace('#/components/schemas/', '')] ?? {})
    : schema;
};

/** Every object variant a request body schema allows: the members of a union, or the object itself. */
const variantsOf = (schema: JsonSchema): JsonSchema[] => {
  const resolved = resolve(schema);
  return Array.isArray(resolved['oneOf'])
    ? (resolved['oneOf'] as JsonSchema[]).map(resolve)
    : [resolved];
};

describe('the Interaction API operations', () => {
  it('are the four of #590: read, read personal data, answer, cancel', () => {
    expect(operations.map(({ operation }) => operation['operationId'])).toEqual([
      'interactions.get',
      'interactions.personal.get',
      'interactions.answer',
      'interactions.cancel',
    ]);
  });

  it('all sit under the versioned prefix, and none under the reserved wallet prefix', () => {
    expect(document['x-qauth-reserved-prefixes']).toEqual([WALLET_RETURN_PREFIX]);
    expect(WALLET_RETURN_PREFIX).toBe('/interaction/v1-rc.0/wallet/');
    for (const { at, path } of operations) {
      expect(path.startsWith(`${INTERACTION_API_PREFIX}/`), at).toBe(true);
      expect(path.startsWith(WALLET_RETURN_PREFIX), at).toBe(false);
    }
    // An interaction id can never be the reserved segment, nor the document's file name.
    const idPattern = new RegExp(String(schemas['InteractionId']?.['pattern']), 'u');
    expect(idPattern.test('wallet')).toBe(false);
    expect(idPattern.test('openapi.json')).toBe(false);
    expect(INTERACTION_OPENAPI_PATH).toBe('/interaction/v1-rc.0/openapi.json');
  });

  it('say whether they need the flow cookie and the CSRF value, consistently', () => {
    for (const { at, operation } of operations) {
      const cookie = operation['x-qauth-flow-cookie'];
      const csrf = operation['x-qauth-csrf'];
      expect(['required', 'none'], at).toContain(cookie);
      expect(['required', 'none'], at).toContain(csrf);
      expect(operation['security'], at).toEqual(cookie === 'required' ? [{ flowCookie: [] }] : []);
      if (csrf === 'required') {
        expect(cookie, `${at}: a CSRF value is always bound to the flow cookie`).toBe('required');
        expect(operation.requestBody, at).toBeDefined();
        for (const [mediaType, media] of Object.entries(operation.requestBody?.content ?? {})) {
          for (const variant of variantsOf(media.schema)) {
            expect(variant['required'], `${at} ${mediaType}`).toContain('csrf');
            expect(variant['additionalProperties'], `${at} ${mediaType}`).toBe(false);
          }
        }
      } else {
        expect(operation.requestBody, `${at}: a read takes no body`).toBeUndefined();
      }
    }
    const scheme = (document['components'] as { securitySchemes: Record<string, JsonSchema> })
      .securitySchemes['flowCookie'];
    expect(scheme).toMatchObject({ type: 'apiKey', in: 'cookie', name: FLOW_COOKIE_NAME });
  });

  it('read with the id alone, and need the flow cookie for personal data, answers and cancels', () => {
    const needs = Object.fromEntries(
      operations.map(({ operation }) => [
        operation['operationId'],
        [operation['x-qauth-flow-cookie'], operation['x-qauth-csrf']],
      ])
    );
    expect(needs).toEqual({
      'interactions.get': ['none', 'none'],
      'interactions.personal.get': ['required', 'none'],
      'interactions.answer': ['required', 'required'],
      'interactions.cancel': ['required', 'required'],
    });
  });

  it('take answers as JSON or as a form post', () => {
    for (const { at, operation } of operations) {
      if (operation.requestBody === undefined) continue;
      expect(Object.keys(operation.requestBody.content).sort(), at).toEqual([
        'application/json',
        'application/x-www-form-urlencoded',
      ]);
    }
  });

  it('list their success and error responses, every error a problem document with its codes', () => {
    for (const { at, operation } of operations) {
      const statuses = Object.keys(operation.responses);
      expect(
        statuses.some((status) => status.startsWith('2')),
        at
      ).toBe(true);
      expect(statuses.filter((status) => /^[45]/.test(status)).length, at).toBeGreaterThan(3);
      for (const [status, response] of Object.entries(operation.responses)) {
        expect(response['description'], `${at} ${status}`).toEqual(expect.any(String));
        if (!/^[45]/.test(status)) continue;
        const codes = response['x-qauth-problem-codes'] as string[];
        expect(codes.length, `${at} ${status}`).toBeGreaterThan(0);
        for (const code of codes) {
          const entry = INTERACTION_PROBLEM_CODES[code as keyof typeof INTERACTION_PROBLEM_CODES];
          expect(entry?.status, `${at} ${status} ${code}`).toBe(Number(status));
        }
        expect(Object.keys(response['content'] as object), `${at} ${status}`).toEqual([
          'application/problem+json',
        ]);
      }
      expect(statuses, `${at}: every operation can be throttled`).toContain('429');
    }
  });

  it('answer a form post with 303, and a JSON answer with a result', () => {
    for (const { at, operation } of operations) {
      if (operation.requestBody === undefined) continue;
      const seeOther = operation.responses['303'] as {
        headers: Record<string, unknown>;
        content?: unknown;
      };
      expect(seeOther, at).toBeDefined();
      expect(Object.keys(seeOther.headers), at).toContain('Location');
      expect(seeOther.content, at).toBeUndefined();
    }
  });

  it('send Cache-Control: no-store on every response, and Retry-After on a 429', () => {
    const headers = (document['components'] as { headers: Record<string, { schema: JsonSchema }> })
      .headers;
    expect(headers['CacheControl']?.schema['const']).toBe('no-store');
    for (const { at, operation } of operations) {
      for (const [status, response] of Object.entries(operation.responses)) {
        const responseHeaders = response['headers'] as Record<string, { $ref: string }>;
        expect(responseHeaders['Cache-Control']?.$ref, `${at} ${status}`).toBe(
          '#/components/headers/CacheControl'
        );
        if (status === '429') {
          expect(responseHeaders['Retry-After']?.$ref, at).toBe('#/components/headers/RetryAfter');
        }
      }
    }
  });

  it('take no query parameter, and no navigational member anywhere', () => {
    const navigational =
      /^(?:return_?to|returnTo|redirect(?:_?uri|Uri|_?to|To)?|client_?id|clientId|state)$/;
    for (const { at, operation } of operations) {
      const parameters = (operation['parameters'] ?? []) as Array<{ in: string; name: string }>;
      expect(
        parameters.filter((parameter) => parameter.in !== 'path'),
        at
      ).toEqual([]);
      for (const media of Object.values(operation.requestBody?.content ?? {})) {
        for (const variant of variantsOf(media.schema)) {
          for (const name of Object.keys((variant['properties'] ?? {}) as object)) {
            expect(name, at).not.toMatch(navigational);
          }
        }
      }
    }
  });

  it('carry examples that validate, the problem documents and the cancel request included', () => {
    const validator = componentValidator(INTERACTION_OPENAPI);
    let checked = 0;
    const check = (schema: JsonSchema, value: unknown, at: string) => {
      const validate = validator.compile(schema);
      expect(validate(value), `${at}\n${describeErrors(validate)}`).toBe(true);
      checked += 1;
    };
    for (const { at, operation } of operations) {
      const media = [
        ...Object.entries(operation.requestBody?.content ?? {}).map(
          ([type, value]) => [`${at} request ${type}`, value] as const
        ),
        ...Object.entries(operation.responses).flatMap(([status, response]) =>
          Object.entries((response['content'] ?? {}) as Record<string, unknown>).map(
            ([type, value]) => [`${at} ${status} ${type}`, value] as const
          )
        ),
      ] as Array<
        readonly [
          string,
          { schema: JsonSchema; example?: unknown; examples?: Record<string, { value: unknown }> },
        ]
      >;
      for (const [where, content] of media) {
        if (content.example !== undefined) check(content.schema, content.example, where);
        for (const [name, example] of Object.entries(content.examples ?? {})) {
          check(content.schema, example.value, `${where} ${name}`);
        }
      }
    }
    expect(checked).toBeGreaterThan(70);
  });
});
