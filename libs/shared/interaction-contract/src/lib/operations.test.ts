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
import { stepNamed } from './steps';

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

describe('the client display data and the problem body', () => {
  const validator = componentValidator(INTERACTION_OPENAPI);

  it('require the verified data each kind of client has, and no logo for an unverified one', () => {
    const client = validator.schema('ClientDisplay');
    const cimd = {
      kind: 'cimd',
      verifiedDomain: {
        host: 'app.example.com',
        registrableDomain: 'example.com',
        sharedHosting: false,
      },
      redirect: { target: 'host', host: 'app.example.com' },
      newClient: false,
    };
    expect(client(cimd), describeErrors(client)).toBe(true);
    const withoutDomain: Record<string, unknown> = { ...cimd };
    delete withoutDomain['verifiedDomain'];
    expect(client(withoutDomain)).toBe(false);
    expect(client({ kind: 'federation', newClient: false })).toBe(false);
    expect(client({ ...cimd, redirect: { target: 'host' } })).toBe(false);
    expect(client({ ...cimd, redirect: { target: 'app' } })).toBe(false);
    const unverified = { kind: 'unverified', redirect: { target: 'this_device' }, newClient: true };
    expect(client(unverified), describeErrors(client)).toBe(true);
    expect(
      client({ ...unverified, logo: { url: '/ui/assets/logo-3f9a1c2e.svg', width: 1, height: 1 } })
    ).toBe(false);
    expect(client({ ...unverified, verifiedDomain: cimd.verifiedDomain })).toBe(false);
    // Each kind refuses the other kinds' members.
    const federation = {
      kind: 'federation',
      federation: { entityId: 'https://rp.example.com', trustMarks: [] },
      newClient: false,
    };
    expect(client(federation), describeErrors(client)).toBe(true);
    expect(client({ ...federation, verifiedDomain: cimd.verifiedDomain })).toBe(false);
    expect(client({ ...cimd, federation: federation.federation })).toBe(false);
    expect(client({ ...cimd, kind: 'admin_registered', federation: federation.federation })).toBe(
      false
    );
    expect(client({ ...cimd, unknownMember: true })).toBe(false);
  });

  it('hold a step read to its step: its own params, a unique list of alternatives, a consent screen’s client', () => {
    const interaction = validator.schema('Interaction');
    const consent = 'urn:qauth:ia:consent:v1-rc.0';
    const password = 'urn:qauth:ia:password:v1-rc.0';
    const base = {
      step: password,
      alternatives: [],
      params: { [password]: {} },
      csrf: 'cGVyLXN0ZXAtY3NyZi12YWx1ZS1vZi0zMi1ieXRlcyE',
      brand: { font: 'system', darkMode: 'enabled' },
      expiresAt: '2026-10-26T10:00:00Z',
    };
    expect(interaction(base), describeErrors(interaction)).toBe(true);
    expect(interaction({ ...base, params: {} })).toBe(false);
    const totp = 'urn:qauth:ia:totp:v1-rc.0';
    expect(interaction({ ...base, alternatives: [totp, totp] })).toBe(false);
    const unverified = { kind: 'unverified', newClient: true };
    const consentRead = {
      ...base,
      step: consent,
      params: { [consent]: stepNamed('consent').example.step.params },
    };
    expect(
      interaction({
        ...consentRead,
        client: { ...unverified, redirect: { target: 'this_device' } },
      }),
      describeErrors(interaction)
    ).toBe(true);
    expect(interaction({ ...consentRead, client: unverified })).toBe(false);
    expect(interaction(consentRead)).toBe(false);
    expect(interaction({ ...base, client: unverified }), describeErrors(interaction)).toBe(true);
  });

  it('refuse a problem document that carries prose', () => {
    const problem = validator.schema('Problem');
    const base = {
      type: 'https://docs.qauth.dev/reference/problem-types/#interaction-expired',
      title: 'Interaction expired',
      status: 410,
      code: 'interaction_expired',
      trace_id: 'req-1',
    };
    expect(problem(base), describeErrors(problem)).toBe(true);
    expect(
      problem({
        ...base,
        type: 'https://docs.qauth.dev/reference/problem-types/#content-too-large',
        title: 'Content too large',
        status: 413,
        code: 'content_too_large',
      })
    ).toBe(true);
    for (const member of ['detail', 'instance', 'errors']) {
      expect(problem({ ...base, [member]: 'The interaction expired.' }), member).toBe(false);
    }
    expect(problem({ ...base, title: '<b>Interaction expired</b>' })).toBe(false);
  });

  it('refuse a redirect to a scheme a browser would run', () => {
    const redirect = validator.schema('RedirectResult');
    expect(redirect({ result: 'redirect', location: 'com.example.app:/callback?code=x' })).toBe(
      true
    );
    for (const location of ['javascript:alert(1)', 'data:text/html,x', 'JavaScript:alert(1)']) {
      expect(redirect({ result: 'redirect', location }), location).toBe(false);
    }
  });
});
