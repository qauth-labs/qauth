import { describe, expect, it } from 'vitest';

import { componentValidator, describeErrors } from '../testing/schema-validator';
import { ACCOUNT_OPENAPI, problemExample } from './openapi';
import { ACCOUNT_OPERATIONS } from './operations';
import { ACCOUNT_PROBLEM_CODES, type AccountProblemCodeName } from './problems';

/**
 * The acceptance criterion "examples validate against the schemas": every
 * operation has one example request and one example response, and each one,
 * like every problem example, validates against the schema it illustrates.
 */

const document = ACCOUNT_OPENAPI as Record<string, unknown>;
const paths = document['paths'] as Record<string, Record<string, OperationObject>>;
const examples = (document['components'] as { examples: Record<string, { value: unknown }> })
  .examples;
const validator = componentValidator(document);

interface MediaObject {
  schema: Record<string, unknown>;
  example?: unknown;
  examples?: Record<string, { $ref: string }>;
}

interface OperationObject {
  operationId: string;
  parameters?: Array<{
    name: string;
    in: string;
    required: boolean;
    schema: Record<string, unknown>;
    example?: unknown;
  }>;
  requestBody?: { required: boolean; content: Record<string, MediaObject> };
  responses: Record<
    string,
    { content?: Record<string, MediaObject>; 'x-qauth-problem-codes'?: string[] }
  >;
}

const operations = Object.entries(paths).flatMap(([path, item]) =>
  Object.entries(item).map(([method, operation]) => ({
    at: `${method.toUpperCase()} ${path}`,
    operation,
  }))
);

function check(schema: Record<string, unknown>, value: unknown, at: string): void {
  const validate = validator.compile(schema);
  expect(validate(value), `${at}: ${describeErrors(validate)}`).toBe(true);
}

describe('the examples', () => {
  it('cover every operation', () => {
    expect(operations).toHaveLength(ACCOUNT_OPERATIONS.length);
  });

  it.each(operations.map(({ at, operation }) => [at, operation] as const))(
    '%s: its example request validates',
    (at, operation) => {
      for (const parameter of operation.parameters ?? []) {
        if (parameter.required) {
          expect(parameter.example, `${at} ${parameter.name} has an example`).toBeDefined();
        }
        if (parameter.example !== undefined) {
          check(parameter.schema, parameter.example, `${at} ${parameter.name}`);
        }
      }
      for (const [mediaType, media] of Object.entries(operation.requestBody?.content ?? {})) {
        expect(media.example, `${at} ${mediaType} has an example`).toBeDefined();
        check(media.schema, media.example, `${at} ${mediaType}`);
      }
    }
  );

  it.each(operations.map(({ at, operation }) => [at, operation] as const))(
    '%s: its example response validates',
    (at, operation) => {
      const successes = Object.entries(operation.responses).filter(([status]) =>
        status.startsWith('2')
      );
      expect(successes, at).toHaveLength(1);
      const [[status, response]] = successes;
      if (status === '204') {
        expect(response.content, at).toBeUndefined();
        return;
      }
      const media = response.content?.['application/json'];
      expect(media?.example, `${at} ${status} has an example`).toBeDefined();
      check(media?.schema ?? {}, media?.example, `${at} ${status}`);
    }
  );

  it('give every error response one example per code it may carry, with its status', () => {
    for (const { at, operation } of operations) {
      for (const [status, response] of Object.entries(operation.responses)) {
        if (!/^[45]/.test(status)) continue;
        const codes = response['x-qauth-problem-codes'] ?? [];
        expect(codes.length, `${at} ${status}`).toBeGreaterThan(0);
        const media = response.content?.['application/problem+json'];
        expect(Object.keys(media?.examples ?? {}), `${at} ${status}`).toEqual(codes);
        for (const code of codes) {
          expect(media?.examples?.[code]?.$ref).toBe(`#/components/examples/${code}`);
          expect(
            ACCOUNT_PROBLEM_CODES[code as AccountProblemCodeName].status,
            `${at}: ${code}`
          ).toBe(Number(status));
        }
      }
    }
  });

  it.each(Object.keys(ACCOUNT_PROBLEM_CODES).map((code) => [code] as const))(
    'the %s problem example validates against Problem',
    (code) => {
      const value = examples[code]?.value;
      expect(value).toEqual(problemExample(code as AccountProblemCodeName));
      const validate = validator.schema('Problem');
      expect(validate(value), describeErrors(validate)).toBe(true);
    }
  );

  it('are checked, so a wrong example fails', () => {
    const validate = validator.schema('Passkey');
    expect(validate({ id: 'not-a-uuid', nickname: '<b>x</b>' })).toBe(false);
    const problem = validator.schema('Problem');
    expect(
      problem({ ...problemExample('insufficient_user_authentication'), max_age: undefined })
    ).toBe(false);
    expect(problem({ ...problemExample('not_found'), detail: 'Not here.' })).toBe(false);
  });
});
