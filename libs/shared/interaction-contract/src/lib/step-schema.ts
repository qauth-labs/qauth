import { INTERACTION_API_VERSION } from './identifiers';
import type { JsonSchema } from './schema-kit';
import type { StepDefinition } from './step-definition';

/**
 * One JSON Schema (draft 2020-12) per step: the step's params, answer fields,
 * personal data, closed error set and `amr`, in one self-contained file (#590).
 *
 * The file's own schema describes the whole step as one record, `{ type,
 * params, answer, personal, error?, amr }`, and each part is a `$def`
 * addressable as `<file>#/$defs/answer` and so on. The record is the shape of
 * the step's test vector, and every part is reachable from the root, so the
 * stable-surface check compares all of them. Every reference points at the
 * file's own `$defs`, as the stable-surface registry requires of a JSON Schema
 * surface. These are the files the step grammar library (#591) generates from
 * its Zod schemas and compares with.
 */

/** Where the docs site publishes the contract: it serves `public/` at its root. */
export const CONTRACT_BASE_URL = `https://docs.qauth.dev/interaction/${INTERACTION_API_VERSION}/`;

/** The file name of one step's schema, relative to the contract's directory. */
export function stepSchemaFile(step: Pick<StepDefinition, 'name'>): string {
  return `steps/${step.name}.json`;
}

const withExamples = (schema: JsonSchema, example: unknown): JsonSchema => ({
  ...schema,
  examples: [example],
});

/** The step's example as one record, the root of its schema file. */
export function stepRecordExample(step: StepDefinition) {
  return {
    type: step.urn,
    params: step.example.step.params,
    answer: step.example.answer,
    personal: step.example.personal ?? {},
    ...(step.example.step.error === undefined ? {} : { error: step.example.step.error }),
    amr: [...step.amr],
  };
}

/** The JSON Schema file of one step. */
export function stepJsonSchema(step: StepDefinition): JsonSchema {
  const hasErrors = step.errors.length > 0;
  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: `${CONTRACT_BASE_URL}${stepSchemaFile(step)}`,
    title: step.urn,
    description: step.description,
    'x-qauth-transports': [...step.transports],
    type: 'object',
    properties: {
      type: { const: step.urn, description: 'The step name.' },
      params: { $ref: '#/$defs/params' },
      answer: { $ref: '#/$defs/answer' },
      personal: { $ref: '#/$defs/personal' },
      ...(hasErrors ? { error: { $ref: '#/$defs/error' } } : {}),
      amr: { $ref: '#/$defs/amr' },
    },
    required: ['type', 'params', 'answer', 'personal', 'amr'],
    examples: [stepRecordExample(step)],
    $defs: {
      params: { ...step.params, examples: [step.example.step.params] },
      answer: withExamples(step.answer, step.example.answer),
      personal: withExamples(step.personal, step.example.personal ?? {}),
      ...(hasErrors
        ? {
            error: {
              type: 'string',
              enum: [...step.errors],
              description: 'Why the last answer was refused. A closed set.',
            },
          }
        : {}),
      amr: {
        type: 'array',
        items: { type: 'string' },
        const: [...step.amr],
        description:
          step.amr.length === 0
            ? 'The RFC 8176 `amr` values a successful answer adds to the transaction: none, because the step proves no authenticator.'
            : 'The RFC 8176 `amr` values a successful answer adds to the transaction.',
      },
    },
  };
}
