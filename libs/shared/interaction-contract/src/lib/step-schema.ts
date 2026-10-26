import { INTERACTION_API_VERSION } from './identifiers';
import type { JsonSchema } from './schema-kit';
import type { StepDefinition } from './step-definition';

/**
 * One JSON Schema (draft 2020-12) per step: the step's params, answer fields,
 * personal data, closed error set and `amr`, in one self-contained file (#590).
 *
 * The file's own schema is the step object as a step read carries it
 * (`{ type, params, error? }`); the other parts are `$defs` of it, addressable
 * as `<file>#/$defs/answer` and so on. Every reference points at the file's
 * own `$defs`, as the stable-surface registry requires of a JSON Schema
 * surface. Each part carries the step's example, so the file is its own test
 * vector. These are the files the step grammar library (#591) generates from
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
      type: { const: step.urn },
      params: { $ref: '#/$defs/params' },
      ...(hasErrors ? { error: { $ref: '#/$defs/error' } } : {}),
    },
    required: ['type', 'params'],
    examples: [step.example.step],
    $defs: {
      params: step.params,
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
        const: [...step.amr],
        description:
          step.amr.length === 0
            ? 'The RFC 8176 `amr` values a successful answer adds to the transaction: none, because the step proves no authenticator.'
            : 'The RFC 8176 `amr` values a successful answer adds to the transaction.',
      },
    },
  };
}
