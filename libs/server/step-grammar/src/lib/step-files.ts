import {
  type JsonSchema,
  stepJsonSchema,
  stepNamed,
} from '@qauth-labs/shared-interaction-contract';

import { toJsonSchemaPart } from './json-schema';
import { grammarStep, type StepName } from './steps';

/**
 * The step schema files of the Interaction API contract (#590), generated
 * from the grammar's Zod schemas.
 *
 * The contract publishes one JSON Schema per step under
 * `apps/docs-site/public/interaction/v1-rc.0/steps/`. Here the same file is
 * built with the contract's own file layout (`stepJsonSchema`), but from what
 * the grammar says: the params, personal data and answer generated from Zod,
 * and the grammar's transports, closed error set and `amr`. The step's prose
 * and its example stay the contract's: they are documentation and test
 * vectors, not types. `json-schema.test.ts` holds the result equal to the
 * published file, so the server's runtime checks and the published contract
 * cannot drift apart.
 */

/** The JSON Schema file of step `name`, generated from the grammar. */
export function generatedStepSchemaFile(name: StepName): JsonSchema {
  const step = grammarStep(name);
  const documented = stepNamed(name);
  return stepJsonSchema({
    ...documented,
    urn: step.urn,
    transports: step.transports,
    params: toJsonSchemaPart(step.params),
    personal: toJsonSchemaPart(step.personal),
    answer: toJsonSchemaPart(step.answer),
    errors: step.errors,
    amr: step.amr,
  });
}
