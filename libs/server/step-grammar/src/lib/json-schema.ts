import type { JsonSchema } from '@qauth-labs/shared-interaction-contract';
import { z } from 'zod';

/**
 * JSON Schema (draft 2020-12) from the step grammar's Zod schemas.
 *
 * Zod's own conversion writes a few things differently from the Interaction
 * API contract (#590), which publishes the step schemas. The meaning is the
 * same; the spelling is the contract's:
 *
 * - a single string or boolean value is `{ "const": v }`, without the `type`
 *   that `const` already implies;
 * - number values are integers here, written `{ "type": "integer", "enum":
 *   [...] }`, as the contract writes `digits` and the COSE algorithms;
 * - an open object (one that may carry members it does not declare) has no
 *   `additionalProperties` member, and no `properties` when it declares
 *   none, where Zod writes `additionalProperties: {}`.
 *
 * Everything else comes from Zod as it is: bounds, patterns, enums, closed
 * objects, required members, unions (`z.xor` is `oneOf`), and the annotations
 * the schemas carry in `.meta()`.
 */

type JsonObject = Record<string, unknown>;

/** Rewrite one node of Zod's output into the contract's spelling; see the module comment. */
function contractSpelling(ctx: { zodSchema: z.core.$ZodTypes; jsonSchema: JsonObject }): void {
  const { zodSchema, jsonSchema } = ctx;
  const def = zodSchema._zod.def;
  if (def.type === 'literal') {
    const values = def.values;
    if (values.every((value) => typeof value === 'number')) {
      if (!values.every((value) => Number.isInteger(value))) {
        throw new Error('a step grammar number value must be an integer');
      }
      delete jsonSchema['const'];
      jsonSchema['type'] = 'integer';
      jsonSchema['enum'] = [...values];
    } else if ('const' in jsonSchema) {
      delete jsonSchema['type'];
    }
    return;
  }
  if (def.type === 'object') {
    const additional = jsonSchema['additionalProperties'];
    const open =
      typeof additional === 'object' && additional !== null && Object.keys(additional).length === 0;
    if (!open) return;
    delete jsonSchema['additionalProperties'];
    const properties = jsonSchema['properties'];
    if (
      typeof properties === 'object' &&
      properties !== null &&
      Object.keys(properties).length === 0
    ) {
      delete jsonSchema['properties'];
    }
  }
}

/**
 * The JSON Schema of one Zod schema, as a part of a step file: no `$schema`,
 * which only the file's root carries. `io: 'input'` because the schemas
 * describe the wire: an answer member with a default (`remember`) is optional
 * there. A Zod construct JSON Schema cannot express throws.
 */
export function toJsonSchemaPart(schema: z.ZodType): JsonSchema {
  const generated = z.toJSONSchema(schema, {
    target: 'draft-2020-12',
    unrepresentable: 'throw',
    io: 'input',
    override: (ctx) => contractSpelling(ctx as Parameters<typeof contractSpelling>[0]),
  }) as JsonObject;
  delete generated['$schema'];
  return generated;
}
