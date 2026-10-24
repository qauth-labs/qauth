import { z } from 'zod';

import { VECTOR_SCHEMA_ID, vectorFileShapeSchema } from './format';

/** Where the published JSON Schema lives, from the repository root. */
export const VECTOR_JSON_SCHEMA_PATH = 'test-vectors/schema/vector-file.schema.json';

/** The command that writes it. */
export const SCHEMA_EXPORT_COMMAND =
  'pnpm exec nx run shared-test-vectors:schema-export --skip-nx-cache';

type JsonObject = Record<string, unknown>;

/**
 * The JSON Schema (draft 2020-12) of a vector file, generated from the Zod
 * schema. Objects stay closed (`additionalProperties: false`): a reader
 * rejects a member it does not know, and a new member needs a new format
 * version. `$id` names the format version and is not a URL to fetch.
 */
export function vectorFileJsonSchema(): JsonObject {
  const { $schema, title, description, ...rest } = z.toJSONSchema(vectorFileShapeSchema, {
    target: 'draft-2020-12',
    unrepresentable: 'throw',
  }) as JsonObject;
  return {
    $schema,
    $id: `urn:qauth:schema:${VECTOR_SCHEMA_ID}`,
    title,
    description,
    ...rest,
  };
}

/** The file's content, as the export script writes it and the test compares it. */
export function vectorFileJsonSchemaText(): string {
  return `${JSON.stringify(vectorFileJsonSchema(), null, 2)}\n`;
}
