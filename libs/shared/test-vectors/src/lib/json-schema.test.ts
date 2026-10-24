import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { VECTOR_SCHEMA_ID } from './format';
import {
  SCHEMA_EXPORT_COMMAND,
  VECTOR_JSON_SCHEMA_PATH,
  vectorFileJsonSchema,
  vectorFileJsonSchemaText,
} from './json-schema';
import { findRepositoryRoot } from './validate';

describe('the published JSON Schema', () => {
  it(`is the committed ${VECTOR_JSON_SCHEMA_PATH} (regenerate with: ${SCHEMA_EXPORT_COMMAND})`, () => {
    const committed = readFileSync(join(findRepositoryRoot(), VECTOR_JSON_SCHEMA_PATH), 'utf8');
    expect(committed).toBe(vectorFileJsonSchemaText());
  });

  it('names the format version and closes both objects', () => {
    const schema = vectorFileJsonSchema() as {
      $id: string;
      title: string;
      additionalProperties: boolean;
      required: string[];
      properties: {
        schema: { const: string };
        cases: { items: { additionalProperties: boolean; required: string[] } };
      };
    };
    expect(schema.$id).toBe(`urn:qauth:schema:${VECTOR_SCHEMA_ID}`);
    expect(schema.title).toBe(VECTOR_SCHEMA_ID);
    expect(schema.properties.schema.const).toBe(VECTOR_SCHEMA_ID);
    expect(schema.required).toEqual(['schema', 'id', 'description', 'source', 'cases']);
    expect(schema.additionalProperties).toBe(false);
    expect(schema.properties.cases.items.required).toEqual(['id', 'input', 'expected']);
    expect(schema.properties.cases.items.additionalProperties).toBe(false);
  });
});
