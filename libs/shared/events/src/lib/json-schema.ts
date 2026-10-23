import { z } from 'zod';

import type { EventTypeDefinition } from './definition';
import { envelopeSchema, EXTENSIBLE_ENUM_META } from './envelope';
import { eventVersionLabel } from './identifier';
import { eventSchemaFor } from './registry';

/**
 * The published JSON Schema (draft 2020-12) of the envelope and of every
 * event type, generated from the Zod schemas. Pure: `artifacts.ts` decides
 * where the files go and the export script writes them.
 *
 * Two changes separate a published schema from the Zod schema it comes from,
 * both because a consumer validates with the schema of the release it was
 * built against while QAuth moves on:
 *
 * - Objects are open: no `additionalProperties: false`. A minor release may
 *   add an optional member (ADR-018 §5), and a consumer ignores the members
 *   it does not know. QAuth itself emits only declared members.
 * - An open enum (`extensibleEnum`) is published as `x-extensible-enum`, not
 *   `enum`: a minor release may add a value, and a consumer accepts one it
 *   does not know. A plain `enum` is closed.
 */

/** Where the schemas are published: the docs site serves `public/` at its root. */
export const SCHEMA_BASE_URL = 'https://docs.qauth.dev/schemas/events/';

/** The file name of the envelope's schema. */
export const ENVELOPE_SCHEMA_FILE = 'envelope.json';

/** The file name of one type's schema: `<name>.v<N>.json`, or `<name>.v<N>-rc.<M>.json`. */
export function eventSchemaFile(
  definition: Pick<EventTypeDefinition, 'name' | 'version' | 'rc'>
): string {
  return `${definition.name}.${eventVersionLabel(definition)}.json`;
}

type JsonObject = Record<string, unknown>;

const isObject = (value: unknown): value is JsonObject =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/** Zod's output, made into the published form; see the module comment. */
function publish(schema: z.ZodType): JsonObject {
  const json = z.toJSONSchema(schema, {
    target: 'draft-2020-12',
    unrepresentable: 'throw',
    override: ({ jsonSchema }) => {
      const node = jsonSchema as JsonObject;
      if (node[EXTENSIBLE_ENUM_META] === true) {
        delete node[EXTENSIBLE_ENUM_META];
        node['x-extensible-enum'] = node['enum'];
        delete node['enum'];
      }
      if (node['additionalProperties'] === false) delete node['additionalProperties'];
    },
  }) as JsonObject;
  return json;
}

/** Put `$schema`, `$id`, `title` and `description` first, so each file reads top-down. */
function withHeader(json: JsonObject, file: string, title: string): JsonObject {
  const { $schema, description, ...rest } = json;
  return {
    $schema,
    $id: `${SCHEMA_BASE_URL}${file}`,
    title,
    ...(description === undefined ? {} : { description }),
    ...rest,
  };
}

/** The JSON Schema of an event of any type. */
export function envelopeJsonSchema(): JsonObject {
  return withHeader(publish(envelopeSchema), ENVELOPE_SCHEMA_FILE, 'QAuth event');
}

/** The JSON Schema of one type's whole event: the envelope with that type's `data`. */
export function eventJsonSchema(definition: EventTypeDefinition): JsonObject {
  return withHeader(
    publish(eventSchemaFor(definition)),
    eventSchemaFile(definition),
    definition.type
  );
}

/** The JSON Schema of one type's `data` alone, as the docs page and the payload rules read it. */
export function dataJsonSchema(definition: EventTypeDefinition): JsonObject {
  const data = eventJsonSchema(definition)['properties'];
  if (!isObject(data) || !isObject(data['data'])) {
    throw new Error(`${definition.type}: the generated schema has no data member`);
  }
  return data['data'];
}
