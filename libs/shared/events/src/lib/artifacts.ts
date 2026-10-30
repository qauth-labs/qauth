import type { EventTypeDefinition } from './definition';
import { renderEventsPage } from './docs-page';
import {
  ENVELOPE_SCHEMA_FILE,
  envelopeJsonSchema,
  eventJsonSchema,
  eventSchemaFile,
} from './json-schema';
import { EVENT_TYPES } from './registry';
import { renderSsfEventsPage } from './ssf-docs-page';

/**
 * Every file the event contract publishes, with its content, keyed by its
 * path from the repository root. The export script writes them; the tests
 * compare them with the committed files. Pure, so both see the same bytes.
 */

/** The directory the JSON Schema files are published from (the docs site's `public/`). */
export const SCHEMA_DIR = 'apps/docs-site/public/schemas/events';

/** The generated docs page. */
export const EVENTS_PAGE_PATH = 'apps/docs-site/src/content/docs/reference/events.md';

/** The generated page of the SSF mapping (#540). */
export const SSF_EVENTS_PAGE_PATH = 'apps/docs-site/src/content/docs/reference/ssf-events.md';

/** The generated docs pages, which the export script formats with Oxfmt. */
export const GENERATED_PAGE_PATHS: readonly string[] = Object.freeze([
  EVENTS_PAGE_PATH,
  SSF_EVENTS_PAGE_PATH,
]);

/** The command that writes the artifacts; the stable-surface registry names it. */
export const EXPORT_COMMAND = 'pnpm exec nx run shared-events:schema-export --skip-nx-cache';

export interface Artifact {
  /** The path from the repository root. */
  readonly path: string;
  readonly content: string;
}

const json = (value: unknown) => `${JSON.stringify(value, null, 2)}\n`;

/** The schema files: the envelope's first, then one per type, in registry order. */
export function schemaArtifacts(
  definitions: readonly EventTypeDefinition[] = EVENT_TYPES
): Artifact[] {
  return [
    { path: `${SCHEMA_DIR}/${ENVELOPE_SCHEMA_FILE}`, content: json(envelopeJsonSchema()) },
    ...definitions.map((definition) => ({
      path: `${SCHEMA_DIR}/${eventSchemaFile(definition)}`,
      content: json(eventJsonSchema(definition)),
    })),
  ];
}

/** Every generated file: the schemas and the docs pages. */
export function eventArtifacts(
  definitions: readonly EventTypeDefinition[] = EVENT_TYPES
): Artifact[] {
  return [
    ...schemaArtifacts(definitions),
    { path: EVENTS_PAGE_PATH, content: renderEventsPage(definitions) },
    { path: SSF_EVENTS_PAGE_PATH, content: renderSsfEventsPage(definitions) },
  ];
}
