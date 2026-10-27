import { renderInteractionPage } from './docs-page';
import { INTERACTION_API_VERSION } from './identifiers';
import { buildInteractionOpenApi } from './openapi';
import { stepJsonSchema, stepSchemaFile } from './step-schema';
import { STEPS } from './steps';

/**
 * Every file the Interaction API contract publishes, with its content, keyed
 * by its path from the repository root. The export script writes them; the
 * tests compare them with the committed files. Pure, so both see the same
 * bytes.
 */

/** The directory the contract is published from (the docs site's `public/`). */
export const CONTRACT_DIR = `apps/docs-site/public/interaction/${INTERACTION_API_VERSION}`;

/** The published OpenAPI document. The stable-surface registry and the typed client read it. */
export const OPENAPI_PATH = `${CONTRACT_DIR}/openapi.json`;

/** The directory of the step schemas. */
export const STEP_SCHEMA_DIR = `${CONTRACT_DIR}/steps`;

/** The generated docs page. */
export const INTERACTION_PAGE_PATH = 'apps/docs-site/src/content/docs/reference/interaction-api.md';

/** The command that writes the artifacts; the stable-surface registry names it. */
export const EXPORT_COMMAND =
  'pnpm exec nx run shared-interaction-contract:contract-export --skip-nx-cache';

export interface Artifact {
  /** The path from the repository root. */
  readonly path: string;
  readonly content: string;
}

const json = (value: unknown) => `${JSON.stringify(value, null, 2)}\n`;

/** The JSON files: the document first, then one schema per step, in step order. */
export function contractFiles(): Artifact[] {
  return [
    { path: OPENAPI_PATH, content: json(buildInteractionOpenApi()) },
    ...STEPS.map((step) => ({
      path: `${CONTRACT_DIR}/${stepSchemaFile(step)}`,
      content: json(stepJsonSchema(step)),
    })),
  ];
}

/** Every generated file: the JSON files and the docs page (before Oxfmt). */
export function contractArtifacts(): Artifact[] {
  return [
    ...contractFiles(),
    { path: INTERACTION_PAGE_PATH, content: renderInteractionPage(buildInteractionOpenApi()) },
  ];
}
