import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { stepSchemaFile } from '@qauth-labs/shared-interaction-contract';
import { CONTRACT_DIR } from '@qauth-labs/shared-interaction-contract/src/lib/artifacts';

import type { StepName } from '../lib/steps';

/**
 * The step schema files the Interaction API contract publishes, for the
 * tests. Test-only: the library itself never reads a file.
 */

/** The repository root. */
export const REPO_ROOT = resolve(__dirname, '..', '..', '..', '..', '..');

/** The directory of the published step schemas, from the repository root. */
export const PUBLISHED_STEP_DIR = `${CONTRACT_DIR}/steps`;

/** Where the contract publishes step `name`'s schema, from the repository root. */
export function publishedStepSchemaPath(name: StepName): string {
  return `${CONTRACT_DIR}/${stepSchemaFile({ name })}`;
}

/** The published schema file of step `name`, parsed. */
export function readPublishedStepFile(name: StepName): unknown {
  return JSON.parse(readFileSync(join(REPO_ROOT, publishedStepSchemaPath(name)), 'utf8'));
}
