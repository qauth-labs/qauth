import { renderAccountPage } from './docs-page';
import { ACCOUNT_API_VERSION } from './identifiers';
import { buildAccountOpenApi } from './openapi';

/**
 * Every file the account API contract publishes, with its content, keyed by
 * its path from the repository root. The export script writes them; the tests
 * compare them with the committed files. Pure, so both see the same bytes.
 */

/** The directory the contract is published from (the docs site's `public/`). */
export const CONTRACT_DIR = `apps/docs-site/public/account/${ACCOUNT_API_VERSION}`;

/** The published OpenAPI document. The stable-surface registry and the typed client read it. */
export const OPENAPI_PATH = `${CONTRACT_DIR}/openapi.json`;

/** The generated docs page. */
export const ACCOUNT_PAGE_PATH = 'apps/docs-site/src/content/docs/reference/account-api.md';

/** The command that writes the artifacts; the stable-surface registry names it. */
export const EXPORT_COMMAND =
  'pnpm exec nx run shared-account-contract:contract-export --skip-nx-cache';

export interface Artifact {
  /** The path from the repository root. */
  readonly path: string;
  readonly content: string;
}

const json = (value: unknown) => `${JSON.stringify(value, null, 2)}\n`;

/** The JSON files: the document. */
export function contractFiles(): Artifact[] {
  return [{ path: OPENAPI_PATH, content: json(buildAccountOpenApi()) }];
}

/** Every generated file: the document and the docs page (before Oxfmt). */
export function contractArtifacts(): Artifact[] {
  return [...contractFiles(), { path: ACCOUNT_PAGE_PATH, content: renderAccountPage() }];
}
