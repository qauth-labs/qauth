/**
 * The files `openapi-export.ts` writes for each flag surface (#525), kept
 * apart from the exporter, which boots the app when it loads, so they have
 * unit tests. The exporter imports this module only after it has set its
 * environment: `openapi-options.ts`, which it reaches, reads QAUTH_VERSION
 * when it loads.
 */

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

import type { ApiFamily } from './app/api-conventions/families';
import {
  DOCUMENT_FAMILIES,
  familyDocument,
  type OpenApiDocument,
  serializeDocument,
} from './app/api-conventions/family-documents';
import type { FlagSurface } from './openapi-export-surface';

/**
 * Where one surface's export writes, relative to the repository root: the
 * server's whole document, and the directory of the family documents.
 *
 * - `default`: `stable-surface/openapi.json` and `docs/api-baseline/`, the
 *   documents a default deployment serves. They are the stable surfaces the
 *   stable-surface check compares with the last release.
 * - `maximal`: `apps/docs-site/public/`, the documents the docs site
 *   publishes, with every switch that registers a route on, the admin
 *   listener's among them.
 */
export const EXPORT_LOCATIONS: Readonly<
  Record<FlagSurface, { readonly combined: string; readonly familyDirectory: string }>
> = Object.freeze({
  default: { combined: 'stable-surface/openapi.json', familyDirectory: 'docs/api-baseline' },
  maximal: {
    combined: 'apps/docs-site/public/openapi.json',
    familyDirectory: 'apps/docs-site/public',
  },
});

/** The file name of a family's document, beside the server's own: `openapi-admin.json`. */
export function familyDocumentFileName(family: ApiFamily): string {
  return `openapi-${family}.json`;
}

/** What one export run read from the booted listeners. */
export interface ExportSources {
  /** The public listener's document. */
  readonly combined: OpenApiDocument;
  /**
   * The admin listener's document, or `null` when the surface runs no admin
   * listener (ADMIN_API_ENABLED off): the admin document then lists no
   * operation, as a deployment with the switch off serves none.
   */
  readonly admin: OpenApiDocument | null;
}

/**
 * Every file one surface's export writes, path to bytes, in a fixed order:
 * the whole document first, then each family's (`DOCUMENT_FAMILIES`). A pure
 * function of its sources, so the same boot writes the same bytes.
 */
export function exportFiles(surface: FlagSurface, sources: ExportSources): Map<string, string> {
  const { combined, familyDirectory } = EXPORT_LOCATIONS[surface];
  const files = new Map<string, string>([[combined, serializeDocument(sources.combined)]]);
  for (const family of DOCUMENT_FAMILIES) {
    const source =
      family === 'admin'
        ? (sources.admin ?? { openapi: sources.combined.openapi, paths: {} })
        : sources.combined;
    files.set(
      `${familyDirectory}/${familyDocumentFileName(family)}`,
      serializeDocument(familyDocument(source, family))
    );
  }
  return files;
}

/**
 * Write `files` under `root`, each only when its bytes differ from what is on
 * disk, and answer the paths written. A second run of the same export writes
 * nothing.
 */
export function writeExportFiles(root: string, files: ReadonlyMap<string, string>): string[] {
  const written: string[] = [];
  for (const [path, content] of files) {
    const target = join(root, path);
    let current: string | null = null;
    try {
      current = readFileSync(target, 'utf8');
    } catch {
      // Not written yet.
    }
    if (current === content) continue;
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, content);
    written.push(path);
  }
  return written;
}
