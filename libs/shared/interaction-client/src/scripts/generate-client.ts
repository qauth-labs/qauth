/**
 * Write the typed Interaction API client from the published document (#590).
 * Run through `pnpm exec nx run shared-interaction-client:generate` after the
 * contract export. The output goes through Oxfmt, so the formatter never
 * rewrites it; the drift test formats the same way. This script is the
 * library's only I/O, and nothing imports it.
 */
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { CLIENT_PATH, DOCUMENT_PATH } from '../codegen/paths';
import { renderClient } from '../codegen/render-client';

const repoRoot = resolve(__dirname, '..', '..', '..', '..', '..');
const document = JSON.parse(readFileSync(join(repoRoot, DOCUMENT_PATH), 'utf8'));

writeFileSync(join(repoRoot, CLIENT_PATH), renderClient(document, DOCUMENT_PATH));
execFileSync('pnpm', ['exec', 'oxfmt', CLIENT_PATH], { cwd: repoRoot, stdio: 'inherit' });
console.log(`shared-interaction-client: wrote ${CLIENT_PATH}`);
