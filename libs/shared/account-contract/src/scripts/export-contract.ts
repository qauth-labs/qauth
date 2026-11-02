/**
 * Write the account API contract's published files (#588): the OpenAPI
 * document and the docs page. Run through
 * `pnpm exec nx run shared-account-contract:contract-export`; the
 * stable-surface check runs it too and fails when a committed file differs.
 *
 * The page then goes through Oxfmt, like the events page, so the formatter
 * never rewrites it; the JSON file stays plain `JSON.stringify` output, which
 * `.oxfmtrc.json` leaves alone. This script is the library's only I/O, and
 * nothing imports it.
 */
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

import { ACCOUNT_PAGE_PATH, contractArtifacts } from '../lib/artifacts';

const repoRoot = resolve(__dirname, '..', '..', '..', '..', '..');
const artifacts = contractArtifacts();

for (const artifact of artifacts) {
  mkdirSync(dirname(join(repoRoot, artifact.path)), { recursive: true });
  writeFileSync(join(repoRoot, artifact.path), artifact.content);
}
execFileSync('pnpm', ['exec', 'oxfmt', ACCOUNT_PAGE_PATH], { cwd: repoRoot, stdio: 'inherit' });
console.log(`shared-account-contract: wrote ${artifacts.length} files`);
