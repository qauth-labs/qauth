/**
 * Write the Interaction API contract's published files (#590): the bundled
 * OpenAPI document, one JSON Schema per step, and the docs page. Run through
 * `pnpm exec nx run shared-interaction-contract:contract-export`; the
 * stable-surface check runs it too and fails when a committed file differs.
 *
 * A step schema whose step left the contract is deleted, so the directory holds
 * exactly what the contract publishes. The page then goes through Oxfmt, like
 * the events page, so the formatter never rewrites it; the JSON files stay
 * plain `JSON.stringify` output, which `.oxfmtrc.json` leaves alone. This
 * script is the library's only I/O, and nothing imports it.
 */
import { execFileSync } from 'node:child_process';
import { mkdirSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

import { contractArtifacts, INTERACTION_PAGE_PATH, STEP_SCHEMA_DIR } from '../lib/artifacts';

const repoRoot = resolve(__dirname, '..', '..', '..', '..', '..');
const artifacts = contractArtifacts();

mkdirSync(join(repoRoot, STEP_SCHEMA_DIR), { recursive: true });
const published = new Set(artifacts.map((artifact) => artifact.path));
for (const name of readdirSync(join(repoRoot, STEP_SCHEMA_DIR))) {
  const path = `${STEP_SCHEMA_DIR}/${name}`;
  if (name.endsWith('.json') && !published.has(path)) rmSync(join(repoRoot, path));
}

for (const artifact of artifacts) {
  mkdirSync(dirname(join(repoRoot, artifact.path)), { recursive: true });
  writeFileSync(join(repoRoot, artifact.path), artifact.content);
}
execFileSync('pnpm', ['exec', 'oxfmt', INTERACTION_PAGE_PATH], {
  cwd: repoRoot,
  stdio: 'inherit',
});
console.log(`shared-interaction-contract: wrote ${artifacts.length} files`);
