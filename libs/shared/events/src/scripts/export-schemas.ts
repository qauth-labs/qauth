/**
 * Write the event contract's generated files (#456): the JSON Schema of the
 * envelope and of every registered type, the docs page that lists them, and
 * the page of their Shared Signals mapping (#540).
 * Run through `pnpm exec nx run shared-events:schema-export`; the
 * stable-surface check runs it too and fails when a committed schema differs.
 *
 * A schema file whose type left the registry is deleted, so the directory
 * holds exactly what the registry publishes. The pages then go through
 * Oxfmt, like the configuration page, so the pre-commit hook never
 * rewrites it; the schema files stay plain `JSON.stringify` output, which
 * `.oxfmtrc.json` leaves alone, like `openapi.json`. This script is the
 * library's only I/O, and nothing imports it.
 */
import { execFileSync } from 'node:child_process';
import { mkdirSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

import { eventArtifacts, GENERATED_PAGE_PATHS, SCHEMA_DIR } from '../lib/artifacts';

const repoRoot = resolve(__dirname, '..', '..', '..', '..', '..');
const artifacts = eventArtifacts();

mkdirSync(join(repoRoot, SCHEMA_DIR), { recursive: true });
const published = new Set(artifacts.map((artifact) => artifact.path));
for (const name of readdirSync(join(repoRoot, SCHEMA_DIR))) {
  const path = `${SCHEMA_DIR}/${name}`;
  if (name.endsWith('.json') && !published.has(path)) rmSync(join(repoRoot, path));
}

for (const artifact of artifacts) {
  mkdirSync(dirname(join(repoRoot, artifact.path)), { recursive: true });
  writeFileSync(join(repoRoot, artifact.path), artifact.content);
}
execFileSync('pnpm', ['exec', 'oxfmt', ...GENERATED_PAGE_PATHS], {
  cwd: repoRoot,
  stdio: 'inherit',
});
console.log(`shared-events: wrote ${artifacts.length} files`);
