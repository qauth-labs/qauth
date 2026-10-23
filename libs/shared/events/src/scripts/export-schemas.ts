/**
 * Write the event contract's generated files (#456): the JSON Schema of the
 * envelope and of every registered type, and the docs page that lists them.
 * Run through `pnpm exec nx run shared-events:schema-export`; the
 * stable-surface check runs it too and fails when a committed schema differs.
 *
 * A schema file whose type left the registry is deleted, so the directory
 * holds exactly what the registry publishes. The page then goes through
 * Prettier, like the configuration page, so the pre-commit hook never
 * rewrites it; the schema files stay plain `JSON.stringify` output, which
 * `.prettierignore` leaves alone, like `openapi.json`. This script is the
 * library's only I/O, and nothing imports it.
 */
import { execFileSync } from 'node:child_process';
import { mkdirSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

import { eventArtifacts, EVENTS_PAGE_PATH, SCHEMA_DIR } from '../lib/artifacts';

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
execFileSync('pnpm', ['exec', 'prettier', '--write', '--log-level', 'warn', EVENTS_PAGE_PATH], {
  cwd: repoRoot,
  stdio: 'inherit',
});
console.log(`shared-events: wrote ${artifacts.length} files`);
