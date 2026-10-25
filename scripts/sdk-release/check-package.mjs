#!/usr/bin/env node
/**
 * Check a packed SDK tarball before it is staged on npm (#596):
 *
 *   node scripts/sdk-release/check-package.mjs <tarball> <projectRoot> <version>
 *
 * It fails (exit 1) on any file outside the allowed set (the manifest, README,
 * LICENSE and compiled `dist/`), on a private key, a source-map pointer or a
 * build-machine path inside a packed file, and on a manifest without the
 * metadata a published package needs. See lib.mjs for each rule.
 */
import { execFileSync } from 'node:child_process';

import { checkFileContent, checkFileList, checkManifest } from './lib.mjs';

const [tarball, projectRoot, version] = process.argv.slice(2);
if (!tarball || !projectRoot || !version) {
  console.error('usage: check-package.mjs <tarball> <projectRoot> <version>');
  process.exit(2);
}

const tar = (...args) =>
  execFileSync('tar', args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });

const files = tar('-tzf', tarball).split('\n').filter(Boolean);
const problems = checkFileList(files);

const manifest = JSON.parse(tar('-xzOf', tarball, 'package/package.json'));
problems.push(...checkManifest(manifest, { projectRoot, version }));

for (const file of files) {
  if (file.endsWith('/') || !file.startsWith('package/')) continue;
  problems.push(...checkFileContent(file, tar('-xzOf', tarball, file)));
}

console.log(`${tarball}: ${files.length} files`);
for (const file of files) console.log(`  ${file}`);
if (problems.length > 0) {
  console.error(`\n${problems.length} problem(s):`);
  for (const problem of problems) console.error(`  - ${problem}`);
  process.exit(1);
}
console.log('\nThe package passes every check.');
