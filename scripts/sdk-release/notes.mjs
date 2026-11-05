#!/usr/bin/env node
/**
 * The two files the draft release of a QAuth version is made from, for the
 * `release-npm` workflow (#596, #1012):
 *
 *   node scripts/sdk-release/notes.mjs X.Y.Z[-rc.N] <repository URL> <out dir>
 *
 * Writes into `<out dir>`:
 *
 * - `release-body.md`: the release body. It stays short, whatever the
 *   CHANGELOG's size, and links the notes in CHANGELOG.md at the tag.
 * - `release-notes-<version>.md`: that version's CHANGELOG.md section, or for a
 *   release candidate the `## [Unreleased]` section it ships, in full. The
 *   release attaches it beside the SDK tarballs.
 *
 * `<repository URL>` is the repository's web address,
 * `https://<host>/<owner>/<name>`.
 */
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { releaseFiles, SdkReleaseError } from './lib.mjs';

const [version, repositoryUrl, outDir] = process.argv.slice(2);
if (!version || !repositoryUrl || !outDir) {
  console.error('usage: notes.mjs X.Y.Z[-rc.N] <repository URL> <out dir>');
  process.exit(2);
}
try {
  const files = releaseFiles(readFileSync('CHANGELOG.md', 'utf8'), version, repositoryUrl);
  mkdirSync(outDir, { recursive: true });
  for (const { name, text } of files) {
    const path = join(outDir, name);
    writeFileSync(path, text);
    console.log(`${path}: ${text.length} characters`);
  }
} catch (error) {
  if (!(error instanceof SdkReleaseError)) throw error;
  console.error(error.message);
  process.exit(1);
}
