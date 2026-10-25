#!/usr/bin/env node
/**
 * The release notes of a QAuth version, for the draft release the
 * `release-npm` workflow leaves (#596):
 *
 *   node scripts/sdk-release/notes.mjs X.Y.Z[-rc.N]
 *
 * Prints that version's CHANGELOG.md section, or for a release candidate the
 * `## [Unreleased]` section it ships.
 */
import { readFileSync } from 'node:fs';

import { releaseNotes, SdkReleaseError } from './lib.mjs';

const [version] = process.argv.slice(2);
if (!version) {
  console.error('usage: notes.mjs X.Y.Z[-rc.N]');
  process.exit(2);
}
try {
  console.log(releaseNotes(readFileSync('CHANGELOG.md', 'utf8'), version));
} catch (error) {
  if (!(error instanceof SdkReleaseError)) throw error;
  console.error(error.message);
  process.exit(1);
}
