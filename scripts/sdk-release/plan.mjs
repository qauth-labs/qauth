#!/usr/bin/env node
/**
 * What the `release-npm` workflow packs, at which version, and whether it
 * publishes (#596):
 *
 *   node scripts/sdk-release/plan.mjs tag vX.Y.Z[-rc.N]   # QAuth's release tag
 *   node scripts/sdk-release/plan.mjs dry-run             # a pull request
 *
 * Prints one JSON line: `{ "publish": bool, "version", "distTag", "packages":
 * [{ project, version, distTag }] }`. Every SDK in `libs/sdk/` is packed at the
 * same version: the tag's, or for a dry run the newest version in
 * CHANGELOG.md, so the dry run stamps a real version just as a release does. A
 * stable tag needs its `## [X.Y.Z]` section in CHANGELOG.md, as the image
 * release does; a release candidate has none.
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  distTagFor,
  hasReleaseSection,
  latestReleasedVersion,
  parseReleaseTag,
  SdkReleaseError,
} from './lib.mjs';

const SDK_ROOT = 'libs/sdk';
const projects = readdirSync(SDK_ROOT, { withFileTypes: true })
  .filter((entry) => entry.isDirectory() && existsSync(join(SDK_ROOT, entry.name, 'package.json')))
  .map((entry) => entry.name)
  .sort();
const changelog = readFileSync('CHANGELOG.md', 'utf8');

const [mode, tag] = process.argv.slice(2);
try {
  let version;
  let publish;
  if (mode === 'tag') {
    version = parseReleaseTag(tag ?? '');
    if (!version.includes('-rc.') && !hasReleaseSection(changelog, version)) {
      throw new SdkReleaseError(`${tag}: CHANGELOG.md has no '## [${version}]' section`);
    }
    publish = true;
  } else if (mode === 'dry-run') {
    version = latestReleasedVersion(changelog);
    publish = false;
  } else {
    console.error('usage: plan.mjs tag vX.Y.Z[-rc.N] | plan.mjs dry-run');
    process.exit(2);
  }
  const distTag = distTagFor(version);
  if (projects.length === 0) throw new SdkReleaseError(`${SDK_ROOT} holds no SDK package`);
  const packages = projects.map((project) => ({ project, version, distTag }));
  console.log(JSON.stringify({ publish, version, distTag, packages }));
} catch (error) {
  if (!(error instanceof SdkReleaseError)) throw error;
  console.error(error.message);
  process.exit(1);
}
