#!/usr/bin/env node
/**
 * What the `release-npm` workflow packs and whether it publishes (#596):
 *
 *   node scripts/sdk-release/plan.mjs tag <project>@<version>   # a release tag
 *   node scripts/sdk-release/plan.mjs all                       # every SDK, dry run
 *
 * Prints one JSON line: `{ "publish": bool, "packages": [{ project, version,
 * distTag }] }`. A tag names one SDK in `libs/sdk/`, and its version must be the
 * version in that SDK's package.json and have a section in its CHANGELOG.md.
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { distTagFor, parseReleaseTag, SdkReleaseError } from './lib.mjs';

const SDK_ROOT = 'libs/sdk';
const projects = readdirSync(SDK_ROOT, { withFileTypes: true })
  .filter((entry) => entry.isDirectory() && existsSync(join(SDK_ROOT, entry.name, 'package.json')))
  .map((entry) => entry.name)
  .sort();
const versionOf = (project) =>
  JSON.parse(readFileSync(join(SDK_ROOT, project, 'package.json'), 'utf8')).version;

const [mode, tag] = process.argv.slice(2);
try {
  if (mode === 'tag') {
    const { project, version } = parseReleaseTag(tag ?? '', projects);
    const manifestVersion = versionOf(project);
    if (manifestVersion !== version) {
      throw new SdkReleaseError(
        `${tag}: ${SDK_ROOT}/${project}/package.json says ${manifestVersion}; run nx release version first`
      );
    }
    const changelog = join(SDK_ROOT, project, 'CHANGELOG.md');
    const sections = existsSync(changelog) ? readFileSync(changelog, 'utf8') : '';
    // `## 0.1.0 (2026-10-26)` as nx release writes it, or `## [0.1.0]`. Plain
    // string comparison: the version never becomes part of a pattern.
    const isSection = (line) =>
      [`## ${version}`, `## [${version}]`].some(
        (heading) => line === heading || line.startsWith(`${heading} `)
      );
    if (!sections.split('\n').some(isSection)) {
      throw new SdkReleaseError(`${tag}: ${changelog} has no section for ${version}`);
    }
    const plan = { publish: true, packages: [{ project, version, distTag: distTagFor(version) }] };
    console.log(JSON.stringify(plan));
  } else if (mode === 'all') {
    const packages = projects.map((project) => ({
      project,
      version: versionOf(project),
      distTag: 'dry-run',
    }));
    console.log(JSON.stringify({ publish: false, packages }));
  } else {
    console.error('usage: plan.mjs tag <project>@<version> | plan.mjs all');
    process.exit(2);
  }
} catch (error) {
  if (!(error instanceof SdkReleaseError)) throw error;
  console.error(error.message);
  process.exit(1);
}
