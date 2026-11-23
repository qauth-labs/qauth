/**
 * The status feed a release carries: `qauth-status.json`, every feature of
 * `apps/docs-site/src/lib/status.ts` by its stable id, with its state and
 * the flag that gates it. qauth.dev reads the feed of the latest release, so
 * the site says what that release holds without a hand-kept copy.
 *
 * `release-npm.yml` builds the feed on every pull request, as a dry run, and
 * attaches it to the draft release a tag starts. `site-rebuild.yml` asks the
 * site to rebuild once a release is published.
 *
 *   node scripts/site-status/export.mts <version> <out-file>
 *
 * The format id is `qauth-status/1-rc.0` until 1.0 (ADR-018 §5). A change a
 * reader cannot ignore raises the rc number; adding a field does not.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { FeatureState, FeatureStatus } from '../../apps/docs-site/src/lib/status.ts';
import { FEATURE_STATUS } from '../../apps/docs-site/src/lib/status.ts';

export const SITE_STATUS_FORMAT = 'qauth-status/1-rc.0';

const STATES: readonly FeatureState[] = ['shipped', 'partial', 'planned'];
const ID_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const VERSION_RE = /^\d+\.\d+\.\d+(?:-rc\.\d+)?$/;
/** A planned entry names its tracking issue after `Open:`, so the issue-state guard can see it close. */
const PLANNED_OPEN_RE = /\bOpen:[^]*?#\d+/;

export interface SiteStatusFeature {
  id: string;
  name: string;
  state: FeatureState;
  flag?: { name: string; default: 'on' | 'off' };
}

export interface SiteStatus {
  format: typeof SITE_STATUS_FORMAT;
  version: string;
  features: SiteStatusFeature[];
}

/** Every rule the feed's entries must meet; empty when the list is sound. */
export function siteStatusProblems(features: readonly FeatureStatus[]): string[] {
  const problems: string[] = [];
  const seen = new Set<string>();
  for (const feature of features) {
    const label = feature.id || feature.feature;
    if (!ID_RE.test(feature.id)) problems.push(`${label}: id is not kebab-case`);
    if (seen.has(feature.id)) problems.push(`${label}: id is used twice`);
    seen.add(feature.id);
    if (!STATES.includes(feature.state)) problems.push(`${label}: unknown state ${feature.state}`);
    if (feature.state === 'planned' && !PLANNED_OPEN_RE.test(feature.summary)) {
      problems.push(`${label}: a planned entry names its tracking issue after "Open:"`);
    }
  }
  return problems;
}

export function buildSiteStatus(version: string, features: readonly FeatureStatus[]): SiteStatus {
  if (!VERSION_RE.test(version)) {
    throw new Error(`version ${JSON.stringify(version)} is not X.Y.Z or X.Y.Z-rc.N`);
  }
  const problems = siteStatusProblems(features);
  if (problems.length > 0) {
    throw new Error(`the feature list is not a sound feed:\n- ${problems.join('\n- ')}`);
  }
  return {
    format: SITE_STATUS_FORMAT,
    version,
    features: features.map((feature) => ({
      id: feature.id,
      name: feature.feature,
      state: feature.state,
      ...(feature.flag ? { flag: { name: feature.flag.name, default: feature.flag.default } } : {}),
    })),
  };
}

function main(argv: string[]): void {
  const [version, outFile] = argv;
  if (!version || !outFile) {
    process.stderr.write('usage: node scripts/site-status/export.mts <version> <out-file>\n');
    process.exit(2);
  }
  const feed = buildSiteStatus(version, FEATURE_STATUS);
  const out = resolve(outFile);
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, `${JSON.stringify(feed, null, 2)}\n`);
  process.stdout.write(`${out}: ${feed.features.length} features at ${version}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2));
}
