/**
 * Guard for the upgrade test's matrix (#475): the shape of
 * `upgrade-baselines.json`, the check that each baseline is a tag, and the
 * rule that makes the rolling-upgrade leg blocking from the 1.0 release
 * candidate. The committed file is read too, so a malformed edit fails here,
 * in the unit suite, before the CI job ever starts.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  assertBaselinesAreTags,
  BASELINES_PATH,
  BaselinesError,
  parseBaselines,
  rollingLegBlocks,
} from './lib.mjs';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

describe('parseBaselines', () => {
  it('returns the listed tags in order', () => {
    expect(parseBaselines('{"baselines": ["v0.1.0-rc.2", "v0.1.3"]}')).toEqual([
      'v0.1.0-rc.2',
      'v0.1.3',
    ]);
  });

  it('accepts a $comment beside the list', () => {
    expect(parseBaselines('{"$comment": "why", "baselines": ["v1.2.0"]}')).toEqual(['v1.2.0']);
  });

  it.each([
    ['not JSON', '{baselines:', /not valid JSON/],
    ['a bare list', '["v0.1.0"]', /must be a JSON object/],
    ['no list', '{}', /at least one release tag/],
    ['an empty list', '{"baselines": []}', /at least one release tag/],
    ['an unknown key', '{"baselines": ["v0.1.0"], "rolling": "block"}', /unknown keys: rolling/],
    ['a tag without the v', '{"baselines": ["0.1.0"]}', /"0\.1\.0" is not a release tag/],
    ['a branch name', '{"baselines": ["main"]}', /"main" is not a release tag/],
    ['a number', '{"baselines": [1]}', /1 is not a release tag/],
    ['a duplicate', '{"baselines": ["v0.1.0", "v0.1.0"]}', /v0\.1\.0 is listed twice/],
  ])('refuses %s', (_name, text, message) => {
    expect(() => parseBaselines(text)).toThrow(BaselinesError);
    expect(() => parseBaselines(text)).toThrow(message);
  });

  it('reads the committed file', () => {
    const baselines = parseBaselines(readFileSync(join(REPO_ROOT, BASELINES_PATH), 'utf8'));
    expect(baselines.length).toBeGreaterThan(0);
  });
});

describe('assertBaselinesAreTags', () => {
  it('passes when every baseline is a tag', () => {
    expect(() =>
      assertBaselinesAreTags(['v0.1.0-rc.2'], ['v0.1.0-rc.1', 'v0.1.0-rc.2', 'v0.1.0'])
    ).not.toThrow();
  });

  it('names every baseline that is not a tag', () => {
    expect(() =>
      assertBaselinesAreTags(['v0.1.0-rc.2', 'v0.9.0', 'v0.9.1'], ['v0.1.0-rc.2'])
    ).toThrow(/does not have: v0\.9\.0, v0\.9\.1/);
  });
});

describe('rollingLegBlocks', () => {
  it('reports only while every release is 0.x or a pre-release before the 1.0 candidate', () => {
    expect(rollingLegBlocks([])).toBe(false);
    expect(rollingLegBlocks(['v0.1.0-rc.2', 'v0.1.3', 'v0.9.0'])).toBe(false);
    expect(rollingLegBlocks(['v0.9.0', 'v1.0.0-beta.4'])).toBe(false);
  });

  it('blocks from the 1.0 release candidate on', () => {
    expect(rollingLegBlocks(['v0.9.0', 'v1.0.0-rc.0'])).toBe(true);
    expect(rollingLegBlocks(['v1.0.0'])).toBe(true);
    expect(rollingLegBlocks(['v1.3.2'])).toBe(true);
    expect(rollingLegBlocks(['v2.0.0-rc.1'])).toBe(true);
  });

  it('ignores tags that are not releases', () => {
    expect(rollingLegBlocks(['release-1.0', 'v1', 'latest'])).toBe(false);
  });
});
