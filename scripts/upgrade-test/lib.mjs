/**
 * The upgrade test (#475, ADR-018 §5): the rules behind the CI job's setup
 * step, without the process glue. `baselines.mjs` is the CLI that wires them to
 * git and to the step outputs; this module takes the tag list as an argument so
 * the tests can drive every branch offline.
 *
 * `upgrade-baselines.json` at the repository root lists the release tags the
 * job upgrades from. Each one becomes one matrix entry of the `upgrade-test`
 * job, so adding a baseline needs no other change.
 *
 * Zero runtime dependencies — Node's standard library and the release-tag
 * rules of the stable-surface guard only.
 */

import { compareReleases, parseReleaseTag } from '../stable-surface/lib.mjs';

export const BASELINES_PATH = 'upgrade-baselines.json';

/**
 * The release from which a failing rolling-upgrade leg fails the job: the 1.0
 * release candidate. Before it, in 0.x, the leg reports its failure and the job
 * stays green (#475).
 */
export const ROLLING_LEG_BLOCKS_FROM = 'v1.0.0-rc.0';

/** A problem with `upgrade-baselines.json` or the tags it names. */
export class BaselinesError extends Error {
  constructor(message) {
    super(message);
    this.name = 'BaselinesError';
  }
}

const isObject = (value) => typeof value === 'object' && value !== null && !Array.isArray(value);

/** The keys the file may carry. `$comment` documents it, since JSON has no comments. */
const KEYS = new Set(['$comment', 'baselines']);

/**
 * Read `upgrade-baselines.json`.
 *
 * The file is an object whose `baselines` is a non-empty list of release tags
 * (`vMAJOR.MINOR.PATCH`, optionally with a pre-release such as `-rc.2`), each
 * listed once. Anything else is refused, so a typo cannot drop a baseline
 * from the matrix silently.
 *
 * @param {string} text the file's contents
 * @returns {string[]} the baselines, in the order the file lists them
 * @throws {BaselinesError} when the file is not of that shape
 */
export function parseBaselines(text) {
  let document;
  try {
    document = JSON.parse(text);
  } catch (error) {
    throw new BaselinesError(`${BASELINES_PATH} is not valid JSON: ${error.message}`);
  }
  if (!isObject(document)) {
    throw new BaselinesError(`${BASELINES_PATH} must be a JSON object with a "baselines" list.`);
  }
  const unknown = Object.keys(document).filter((key) => !KEYS.has(key));
  if (unknown.length > 0) {
    throw new BaselinesError(`${BASELINES_PATH} has unknown keys: ${unknown.join(', ')}.`);
  }
  const { baselines } = document;
  if (!Array.isArray(baselines) || baselines.length === 0) {
    throw new BaselinesError(`${BASELINES_PATH}: "baselines" must list at least one release tag.`);
  }
  const seen = new Set();
  for (const tag of baselines) {
    if (typeof tag !== 'string' || parseReleaseTag(tag) === null) {
      throw new BaselinesError(
        `${BASELINES_PATH}: ${JSON.stringify(tag)} is not a release tag such as v0.1.0 or v1.2.0-rc.1.`
      );
    }
    if (seen.has(tag)) {
      throw new BaselinesError(`${BASELINES_PATH}: ${tag} is listed twice.`);
    }
    seen.add(tag);
  }
  return [...baselines];
}

/**
 * Refuse a baseline that is not a tag of the repository: the job builds each
 * baseline from its tag, so a missing one would fail later and less clearly.
 *
 * @param {string[]} baselines from {@link parseBaselines}
 * @param {string[]} tags every tag the checkout has
 * @throws {BaselinesError} naming each baseline that is not a tag
 */
export function assertBaselinesAreTags(baselines, tags) {
  const known = new Set(tags);
  const missing = baselines.filter((tag) => !known.has(tag));
  if (missing.length > 0) {
    throw new BaselinesError(
      `${BASELINES_PATH} names tags this checkout does not have: ${missing.join(', ')}. ` +
        'Fetch the tags (actions/checkout with fetch-depth: 0) or correct the file.'
    );
  }
}

/**
 * Whether a failing rolling-upgrade leg fails the job.
 *
 * It does once the repository has a release at or after
 * {@link ROLLING_LEG_BLOCKS_FROM}. The rule reads the tags rather than a
 * setting, so the leg starts to block with the release candidate without
 * anyone having to remember to switch it.
 *
 * @param {string[]} tags every tag the checkout has
 */
export function rollingLegBlocks(tags) {
  const from = parseReleaseTag(ROLLING_LEG_BLOCKS_FROM);
  return tags.some((tag) => {
    const release = parseReleaseTag(tag);
    return release !== null && compareReleases(release, from) >= 0;
  });
}
