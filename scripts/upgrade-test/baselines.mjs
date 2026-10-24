#!/usr/bin/env node
/**
 * upgrade-test baselines — the matrix of the `upgrade-test` CI job (#475,
 * ADR-018 §5).
 *
 * Reads `upgrade-baselines.json`, checks that every baseline is a tag of this
 * checkout, and decides whether a failing rolling-upgrade leg fails the job.
 * The rules live in `lib.mjs` and are unit-tested there; this file is the glue
 * to git and to the step outputs.
 *
 * Prints two `key=value` lines, and appends them to the file `--output` names
 * (the CI step's output file):
 *
 *   baselines=["v0.1.3", ...]   the matrix, as JSON
 *   rolling=report|block             what a failing rolling leg does
 *
 * Exit codes:
 *   0  the outputs were written
 *   2  the file is invalid, names a tag the checkout does not have, or the
 *      arguments are wrong
 *
 * Usage:
 *   node scripts/upgrade-test/baselines.mjs [--output <file>]
 */

import { spawnSync } from 'node:child_process';
import { appendFileSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  assertBaselinesAreTags,
  BASELINES_PATH,
  BaselinesError,
  parseBaselines,
  rollingLegBlocks,
} from './lib.mjs';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');

function gitTags() {
  const result = spawnSync('git', ['tag', '--list'], { cwd: REPO_ROOT, encoding: 'utf8' });
  if (result.status !== 0) {
    throw new BaselinesError(`git tag --list failed: ${result.stderr.trim()}`);
  }
  return result.stdout.split('\n').filter((line) => line !== '');
}

function outputPath(args) {
  if (args.length === 0) return null;
  if (args.length === 2 && args[0] === '--output' && args[1] !== '') return args[1];
  throw new BaselinesError('Usage: node scripts/upgrade-test/baselines.mjs [--output <file>]');
}

try {
  const output = outputPath(process.argv.slice(2));
  const baselines = parseBaselines(readFileSync(join(REPO_ROOT, BASELINES_PATH), 'utf8'));
  const tags = gitTags();
  assertBaselinesAreTags(baselines, tags);
  const lines = [
    `baselines=${JSON.stringify(baselines)}`,
    `rolling=${rollingLegBlocks(tags) ? 'block' : 'report'}`,
  ];
  for (const line of lines) console.log(line);
  if (output) appendFileSync(output, `${lines.join('\n')}\n`);
} catch (error) {
  if (!(error instanceof BaselinesError)) throw error;
  console.error(`::error file=${BASELINES_PATH}::${error.message}`);
  process.exit(2);
}
