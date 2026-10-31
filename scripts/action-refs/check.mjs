#!/usr/bin/env node
/**
 * action-refs — every `uses:` in the workflows names a major tag or a full
 * commit SHA, never a branch or `latest` (#796). The rules live in `lib.mjs`
 * and are unit-tested there; this file reads the workflow directory and
 * reports.
 *
 * It reads every `.yml` and `.yaml` file of the directory it is given (not
 * its subdirectories, which hold no workflow) and prints one error
 * annotation per refused reference, with its file and line, so CI marks the
 * line in the pull request. The `actionlint` job of the CI workflow passes it
 * the repository's workflow directory.
 *
 * Exit codes:
 *   0  every reference is pinned
 *   1  a reference is refused
 *   2  the arguments are wrong, or the directory cannot be read or holds no
 *      workflow file
 *
 * Usage:
 *   node scripts/action-refs/check.mjs <directory>
 */

import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

import { workflowReferences } from './lib.mjs';

const EXIT_OK = 0;
const EXIT_REFUSED = 1;
const EXIT_INPUT = 2;

const USAGE = 'usage: node scripts/action-refs/check.mjs <directory>';

const isWorkflowFile = (name) => /\.ya?ml$/.test(name);

function main(args) {
  if (args.length !== 1 || args[0].startsWith('-')) {
    console.error(`action-refs: ${USAGE}`);
    return EXIT_INPUT;
  }
  const directory = resolve(args[0]);

  let files;
  try {
    files = readdirSync(directory).filter(isWorkflowFile).sort();
  } catch (error) {
    console.error(`action-refs: cannot read ${directory}: ${error.message}`);
    return EXIT_INPUT;
  }
  if (files.length === 0) {
    console.error(`action-refs: ${directory} holds no workflow file`);
    return EXIT_INPUT;
  }

  let count = 0;
  let refused = 0;
  for (const name of files) {
    const path = join(directory, name);
    const shown = relative(process.cwd(), path);
    for (const { line, uses, problem } of workflowReferences(readFileSync(path, 'utf8'))) {
      count += 1;
      if (problem === null) continue;
      refused += 1;
      console.error(`::error file=${shown},line=${line}::uses: ${uses} ${problem}`);
    }
  }

  if (refused > 0) {
    console.error(`action-refs: ${refused} of ${count} references refused`);
    return EXIT_REFUSED;
  }
  console.log(`action-refs: ${count} references in ${files.length} workflow files, all pinned`);
  return EXIT_OK;
}

process.exitCode = main(process.argv.slice(2));
