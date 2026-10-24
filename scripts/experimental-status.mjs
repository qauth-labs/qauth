#!/usr/bin/env node
/**
 * experimental-status — tell the maintainer which experimental items may
 * become stable (#476, ADR-018 §5).
 *
 * It prints, for every item of the experimental-feature registry
 * (`libs/shared/stability`), whether it is built and stable, its switch, the
 * spec it implements, and the four promotion conditions with their evidence.
 * The last line names the items that may become stable: built, not stable
 * yet, and every condition has evidence.
 *
 * With `--check-stable` it fails when an item marked `stable: true` has a
 * condition with no evidence, or evidence that names a file or a section that
 * does not exist, or when the registry breaks any other of its rules, such as
 * an ADR link to a missing file. A path must name a file, not a directory,
 * and a `#section` must be a heading anchor of a Markdown file.
 *
 * The registry is TypeScript. Node strips its types itself; the two hooks
 * below only tell it that the library's `.ts` files are ES modules and add
 * the `.ts` its extensionless relative imports leave out. So the script
 * imports the same registry and the same checks the library's tests run,
 * with no copy to drift and no script runner in the root devDependencies.
 *
 * Exit codes:
 *   0  printed; with --check-stable, nothing failed
 *   1  --check-stable failed
 *   2  input error: an unknown argument, or a registry that cannot be read
 *      or does not have the registry's shape
 *
 * Usage:
 *   node scripts/experimental-status.mjs
 *   node scripts/experimental-status.mjs --check-stable
 *   node scripts/experimental-status.mjs --registry proposed.json --check-stable
 *
 * `--registry` reads the items from a JSON array instead of the registry, to
 * check a proposed change before it is written into `items.ts`. Evidence
 * paths are still read from this repository.
 */

import { readFileSync, statSync } from 'node:fs';
import { registerHooks } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const LIBRARY_SOURCE = join(REPO_ROOT, 'libs', 'shared', 'stability', 'src');
const LIBRARY_URL = `${pathToFileURL(LIBRARY_SOURCE).href}/`;

const EXIT_OK = 0;
const EXIT_FAILED = 1;
const EXIT_INPUT = 2;

const USAGE =
  'usage: node scripts/experimental-status.mjs [--check-stable] [--registry <file.json>]';

registerHooks({
  resolve(specifier, context, nextResolve) {
    const fromLibrary = context.parentURL?.startsWith(LIBRARY_URL) === true;
    if (fromLibrary && /^\.\.?\//.test(specifier) && !/\.[cm]?[jt]s$/.test(specifier)) {
      return nextResolve(`${specifier}.ts`, context);
    }
    return nextResolve(specifier, context);
  },
  load(url, context, nextLoad) {
    if (url.startsWith(LIBRARY_URL) && url.endsWith('.ts')) {
      return nextLoad(url, { ...context, format: 'module-typescript' });
    }
    return nextLoad(url, context);
  },
});

/** Parse the arguments, or return the line that says what is wrong with them. */
function parseArguments(argv) {
  const options = { checkStable: false, registry: undefined, help: false };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--check-stable') {
      options.checkStable = true;
    } else if (argument === '--help' || argument === '-h') {
      options.help = true;
    } else if (argument === '--registry') {
      const value = argv[index + 1];
      if (value === undefined || value.startsWith('--')) return '--registry needs a file';
      options.registry = value;
      index += 1;
    } else {
      return `unknown argument ${argument}`;
    }
  }
  return options;
}

/** The items: the registry, or the JSON array `--registry` names. */
function readItems(path, registry) {
  if (path === undefined) return registry;
  const items = JSON.parse(readFileSync(resolve(path), 'utf8'));
  if (!Array.isArray(items)) throw new Error(`${path} does not hold a JSON array of items`);
  return items;
}

async function main(argv) {
  const options = parseArguments(argv);
  if (typeof options === 'string') {
    process.stderr.write(`experimental-status: ${options}\n${USAGE}\n`);
    return EXIT_INPUT;
  }
  if (options.help) {
    process.stdout.write(`${USAGE}\n`);
    return EXIT_OK;
  }

  let stability;
  let items;
  try {
    stability = await import(pathToFileURL(join(LIBRARY_SOURCE, 'index.ts')).href);
    items = readItems(options.registry, stability.EXPERIMENTAL_ITEMS);
  } catch (error) {
    process.stderr.write(`experimental-status: cannot read the registry: ${error.message}\n`);
    return EXIT_INPUT;
  }

  // A proposed registry is JSON, so check its shape before reading it as items.
  const shape = stability.registryShapeProblems(items);
  if (shape.length > 0) {
    for (const problem of shape) process.stderr.write(`experimental-status: ${problem}\n`);
    process.stderr.write('experimental-status: the registry does not have the shape of one\n');
    return EXIT_INPUT;
  }

  const pathExists = stability.repositoryPathCheck({
    isFile(path) {
      try {
        return statSync(join(REPO_ROOT, path)).isFile();
      } catch {
        return false;
      }
    },
    readText: (path) => readFileSync(join(REPO_ROOT, path), 'utf8'),
  });
  process.stdout.write(stability.renderPromotionStatus(items, pathExists));

  if (!options.checkStable) return EXIT_OK;

  const failures = stability.stableCheckFailures(items, pathExists);
  if (failures.length > 0) {
    for (const failure of failures) process.stderr.write(`experimental-status: ${failure}\n`);
    process.stderr.write(
      `experimental-status: --check-stable failed with ${failures.length} problem(s)\n`
    );
    return EXIT_FAILED;
  }
  process.stdout.write(
    '\n--check-stable: every stable item has evidence for all four conditions.\n'
  );
  return EXIT_OK;
}

process.exitCode = await main(process.argv.slice(2));
