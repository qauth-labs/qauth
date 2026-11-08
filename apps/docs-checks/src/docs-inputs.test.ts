import { readdirSync, readFileSync } from 'node:fs';
import { join, matchesGlob, relative } from 'node:path';

import { describe, expect, it } from 'vitest';

import { REPO_ROOT } from './workspace';

/**
 * A docs-only change touches no project but the docs site and this one
 * (#1044).
 *
 * Nx counts a project as touched by a changed file that an input of one of
 * its targets names as `{workspaceRoot}/…`, and with `affected.legacy`
 * (nx.json) a touched project marks every project that depends on it
 * affected, for every target. A docs page in a library's `test` inputs
 * therefore ran the auth server's integration suite on a pull request that
 * changed only docs. The checks that read the docs live here instead, and
 * nothing depends on this project.
 */

/** The directories that hold docs, and nothing a project builds from. */
const DOCS_DIRECTORIES = ['apps/docs-site/src/content/docs', 'docs'];
/** The docs files outside those directories. */
const DOCS_FILES = ['CHANGELOG.md'];

/** The projects a docs edit may touch: the one that renders the docs, and this one. */
const DOCS_OWNERS = new Set(['docs-site', 'docs-checks']);

/**
 * The docs pages a project still names among its inputs, each because the
 * project writes or checks the page itself. An edit of one of them affects
 * that project and its dependents; an edit of any other docs file does not.
 *
 * - The auth server generates two pages from its registries (`pnpm nx test
 *   auth-server -- -u`), and its tests compare the table of problem codes on
 *   the third with the code. No other project may import an application (the
 *   module boundaries in .oxlintrc.json), so these checks stay with it.
 * - The three contract libraries publish their page together with the JSON
 *   files under the docs site's `public/` and the stable-surface registry,
 *   all written by the library's export target and compared as one set.
 *
 * Every page here is generated or checked against the code, so an edit that
 * is not a code change fails that project's tests anyway.
 */
const SOURCE_PAGES: Readonly<Record<string, readonly string[]>> = {
  'auth-server': [
    'apps/docs-site/src/content/docs/reference/admin-permissions.md',
    'apps/docs-site/src/content/docs/reference/api-conventions.md',
    'apps/docs-site/src/content/docs/reference/security-operations.md',
  ],
  'shared-account-contract': ['apps/docs-site/src/content/docs/reference/account-api.md'],
  'shared-events': [
    'apps/docs-site/src/content/docs/reference/events.md',
    'apps/docs-site/src/content/docs/reference/ssf-events.md',
  ],
  'shared-interaction-contract': ['apps/docs-site/src/content/docs/reference/interaction-api.md'],
};

/** Directories no project configuration lives in. */
const SKIPPED = new Set(['node_modules', 'dist', 'coverage', 'tmp', '.git', '.nx', '.claude']);

/** Every file under `directory`, relative to the repository root. */
function filesUnder(directory: string): string[] {
  return readdirSync(join(REPO_ROOT, directory), { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => relative(REPO_ROOT, join(entry.parentPath, entry.name)));
}

/** Every `project.json` of the workspace, relative to the repository root. */
function projectFiles(directory = ''): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(join(REPO_ROOT, directory), { withFileTypes: true })) {
    const path = directory === '' ? entry.name : `${directory}/${entry.name}`;
    if (entry.isDirectory() && !SKIPPED.has(entry.name)) found.push(...projectFiles(path));
    else if (entry.isFile() && entry.name === 'project.json') found.push(path);
  }
  return found;
}

/** The `{workspaceRoot}/…` file patterns among a list of Nx inputs, without the prefix. */
function workspacePatterns(inputs: unknown): string[] {
  if (!Array.isArray(inputs)) return [];
  return inputs.flatMap((input: unknown) => {
    const pattern =
      typeof input === 'string'
        ? input
        : typeof input === 'object' && input !== null && 'fileset' in input
          ? String(input.fileset)
          : '';
    return pattern.startsWith('{workspaceRoot}/') ? [pattern.slice('{workspaceRoot}/'.length)] : [];
  });
}

/** Every input pattern of a project configuration: its targets' and its named inputs. */
function inputPatterns(configuration: {
  targets?: Record<string, { inputs?: unknown }>;
  targetDefaults?: Record<string, { inputs?: unknown }>;
  namedInputs?: Record<string, unknown>;
}): string[] {
  return [
    ...Object.values(configuration.targets ?? {}).flatMap((target) =>
      workspacePatterns(target.inputs)
    ),
    ...Object.values(configuration.targetDefaults ?? {}).flatMap((target) =>
      workspacePatterns(target.inputs)
    ),
    ...Object.values(configuration.namedInputs ?? {}).flatMap(workspacePatterns),
  ];
}

/** The files of `files` that one of `patterns` matches, sorted. */
function matchedFiles(patterns: readonly string[], files: readonly string[]): string[] {
  return files.filter((file) => patterns.some((pattern) => matchesGlob(file, pattern))).sort();
}

const DOCS = [...DOCS_DIRECTORIES.flatMap(filesUnder), ...DOCS_FILES];

describe('the inputs that a docs edit reaches', () => {
  it('reads the docs and the projects it checks', () => {
    expect(DOCS.length).toBeGreaterThan(100);
    expect(DOCS).toContain('docs/adr/018-1-0-scope-and-stability.md');
    expect(DOCS).toContain('apps/docs-site/src/content/docs/reference/realm-policies.md');
    expect(projectFiles()).toEqual(
      expect.arrayContaining([
        'apps/auth-server/project.json',
        'apps/docs-checks/project.json',
        'libs/server/realm-policy/project.json',
        'libs/shared/stability/project.json',
      ])
    );
  });

  it('finds a docs file in a target input, a named input and a fileset', () => {
    const files = ['docs/adr/001.md', 'apps/docs-site/src/content/docs/a.md', 'libs/x/src/a.ts'];
    expect(
      matchedFiles(
        inputPatterns({ targets: { test: { inputs: ['default', '{workspaceRoot}/docs/**/*'] } } }),
        files
      )
    ).toEqual(['docs/adr/001.md']);
    expect(
      matchedFiles(
        inputPatterns({
          namedInputs: { docs: ['{workspaceRoot}/apps/docs-site/src/content/docs/**/*.{md,mdx}'] },
        }),
        files
      )
    ).toEqual(['apps/docs-site/src/content/docs/a.md']);
    expect(
      matchedFiles(
        inputPatterns({
          targets: { build: { inputs: [{ fileset: '{workspaceRoot}/docs/adr/*.md' }] } },
        }),
        files
      )
    ).toEqual(['docs/adr/001.md']);
    expect(
      matchedFiles(inputPatterns({ targets: { test: { inputs: ['{projectRoot}/**/*'] } } }), files)
    ).toEqual([]);
  });

  it('touches no project but the docs site and this one, beyond the pages a project writes', () => {
    const touched: Record<string, string[]> = {};
    for (const file of projectFiles()) {
      const configuration = JSON.parse(readFileSync(join(REPO_ROOT, file), 'utf8'));
      const name = String(configuration.name);
      if (DOCS_OWNERS.has(name)) continue;
      const matched = matchedFiles(inputPatterns(configuration), DOCS);
      if (matched.length > 0) touched[name] = matched;
    }
    expect(touched).toEqual(SOURCE_PAGES);
  });

  // A target default or a named input reaches every project that has the
  // target or uses the input, so none may name a docs file.
  it('has no docs file among the inputs nx.json gives every project', () => {
    const lines = readFileSync(join(REPO_ROOT, 'nx.json'), 'utf8').split('\n');
    const configuration = JSON.parse(lines.filter((line) => !/^\s*\/\//.test(line)).join('\n'));
    expect(matchedFiles(inputPatterns(configuration), DOCS)).toEqual([]);
  });
});
