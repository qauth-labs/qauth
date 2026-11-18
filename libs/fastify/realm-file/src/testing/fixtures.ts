import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * The realm file's fixtures (#515), for this library's tests: nothing else
 * imports this module. `fixtures/valid` holds files the format accepts,
 * `fixtures/invalid` files it refuses, with `fixtures/invalid-expected.json`
 * saying where each fails, and `fixtures/seed-manifests` seed manifests,
 * which are realm files as they are.
 */

/** The repository root. */
export const REPO_ROOT = join(__dirname, '..', '..', '..', '..', '..');

const FIXTURES_DIR = join(__dirname, '..', '..', 'fixtures');

/** One fixture: its file name and its parsed JSON. */
export interface Fixture {
  readonly name: string;
  readonly value: unknown;
}

/** What an invalid fixture must give. */
export interface InvalidExpectation {
  readonly path: readonly (string | number)[];
  readonly message: string;
  /** `accepts` when only the parser refuses the file, with why. */
  readonly jsonSchema?: 'accepts';
  readonly why?: string;
}

const readJson = (path: string): unknown => JSON.parse(readFileSync(path, 'utf8'));

/** The fixtures of one directory, by file name. */
export function fixtures(kind: 'valid' | 'invalid' | 'seed-manifests'): Fixture[] {
  const directory = join(FIXTURES_DIR, kind);
  return readdirSync(directory)
    .filter((name) => name.endsWith('.json'))
    .sort()
    .map((name) => ({ name, value: readJson(join(directory, name)) }));
}

/** What each invalid fixture must give, by file name. */
export function invalidExpectations(): Readonly<Record<string, InvalidExpectation>> {
  return (
    readJson(join(FIXTURES_DIR, 'invalid-expected.json')) as {
      fixtures: Record<string, InvalidExpectation>;
    }
  ).fixtures;
}

/** The seed manifests the repository ships, outside the fixtures, by path from the root. */
export const SHIPPED_SEED_MANIFESTS = Object.freeze([
  'graphs/fixtures/seed-manifest.json',
  'apps/wire-suite/seed/clients.json',
]);

/** A file of the repository, parsed as JSON. */
export const readRepoJson = (path: string): unknown => readJson(join(REPO_ROOT, path));
