import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';

import { type VectorFile, vectorFileSchema } from './format';

/** One thing wrong with a vector file. */
export interface VectorProblem {
  /** Where in the file, such as `cases[2].id`; empty for the file as a whole. */
  readonly path: string;
  readonly message: string;
}

export interface ValidateOptions {
  /**
   * The id the file must carry: its path under `test-vectors/` without
   * `.json`. Set when the file was read from disk.
   */
  readonly expectedId?: string;
}

function formatPath(path: readonly PropertyKey[]): string {
  return path
    .map((segment, index) =>
      typeof segment === 'number' ? `[${segment}]` : `${index === 0 ? '' : '.'}${String(segment)}`
    )
    .join('');
}

/**
 * Check a parsed vector file against the format. Returns every problem, or
 * an empty list for a valid file.
 *
 * Rejects a missing member, a `schema` other than `qauth-vectors/1-rc.0`, an
 * unknown member at the top level or in a case, a duplicate case id, a JWK
 * not marked as a throwaway test key, and an `id` that does not match the
 * file's path.
 */
export function validateVectorFile(value: unknown, options: ValidateOptions = {}): VectorProblem[] {
  const result = vectorFileSchema.safeParse(value);
  const problems: VectorProblem[] = result.success
    ? []
    : result.error.issues.map((issue) => ({
        path: formatPath(issue.path),
        message: issue.message,
      }));

  const id = (value as { id?: unknown } | null)?.id;
  if (options.expectedId !== undefined && typeof id === 'string' && id !== options.expectedId) {
    problems.push({
      path: 'id',
      message: `id "${id}" does not match the file's path; expected "${options.expectedId}"`,
    });
  }
  return problems;
}

/** Throws unless `value` is a valid vector file; returns it typed. */
export function parseVectorFile<TInput, TExpected>(
  value: unknown,
  options: ValidateOptions & { readonly label?: string } = {}
): VectorFile<TInput, TExpected> {
  const problems = validateVectorFile(value, options);
  if (problems.length > 0) {
    const label = options.label ?? options.expectedId ?? 'vector file';
    const lines = problems.map((p) => `  ${p.path || '(file)'}: ${p.message}`);
    throw new Error(`${label} is not a valid vector file:\n${lines.join('\n')}`);
  }
  return value as VectorFile<TInput, TExpected>;
}

/** The directory every vector file lives under, from the repository root. */
export const VECTORS_DIR = 'test-vectors';

/** The files under `test-vectors/` that are not vector files. */
const NOT_VECTOR_FILES = new Set(['project.json']);
const NOT_VECTOR_DIRS = new Set(['schema', 'node_modules']);

/**
 * The repository root: the nearest directory above `start` that holds
 * `test-vectors/schema/`. Walking up rather than counting `..` keeps it right
 * when the package is read through a link under `node_modules`.
 */
export function findRepositoryRoot(start: string = __dirname): string {
  let dir = start;
  for (;;) {
    if (existsSync(join(dir, VECTORS_DIR, 'schema'))) return dir;
    const parent = dirname(dir);
    if (parent === dir) {
      throw new Error(`no ${VECTORS_DIR}/schema/ directory above ${start}`);
    }
    dir = parent;
  }
}

/** The id a file at `relativePath` (from `test-vectors/`) must carry. */
export function vectorIdForPath(relativePath: string): string {
  return relativePath
    .split(sep)
    .join('/')
    .replace(/\.json$/, '');
}

/**
 * Every vector file under `test-vectors/`, as paths relative to it, sorted.
 * A vector file is any `.json` file below it, except `project.json` and the
 * files in `schema/`.
 */
export function listVectorFiles(root: string = findRepositoryRoot()): string[] {
  const base = join(root, VECTORS_DIR);
  const files: string[] = [];
  const walk = (dir: string, top: boolean): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (!(top && NOT_VECTOR_DIRS.has(entry.name))) walk(join(dir, entry.name), false);
      } else if (entry.name.endsWith('.json') && !(top && NOT_VECTOR_FILES.has(entry.name))) {
        files.push(relative(base, join(dir, entry.name)));
      }
    }
  };
  walk(base, true);
  return files.sort();
}

/** The problems found in one file on disk. */
export interface VectorFileReport {
  /** The path from the repository root. */
  readonly file: string;
  readonly problems: readonly VectorProblem[];
}

/** Read, parse and validate one file at `relativePath` under `test-vectors/`. */
export function validateVectorFileOnDisk(
  relativePath: string,
  root: string = findRepositoryRoot()
): VectorFileReport {
  const file = `${VECTORS_DIR}/${relativePath.split(sep).join('/')}`;
  let value: unknown;
  try {
    value = JSON.parse(readFileSync(join(root, file), 'utf8'));
  } catch (error) {
    return { file, problems: [{ path: '', message: `not JSON: ${(error as Error).message}` }] };
  }
  return {
    file,
    problems: validateVectorFile(value, { expectedId: vectorIdForPath(relativePath) }),
  };
}

/** Validate every vector file in the tree. */
export function validateVectorTree(root: string = findRepositoryRoot()): VectorFileReport[] {
  return listVectorFiles(root).map((path) => validateVectorFileOnDisk(path, root));
}
