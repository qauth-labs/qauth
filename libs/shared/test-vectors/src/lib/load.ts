import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { VECTOR_FILE_ID_PATTERN, type VectorFile } from './format';
import { findRepositoryRoot, parseVectorFile, VECTORS_DIR } from './validate';

export interface LoadOptions {
  /** The repository root; found by walking up from this package when omitted. */
  readonly root?: string;
}

/**
 * Load a vector file by id for a TypeScript test: `loadVectors('pkce/s256')`
 * reads `test-vectors/pkce/s256.json`, validates it and returns it typed by
 * what the file's description says `input` and `expected` hold.
 *
 * Throws when the id is malformed, the file is missing, or it is not a valid
 * vector file, so a test never runs against a file the validator would
 * reject.
 *
 * @example
 * ```ts
 * const vectors = loadVectors<{ code_verifier: string }, { accepted: boolean }>('pkce/s256');
 * it.each(vectors.cases)('$id', ({ input, expected }) => { ... });
 * ```
 */
export function loadVectors<TInput = Record<string, unknown>, TExpected = Record<string, unknown>>(
  id: string,
  options: LoadOptions = {}
): VectorFile<TInput, TExpected> {
  if (!VECTOR_FILE_ID_PATTERN.test(id)) {
    throw new Error(`"${id}" is not a vector file id (such as "pkce/s256")`);
  }
  const root = options.root ?? findRepositoryRoot();
  const path = join(root, VECTORS_DIR, `${id}.json`);
  const value: unknown = JSON.parse(readFileSync(path, 'utf8'));
  return parseVectorFile<TInput, TExpected>(value, { expectedId: id });
}
