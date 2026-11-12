import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

/**
 * THE SERVER NAMES NO PROVIDER (#671, ADR-018 §3). Every provider plugin
 * (Google, Microsoft, Apple, GitHub, My Number) lives in its own repository
 * and depends only on the published plugin SDK; the server builds a preset
 * plugin's method from how it was built, never from its name. So no source
 * file of `apps/` or `libs/` outside tests and docs holds such a provider's
 * id, type or display name as a string, or the npm name of its plugin.
 *
 * Platform names that are no sign-in provider stay: the Apple app-site
 * association a passkey needs, a font stack, a crawler's name. They are
 * never one of these whole strings.
 */

/** The workspace root, from `apps/auth-server/src/app`. */
const WORKSPACE_ROOT = resolve(__dirname, '../../../..');

/** A provider's id, type or display name, as a whole string literal. */
const PROVIDER_LITERAL = /(['"`])(google|microsoft|apple|github|my[-_ ]?number)\1/i;

/** The npm name of a provider plugin. */
const PROVIDER_PACKAGE = /@qauth-labs\/plugin-(google|microsoft|apple|github|my-?number)\b/i;

const SOURCE_EXTENSION = /\.(?:[cm]?[jt]s|tsx|jsx)$/;

/** Tests, test support and fixtures: they may name what they like. */
const TEST_FILE = /\.(?:test|spec|fixture)\.[cm]?[jt]sx?$/;

/** Directories that are no source: builds, caches, dependencies, test support. */
const SKIPPED_DIRECTORIES: ReadonlySet<string> = new Set([
  'node_modules',
  'dist',
  'out-tsc',
  'coverage',
  'tmp',
  'testing',
  '.astro',
  '.vite',
  '.nx',
]);

/** The docs pages: they name the provider repositories as examples. */
const DOCS_CONTENT = join('apps', 'docs-site', 'src', 'content');

function sourceFiles(directory: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      if (SKIPPED_DIRECTORIES.has(entry.name)) continue;
      if (relative(WORKSPACE_ROOT, path) === DOCS_CONTENT) continue;
      files.push(...sourceFiles(path));
    } else if (entry.isFile() && SOURCE_EXTENSION.test(entry.name) && !TEST_FILE.test(entry.name)) {
      files.push(path);
    }
  }
  return files;
}

describe('the server names no provider (#671)', () => {
  it('holds no provider id, type, display name or plugin package name in the source of apps/ and libs/', () => {
    const files = ['apps', 'libs'].flatMap((top) => sourceFiles(join(WORKSPACE_ROOT, top)));
    // The walk reached the code it guards.
    expect(files.map((file) => relative(WORKSPACE_ROOT, file))).toEqual(
      expect.arrayContaining([
        'libs/server/federation/src/claims/attribute-trust.ts',
        'apps/auth-server/src/app/helpers/auth-method-plugins.ts',
      ])
    );

    const hits: string[] = [];
    for (const file of files) {
      const lines = readFileSync(file, 'utf8').split('\n');
      lines.forEach((line, index) => {
        if (PROVIDER_LITERAL.test(line) || PROVIDER_PACKAGE.test(line)) {
          hits.push(`${relative(WORKSPACE_ROOT, file)}:${index + 1}: ${line.trim()}`);
        }
      });
    }
    expect(hits).toEqual([]);
  });

  it('would find one', () => {
    expect(PROVIDER_LITERAL.test("type: 'google',")).toBe(true);
    expect(PROVIDER_LITERAL.test('display: { name: "Apple" }')).toBe(true);
    expect(PROVIDER_PACKAGE.test("'@qauth-labs/plugin-microsoft'")).toBe(true);
    expect(PROVIDER_LITERAL.test("'apple-app-site-association'")).toBe(false);
    expect(PROVIDER_LITERAL.test("'oidc_google'")).toBe(false);
  });
});
