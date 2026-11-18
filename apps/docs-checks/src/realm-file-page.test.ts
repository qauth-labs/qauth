import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';

import { parseManifest } from '@qauth-labs/infra-db/seed-manifest';
import {
  REALM_FILE_FORMAT,
  REALM_FILE_FORMAT_VERSION,
  REALM_FILE_PAGE_PATH,
  REALM_FILE_SECTIONS,
  realmFileJsonSchema,
  safeParseRealmFile,
} from '@qauth-labs/realm-file';
import Ajv2020 from 'ajv/dist/2020';
import addFormats from 'ajv-formats';
import { describe, expect, it } from 'vitest';

import { REPO_ROOT } from './workspace';

/**
 * The realm file's docs page against the format of `@qauth-labs/realm-file`
 * (#515). The library's own tests check the format and its published JSON
 * Schema; these check the page, which is written by hand, and the seed
 * manifest examples of every other page.
 */

const DOCS_DIR = join(REPO_ROOT, 'apps/docs-site/src/content/docs');
const page = readFileSync(join(REPO_ROOT, REALM_FILE_PAGE_PATH), 'utf8');

/** The ```json blocks of a Markdown text, as written. */
const jsonBlocks = (markdown: string): string[] =>
  [...markdown.matchAll(/^```json\n([\s\S]*?)^```$/gm)].map((match) => match[1]);

/** The JSON Schema the docs site publishes, under a strict validator. */
function jsonSchemaValidator() {
  const ajv = new Ajv2020({ strict: true, strictRequired: false, allErrors: true });
  addFormats(ajv);
  ajv.addKeyword('x-qauth-policy');
  ajv.addKeyword('x-qauth-schema-version');
  return ajv.compile(realmFileJsonSchema());
}

/** Every page of the docs site, by path from the repository root. */
function docsPages(): string[] {
  return readdirSync(DOCS_DIR, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile() && /\.mdx?$/.test(entry.name))
    .map((entry) => relative(REPO_ROOT, join(entry.parentPath, entry.name)))
    .sort();
}

describe('the realm file page (#515)', () => {
  const blocks = jsonBlocks(page);

  // Acceptance criterion: the docs page example is valid against the schema.
  it('has a full example, valid for the parser and for the published JSON Schema', () => {
    expect(blocks).toHaveLength(1);
    const example = JSON.parse(blocks[0]) as Record<string, unknown>;
    const result = safeParseRealmFile(example);
    expect(result.success, JSON.stringify(result, null, 2)).toBe(true);
    const validate = jsonSchemaValidator();
    expect(validate(example), JSON.stringify(validate.errors, null, 2)).toBe(true);
    // A full example: every top-level key of the format.
    expect(Object.keys(example)).toEqual([
      'format',
      'realm',
      ...REALM_FILE_SECTIONS.map(({ name }) => name),
    ]);
  });

  it('names the format and links the published schema', () => {
    expect(page).toContain(REALM_FILE_FORMAT);
    expect(page).toContain(`(/schemas/realm-file-${REALM_FILE_FORMAT_VERSION}.json)`);
  });

  // The growth rule: a section is added with its schema, its natural key and
  // its diff rules. The page says each section's natural key under its own
  // heading.
  it.each(REALM_FILE_SECTIONS.map((section) => [section.name, section] as const))(
    'describes the section %s under its own heading, with its natural key',
    (name, section) => {
      const start = page.indexOf(`\n### \`${name}\`\n`);
      expect(start, name).toBeGreaterThan(-1);
      const next = page.slice(start + 1).search(/\n#{2,3} /);
      const body = page.slice(start, next === -1 ? undefined : start + 1 + next);
      expect(body).toContain(
        section.naturalKey === undefined
          ? 'Natural key: none'
          : `Natural key: \`${section.naturalKey}\``
      );
    }
  );
});

// CFG-12: the seed manifest is a realm file as it is. Every example of a
// manifest on the docs site that the seed accepts is a realm file too.
describe('the seed manifest examples of the docs', () => {
  const examples = docsPages().flatMap((path) =>
    jsonBlocks(readFileSync(join(REPO_ROOT, path), 'utf8')).flatMap((block, index) => {
      let value: unknown;
      try {
        value = JSON.parse(block);
      } catch {
        return [];
      }
      if (typeof value !== 'object' || value === null || !('realm' in value)) return [];
      try {
        parseManifest(value);
      } catch {
        return [];
      }
      return [{ name: `${path} #${index + 1}`, value }];
    })
  );

  it('are found', () => {
    expect(examples.length).toBeGreaterThanOrEqual(5);
  });

  it.each(examples)('$name is a valid realm file', ({ value }) => {
    const result = safeParseRealmFile(value);
    expect(result.success, JSON.stringify(result, null, 2)).toBe(true);
  });
});
