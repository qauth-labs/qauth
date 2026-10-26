/// <reference types="vitest/globals" />
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { codeForStatus, PROBLEM_CODES, problemCodeFor } from './problem';

/**
 * The published problem `code` values (#506, #513): which code an error gets,
 * and that the docs site's problem types page lists exactly these types.
 */

const PROBLEM_TYPES_PAGE = join(
  __dirname,
  '..',
  '..',
  '..',
  '..',
  'docs-site',
  'src',
  'content',
  'docs',
  'reference',
  'problem-types.md'
);

/** The heading of one type on the page: ``## `not-found` ``. */
const TYPE_HEADING = /^## `([a-z0-9-]+)`$/;

/** The line under it: ``**Code** `not_found` · **Status** 404 · **Title** Not found``. */
const TYPE_FACTS = /^\*\*Code\*\* `([a-z_]+)` · \*\*Status\*\* (\d{3}) · \*\*Title\*\* (.+)$/;

/** Each type the page documents, in page order: slug, code, status, title, meaning. */
function publishedTypes(page: string): [string, string, number, string, string][] {
  const lines = page.split('\n');
  const types: [string, string, number, string, string][] = [];
  lines.forEach((line, index) => {
    const heading = TYPE_HEADING.exec(line);
    if (!heading) return;
    const facts = TYPE_FACTS.exec(lines[index + 2] ?? '');
    const meaning = lines[index + 4] ?? '';
    if (!facts) throw new Error(`no facts line under ${line}`);
    types.push([heading[1], facts[1], Number(facts[2]), facts[3], meaning]);
  });
  return types;
}

describe('problem codes (#506)', () => {
  it('gives every status the code its entry lists for that status', () => {
    for (const status of [
      400, 401, 403, 404, 405, 408, 409, 412, 413, 414, 415, 421, 422, 428, 429, 431, 500, 503,
    ]) {
      expect(PROBLEM_CODES[codeForStatus(status)].status).toBe(status);
    }
  });

  it('falls back to bad_request for another 4xx and internal_error for anything else', () => {
    expect(codeForStatus(418)).toBe('bad_request');
    expect(codeForStatus(502)).toBe('internal_error');
    expect(codeForStatus(200)).toBe('internal_error');
  });

  it("keeps an error's own code only when it is published for that status", () => {
    // The error classes name their codes in upper case, for the earlier body.
    expect(problemCodeFor('WEAK_PASSWORD', 422)).toBe('weak_password');
    expect(problemCodeFor('weak_password', 422)).toBe('weak_password');
    expect(problemCodeFor('NOT_FOUND', 400)).toBe('bad_request');
    expect(problemCodeFor('FST_ERR_CTP_INVALID_MEDIA_TYPE', 415)).toBe('unsupported_media_type');
    expect(problemCodeFor('INVALID_GRANT', 400)).toBe('invalid_grant');
    expect(problemCodeFor('INVALID_GRANT', 401)).toBe('unauthorized');
    expect(problemCodeFor(undefined, 404)).toBe('not_found');
    expect(problemCodeFor('toString', 400)).toBe('bad_request');
  });

  it('names every code in lower-case snake_case and sends it with a 4xx or 5xx status', () => {
    for (const [code, { status }] of Object.entries(PROBLEM_CODES)) {
      expect(code).toMatch(/^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$/);
      expect(status).toBeGreaterThanOrEqual(400);
      expect(status).toBeLessThanOrEqual(599);
    }
  });

  it('is the list the problem types page publishes, type for type', () => {
    const page = readFileSync(PROBLEM_TYPES_PAGE, 'utf8');

    expect(publishedTypes(page)).toEqual(
      Object.entries(PROBLEM_CODES).map(([code, { status, type, title, description }]) => [
        type,
        code,
        status,
        title,
        description,
      ])
    );
  });
});
