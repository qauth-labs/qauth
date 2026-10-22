/// <reference types="vitest/globals" />
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { codeForStatus, PROBLEM_CODES, problemCodeFor } from './problem';

/**
 * The published problem `code` values (#506): which code an error gets, and
 * that the docs site's table is this table.
 */

const CONVENTIONS_PAGE = join(
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
  'api-conventions.md'
);

/** One row of the page's code table: `` | `CODE` | 400 | Meaning | ``. */
const CODE_ROW = /^\|\s*`([a-z_]+)`\s*\|\s*(\d{3})\s*\|\s*(.*?)\s*\|\s*$/;

describe('problem codes (#506)', () => {
  it('gives every status the code its entry lists for that status', () => {
    for (const status of [400, 401, 403, 404, 405, 409, 412, 413, 415, 422, 428, 429, 500, 503]) {
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
    expect(problemCodeFor('INVALID_GRANT', 400)).toBe('bad_request');
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

  it('is the table the conventions page publishes, row for row', () => {
    const page = readFileSync(CONVENTIONS_PAGE, 'utf8');
    const published = page
      .split('\n')
      .map((line) => CODE_ROW.exec(line))
      .filter((match) => match !== null)
      .map(([, code, status, description]) => [code, Number(status), description]);

    expect(published).toEqual(
      Object.entries(PROBLEM_CODES).map(([code, { status, description }]) => [
        code,
        status,
        description,
      ])
    );
  });
});
