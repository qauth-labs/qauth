import { randomBytes } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { call } from '../../helpers/operations';

/**
 * The one-time admin enrolment (ADR-019 Decision 7, #621). The break-glass
 * CLI's `enrol-admin` prints a URL whose fragment holds a token; the
 * ceremony app's page posts it to `POST /auth/admin-enrolment`, which
 * starts the `admin_enrolment` step. The suite cannot run the CLI, so these
 * tests check what every caller can reach: a post with no token, a damaged
 * one, one the server never minted, and one from another site; and the page
 * an enrolment ends on. Every refused start gets the same page, never
 * stored, sends no referrer, sets no cookie and repeats nothing of the post.
 */

/** `text/html`, with or without parameters. */
const HTML_CONTENT_TYPE = /^text\/html\b/i;

/** A form post from a page of the realm origin, as the ceremony app's page sends it. */
const SAME_ORIGIN = { 'sec-fetch-site': 'same-origin' };

/** Assert the one page a start that enrols nothing gets. */
async function expectRefusedPage(response: Response, sent?: string): Promise<void> {
  const body = await response.text();
  expect(response.status, body.slice(0, 500)).toBe(400);
  expect(response.headers.get('content-type') ?? '').toMatch(HTML_CONTENT_TYPE);
  expect(response.headers.get('cache-control')).toBe('no-store');
  expect(response.headers.get('referrer-policy')).toBe('no-referrer');
  expect(response.headers.get('location')).toBeNull();
  expect(response.headers.get('set-cookie')).toBeNull();
  expect(body).toContain('This enrolment link is no longer valid');
  if (sent !== undefined) expect(body).not.toContain(sent);
}

describe('[POST /auth/admin-enrolment] ADR-019 Decision 7 — a start that enrols nothing', () => {
  it('answers a post with no token with the refusal page and starts nothing', async () => {
    await expectRefusedPage(
      await call('POST /auth/admin-enrolment', { headers: SAME_ORIGIN, form: {} })
    );
  });

  it('answers a damaged token with the same page, and repeats none of it', async () => {
    const damaged = `damaged-${randomBytes(6).toString('hex')}`;
    await expectRefusedPage(
      await call('POST /auth/admin-enrolment', { headers: SAME_ORIGIN, form: { token: damaged } }),
      damaged
    );
  });

  it('answers a well-formed token the server never minted with the same page', async () => {
    const unknown = randomBytes(32).toString('base64url');
    await expectRefusedPage(
      await call('POST /auth/admin-enrolment', { headers: SAME_ORIGIN, form: { token: unknown } }),
      unknown
    );
  });

  it('refuses a post from another site with 403, and starts nothing', async () => {
    const response = await call('POST /auth/admin-enrolment', {
      headers: { 'sec-fetch-site': 'cross-site', origin: 'https://other.example' },
      form: { token: randomBytes(32).toString('base64url') },
    });
    expect(response.status).toBe(403);
    expect(response.headers.get('location')).toBeNull();
    expect(response.headers.get('set-cookie')).toBeNull();
  });
});

describe('[GET /auth/admin-enrolment/status] ADR-019 Decision 7 — the page an enrolment ends on', () => {
  /** The page for `result`, as a browser sent to it opens it. */
  async function statusPage(result?: string): Promise<string> {
    const response = await call(
      'GET /auth/admin-enrolment/status',
      result === undefined ? {} : { query: { result } }
    );
    const body = await response.text();
    expect(response.status, body.slice(0, 500)).toBe(200);
    expect(response.headers.get('content-type') ?? '').toMatch(HTML_CONTENT_TYPE);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('set-cookie')).toBeNull();
    return body;
  }

  it('tells each ending its own page', async () => {
    expect(await statusPage('enrolled')).toContain('Your passkey is registered');
    expect(await statusPage('cancelled')).toContain('The enrolment was cancelled');
    expect(await statusPage('refused')).toContain('This enrolment link is no longer valid');
  });

  it('reads a value that is not an ending, or none, as refused', async () => {
    const refused = await statusPage('refused');
    expect(await statusPage()).toBe(refused);
    expect(await statusPage('ENROLLED')).toBe(refused);
  });
});
