import { randomBytes } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { call } from '../../helpers/operations';

/**
 * The landing of a mailed pass link (ADR-017 Decision 5, #637). The
 * send-ceiling and password-disabled notices carry a link with a single-use
 * pass; opening it starts an interaction that holds the pass and redirects to
 * its ceremony page. The suite cannot make the server mail a pass, so these
 * tests check what every caller can reach: a link with no pass, a damaged
 * one, and one that names no pass. Each gets the same page, never stored,
 * sends no referrer, sets no cookie and repeats nothing of the link.
 */

/** `text/html`, with or without parameters. */
const HTML_CONTENT_TYPE = /^text\/html\b/i;

/** Assert the one page a link whose pass opens nothing gets. */
async function expectInvalidLinkPage(response: Response, sent?: string): Promise<void> {
  const body = await response.text();
  expect(response.status, body.slice(0, 500)).toBe(400);
  expect(response.headers.get('content-type') ?? '').toMatch(HTML_CONTENT_TYPE);
  expect(response.headers.get('cache-control')).toBe('no-store');
  expect(response.headers.get('referrer-policy')).toBe('no-referrer');
  expect(response.headers.get('location')).toBeNull();
  expect(response.headers.get('set-cookie')).toBeNull();
  expect(body).toContain('This link is no longer valid');
  if (sent !== undefined) expect(body).not.toContain(sent);
}

describe('[GET /auth/pass] ADR-017 Decision 5 — a mailed pass link that opens nothing', () => {
  it('answers a link with no pass with the invalid-link page and starts nothing', async () => {
    await expectInvalidLinkPage(await call('GET /auth/pass'));
  });

  it('answers a damaged pass with the same page, and repeats none of it', async () => {
    const damaged = `damaged-${randomBytes(6).toString('hex')}`;
    await expectInvalidLinkPage(
      await call('GET /auth/pass', { query: { pass: damaged } }),
      damaged
    );
  });

  it('answers a well-formed pass the server never minted with the same page', async () => {
    const unknown = randomBytes(32).toString('base64url');
    await expectInvalidLinkPage(
      await call('GET /auth/pass', { query: { pass: unknown } }),
      unknown
    );
  });
});
