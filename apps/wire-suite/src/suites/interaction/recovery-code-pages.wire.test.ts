import { randomBytes } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { serverPath, wireConfig } from '../../config';

/**
 * The recovery codes' hosted pages (#649; ADR-017 Decision 8): "use a
 * recovery code" and "save your recovery codes", server-rendered for an
 * interaction of the Interaction API whose current step is one of the two
 * recovery steps. A wire client holds no such interaction, so these tests
 * check what every caller can reach: an interaction the server does not hold
 * gets the page that says the sign-in has ended, `410`, never stored and
 * sending the browser nowhere; and the page that shows a set refuses a
 * request another site sent before it reads anything.
 */

const { baseUrl } = wireConfig();

/** An interaction id of the right shape (32 random bytes, base64url) that names none. */
function unknownInteractionId(): string {
  return randomBytes(32).toString('base64url');
}

/** A GET of the page at `path` for `id`, following no redirect. */
function page(
  path: '/ui/recovery-code' | '/ui/recovery-codes',
  id: string,
  headers: Record<string, string> = {}
): Promise<Response> {
  return fetch(serverPath(baseUrl, `${path}/${id}`), { headers, redirect: 'manual' });
}

/** The page of an interaction that ended: 410, HTML, never stored, and no redirect. */
async function expectEndedPage(response: Response): Promise<void> {
  expect(response.status).toBe(410);
  expect(response.headers.get('location'), 'an ended sign-in sends the browser nowhere').toBeNull();
  expect(response.headers.get('content-type')).toMatch(/^text\/html\b/i);
  expect(response.headers.get('cache-control')).toBe('no-store');
  expect(await response.text()).toContain('This sign-in has ended');
}

describe('[GET /ui/recovery-code/{interactionId}] the "use a recovery code" page', () => {
  it('answers an interaction the server does not hold with its ended page, 410, never stored', async () => {
    await expectEndedPage(await page('/ui/recovery-code', unknownInteractionId()));
  });

  it('answers an id that cannot name an interaction the same way', async () => {
    await expectEndedPage(await page('/ui/recovery-code', 'not-an-interaction'));
  });
});

describe('[GET /ui/recovery-codes/{interactionId}] the "save your recovery codes" page', () => {
  it('refuses a request another site sent with 403, before it reads the interaction', async () => {
    const response = await page('/ui/recovery-codes', unknownInteractionId(), {
      'sec-fetch-site': 'cross-site',
      origin: 'https://other.example',
    });
    expect(response.status).toBe(403);
    expect(response.headers.get('location')).toBeNull();
    expect(await response.text()).not.toMatch(/<code>[a-z2-7]{4}-[a-z2-7]{4}/);
  });

  it('answers an interaction the server does not hold with its ended page, 410, never stored', async () => {
    await expectEndedPage(
      await page('/ui/recovery-codes', unknownInteractionId(), { 'sec-fetch-site': 'same-origin' })
    );
  });
});
