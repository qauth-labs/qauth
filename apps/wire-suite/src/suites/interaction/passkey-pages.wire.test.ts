import { randomBytes } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { serverPath, wireConfig } from '../../config';

/**
 * The passkey pages (#651; ADR-017 Decisions 4 and 10): "sign in with a
 * passkey" and "add a passkey", server-rendered for an interaction of the
 * Interaction API that offers a passkey step. A wire client holds no such
 * interaction, so these tests check what every caller can reach: an
 * interaction the server does not hold gets the page that says the sign-in
 * has ended, `410`, never stored and sending the browser nowhere; and the
 * page that shows the account's name refuses a request another site sent
 * before it reads anything.
 */

const { baseUrl } = wireConfig();

/** An interaction id of the right shape (32 random bytes, base64url) that names none. */
function unknownInteractionId(): string {
  return randomBytes(32).toString('base64url');
}

/** A GET of the page at `path` for `id`, following no redirect. */
function page(
  path: '/ui/passkey' | '/ui/passkey-enrolment',
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

describe('[GET /ui/passkey/{interactionId}] the "sign in with a passkey" page', () => {
  it('answers an interaction the server does not hold with its ended page, 410, never stored', async () => {
    await expectEndedPage(await page('/ui/passkey', unknownInteractionId()));
  });

  it('answers an id that cannot name an interaction the same way', async () => {
    await expectEndedPage(await page('/ui/passkey', 'not-an-interaction'));
  });
});

describe('[GET /ui/passkey-enrolment/{interactionId}] the "add a passkey" page', () => {
  it('refuses a request another site sent with 403, before it reads the interaction', async () => {
    const response = await page('/ui/passkey-enrolment', unknownInteractionId(), {
      'sec-fetch-site': 'cross-site',
      origin: 'https://other.example',
    });
    expect(response.status).toBe(403);
    expect(response.headers.get('location')).toBeNull();
    expect(await response.text()).not.toContain('data-options');
  });

  it('answers an interaction the server does not hold with its ended page, 410, never stored', async () => {
    await expectEndedPage(
      await page('/ui/passkey-enrolment', unknownInteractionId(), {
        'sec-fetch-site': 'same-origin',
      })
    );
  });
});
