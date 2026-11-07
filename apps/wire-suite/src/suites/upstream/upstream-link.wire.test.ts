import { randomBytes } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { serverPath, wireConfig } from '../../config';

/**
 * The hosted pages of an upstream account link (#670; ADR-020 §3): the choice
 * between a new account and "I already have an account" for an identity no
 * account holds, and the page of a link that was refused. A wire client holds
 * no interaction and a default deployment configures no upstream provider,
 * so these tests check what every caller can reach: a choice page for an
 * interaction the server does not hold says the sign-in has ended, and the
 * refused page changes nothing and sends the browser nowhere. Neither is
 * stored.
 */

const { baseUrl } = wireConfig();

/** A GET of `path`, following no redirect. */
function get(path: string, query?: Record<string, string>): Promise<Response> {
  const search = query === undefined ? '' : `?${new URLSearchParams(query).toString()}`;
  return fetch(`${serverPath(baseUrl, path)}${search}`, { redirect: 'manual' });
}

/** A provider type of the right shape (`oidc_` and an alias) that no realm of the run has. */
const ABSENT_TYPE = 'oidc_wireabsent';

/** An HTML page that is never stored and sends the browser nowhere. */
function expectPage(response: Response, status: number): void {
  expect(response.status).toBe(status);
  expect(response.headers.get('location'), 'the page sends the browser nowhere').toBeNull();
  expect(response.headers.get('content-type')).toMatch(/^text\/html\b/i);
  expect(response.headers.get('cache-control')).toBe('no-store');
}

describe('[GET /ui/upstream-link/{interactionId}] the choice of a new account or an existing one', () => {
  it('answers an interaction the server does not hold with the ended page, 410', async () => {
    const response = await get(`/ui/upstream-link/${randomBytes(32).toString('base64url')}`);
    expectPage(response, 410);
    expect(await response.text()).toContain('This sign-in has ended');
  });

  it('answers an id that is no interaction id with the same page', async () => {
    const response = await get('/ui/upstream-link/not-an-interaction');
    expectPage(response, 410);
    expect(await response.text()).toContain('This sign-in has ended');
  });
});

describe('[GET /ui/upstream-link-refused] the page of a refused link', () => {
  it('says the account was not linked, and why', async () => {
    const response = await get('/ui/upstream-link-refused', {
      provider: ABSENT_TYPE,
      reason: 'already_linked',
    });
    expectPage(response, 409);
    const body = await response.text();
    expect(body).toContain('The account was not linked');
    expect(body).toContain('already linked');
  });

  it('refuses a reason it does not know with 400', async () => {
    const response = await get('/ui/upstream-link-refused', {
      provider: ABSENT_TYPE,
      reason: 'merged_by_email',
    });
    expect(response.status).toBe(400);
  });
});
