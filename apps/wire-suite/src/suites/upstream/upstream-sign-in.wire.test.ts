import { randomBytes } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { serverPath, wireConfig } from '../../config';
import { authorizationRequest, SEEDED_REDIRECT_URI } from '../../fixtures/authorization';

/**
 * The provider links of the hosted sign-in page and the routed start of an
 * upstream identity provider (ADR-020 §3, #639), as a browser that names a
 * provider the realm does not have sees them. A default deployment configures
 * no upstream provider, so these tests check what every caller can reach:
 * each refusal is the one HTML error page with the request's trace id, never
 * stored, and sends nothing to the client: no redirect, and not its redirect
 * URI.
 */

const { baseUrl } = wireConfig();

/** A GET of `path` on the server under test, following no redirect. */
function get(path: string, query: Record<string, string>): Promise<Response> {
  return fetch(`${serverPath(baseUrl, path)}?${new URLSearchParams(query).toString()}`, {
    redirect: 'manual',
  });
}

/** A provider type of the right shape (`oidc_` and an alias) that no realm of the run has. */
const ABSENT_TYPE = 'oidc_wireabsent';

/** The one error page: 400, HTML, never stored, its trace id, and nothing for the client. */
async function expectErrorPage(response: Response): Promise<void> {
  expect(response.status).toBe(400);
  expect(response.headers.get('location'), 'a refusal sends the browser nowhere').toBeNull();
  expect(response.headers.get('content-type')).toMatch(/^text\/html\b/i);
  expect(response.headers.get('cache-control')).toBe('no-store');
  const body = await response.text();
  expect(body, 'the page names the trace id').toMatch(/<code>[^<\s]+<\/code>/);
  expect(body, 'nothing of the client reaches the page').not.toContain(SEEDED_REDIRECT_URI);
}

describe('[GET /ui/upstream/{type}] ADR-020 §3 — a provider link of the sign-in page', () => {
  it('answers a provider the realm does not have with the error page, sending the browser nowhere', async () => {
    const { url } = authorizationRequest();

    await expectErrorPage(
      await get(`/ui/upstream/${ABSENT_TYPE}`, { return_to: `${url.pathname}${url.search}` })
    );
  });
});

describe('[GET /ui/upstream/{type}/start] ADR-020 §3 — the start of a provider a request routes to', () => {
  it('answers a provider the realm does not have with the error page, starting nothing', async () => {
    await expectErrorPage(
      await get(`/ui/upstream/${ABSENT_TYPE}/start`, {
        interaction: randomBytes(32).toString('base64url'),
      })
    );
  });
});
