import { randomBytes } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { serverPath, wireConfig } from '../../config';
import { expectProblem } from '../../helpers/error-shape';

/**
 * The Interaction API's operations (ADR-019 Decision 6), as a client that
 * holds no interaction sees them. No default deployment starts an
 * interaction yet (the authorization endpoint will), so these tests check
 * what every caller can reach: an interaction the server does not hold, a
 * request from another site, a body of another media type. Each answer is a
 * bare problem document (no `detail`, no `instance`), is never stored, and
 * carries no CORS header.
 */

const { baseUrl } = wireConfig();

/** The step the bodies below answer: the identifier step's URN. */
const IDENTIFIER_STEP = 'urn:qauth:ia:identifier:v1-rc.0';

/** An interaction id of the right shape (32 random bytes, base64url) that names none. */
function unknownInteractionId(): string {
  return randomBytes(32).toString('base64url');
}

function interactionUrl(id: string, operation: '' | '/personal' | '/answer' | '/cancel'): string {
  return serverPath(baseUrl, `/interaction/v1-rc.0/${id}${operation}`);
}

/** POST an answer or a cancel with the given headers and form body. */
function post(
  id: string,
  operation: '/answer' | '/cancel',
  headers: Record<string, string>,
  body: string
): Promise<Response> {
  return fetch(interactionUrl(id, operation), {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
    body,
    redirect: 'manual',
  });
}

/** Never stored, and no `Access-Control-*` header field. */
function expectNoStoreNoCors(response: Response): void {
  expect(response.headers.get('cache-control')).toBe('no-store');
  const cors = [...response.headers.keys()].filter((name) => name.startsWith('access-control-'));
  expect(cors).toEqual([]);
}

/** A problem document that names nothing about the request. */
async function expectBareProblem(response: Response, status: number, code: string): Promise<void> {
  expectNoStoreNoCors(response);
  const problem = await expectProblem(response, { status, code });
  expect(problem).not.toHaveProperty('detail');
  expect(problem).not.toHaveProperty('instance');
}

const ANSWER = `type=${encodeURIComponent(IDENTIFIER_STEP)}&csrf=x&login_hint=alice%40example.com`;

describe('[GET /interaction/v1-rc.0/{interactionId}] the step read', () => {
  it('answers an interaction the server does not hold with 410 interaction_expired, to any origin', async () => {
    const response = await fetch(interactionUrl(unknownInteractionId(), ''), {
      headers: { origin: 'https://other.example' },
      redirect: 'manual',
    });
    await expectBareProblem(response, 410, 'interaction_expired');
  });
});

describe('[GET /interaction/v1-rc.0/{interactionId}/personal] the personal read', () => {
  it('refuses a request from another site with 403 forbidden', async () => {
    const response = await fetch(interactionUrl(unknownInteractionId(), '/personal'), {
      headers: { 'sec-fetch-site': 'cross-site', origin: 'https://other.example' },
      redirect: 'manual',
    });
    await expectBareProblem(response, 403, 'forbidden');
  });

  it('answers a same-origin read without the flow cookie with 410 interaction_expired', async () => {
    const response = await fetch(interactionUrl(unknownInteractionId(), '/personal'), {
      headers: { 'sec-fetch-site': 'same-origin' },
      redirect: 'manual',
    });
    await expectBareProblem(response, 410, 'interaction_expired');
  });
});

describe('[POST /interaction/v1-rc.0/{interactionId}/answer] the answer', () => {
  it('refuses Sec-Fetch-Site: cross-site with 403 forbidden', async () => {
    const response = await post(
      unknownInteractionId(),
      '/answer',
      { 'sec-fetch-site': 'cross-site' },
      ANSWER
    );
    await expectBareProblem(response, 403, 'forbidden');
  });

  it('refuses a body that is neither JSON nor a form post with 415 unsupported_media_type', async () => {
    const response = await post(
      unknownInteractionId(),
      '/answer',
      { 'sec-fetch-site': 'same-origin', 'content-type': 'text/plain' },
      ANSWER
    );
    await expectBareProblem(response, 415, 'unsupported_media_type');
  });

  it('answers a same-origin form post without the flow cookie with 410 interaction_expired', async () => {
    const response = await post(
      unknownInteractionId(),
      '/answer',
      { 'sec-fetch-site': 'same-origin' },
      ANSWER
    );
    await expectBareProblem(response, 410, 'interaction_expired');
  });

  it('answers a CORS preflight from another origin without any CORS header', async () => {
    const response = await fetch(interactionUrl(unknownInteractionId(), '/answer'), {
      method: 'OPTIONS',
      headers: {
        origin: 'https://other.example',
        'access-control-request-method': 'POST',
        'access-control-request-headers': 'content-type',
      },
      redirect: 'manual',
    });
    const cors = [...response.headers.keys()].filter((name) => name.startsWith('access-control-'));
    expect(cors).toEqual([]);
  });
});

describe('[POST /interaction/v1-rc.0/{interactionId}/cancel] the cancel', () => {
  it('refuses Sec-Fetch-Site: cross-site with 403 forbidden', async () => {
    const response = await post(
      unknownInteractionId(),
      '/cancel',
      { 'sec-fetch-site': 'cross-site' },
      'csrf=x'
    );
    await expectBareProblem(response, 403, 'forbidden');
  });

  it('answers a same-origin cancel without the flow cookie with 410 interaction_expired', async () => {
    const response = await post(
      unknownInteractionId(),
      '/cancel',
      { 'sec-fetch-site': 'same-origin' },
      'csrf=x'
    );
    await expectBareProblem(response, 410, 'interaction_expired');
  });
});
