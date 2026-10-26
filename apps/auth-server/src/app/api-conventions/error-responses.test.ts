/// <reference types="vitest/globals" />
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { OAUTH_ERROR_MEDIA_TYPE, OAUTH_ERROR_SCHEMA_REF } from './oauth-error';
import { PROBLEM_MEDIA_TYPE, PROBLEM_SCHEMA_REF } from './problem';

/**
 * EVERY ERROR RESPONSE IN THE OPENAPI DOCUMENT NAMES ITS FORMAT (#513).
 *
 * The OAuth protocol endpoints answer an error with the `OAuthError` schema,
 * as `application/json`; every other operation with the `Problem` schema, as
 * `application/problem+json`. Read over the committed documents, the default
 * one and the maximal one, which CI's stable-surface check regenerates and
 * compares, so this reads what the server serves.
 */

const ROOT = join(__dirname, '..', '..', '..', '..', '..');

const DOCUMENTS = {
  default: join(ROOT, 'stable-surface', 'openapi.json'),
  maximal: join(ROOT, 'apps', 'docs-site', 'public', 'openapi.json'),
};

/** The OAuth protocol endpoints, as the document names them (`route-surfaces.test.ts`). */
const OAUTH_PROTOCOL_ENDPOINTS = new Set([
  'GET /oauth/authorize',
  'POST /oauth/authorize',
  'POST /oauth/token',
  'POST /oauth/introspect',
  'POST /oauth/revoke',
  'POST /oauth/register',
  'GET /oauth/userinfo',
  'POST /oauth/userinfo',
  'GET /oid4vp/request/{handle}',
  'POST /oid4vp/response',
]);

interface Operation {
  responses?: Record<string, { content?: Record<string, { schema?: unknown }> }>;
}

function operationsOf(path: string): [string, Operation][] {
  const document = JSON.parse(readFileSync(path, 'utf8')) as {
    paths: Record<string, Record<string, Operation>>;
  };
  return Object.entries(document.paths).flatMap(([url, item]) =>
    Object.entries(item).map(
      ([method, operation]) => [`${method.toUpperCase()} ${url}`, operation] as [string, Operation]
    )
  );
}

describe.each(Object.entries(DOCUMENTS))(
  'error responses of the %s OpenAPI document (#513)',
  (_name, path) => {
    const operations = operationsOf(path);

    it('has operations to check', () => {
      expect(operations.length).toBeGreaterThan(30);
    });

    it('declares every error response with the schema of its route', () => {
      const wrong: string[] = [];
      for (const [operation, { responses = {} }] of operations) {
        const expected = OAUTH_PROTOCOL_ENDPOINTS.has(operation)
          ? { [OAUTH_ERROR_MEDIA_TYPE]: { schema: { $ref: OAUTH_ERROR_SCHEMA_REF } } }
          : { [PROBLEM_MEDIA_TYPE]: { schema: { $ref: PROBLEM_SCHEMA_REF } } };
        for (const [status, response] of Object.entries(responses)) {
          if (Number(status) < 400) continue;
          if (JSON.stringify(response.content) !== JSON.stringify(expected)) {
            wrong.push(`${operation} ${status}`);
          }
        }
      }
      expect(wrong).toEqual([]);
    });

    it('lists 421 and 500 on every operation of a realm', () => {
      for (const [operation, { responses = {} }] of operations) {
        if (operation === 'GET /health') continue;
        expect(Object.keys(responses), operation).toContain('500');
        expect(Object.keys(responses), operation).toContain('421');
      }
    });
  }
);

/**
 * The routes #866 met after it branched list the statuses they answer by
 * design (`x-qauth-errors`), each a problem document: the SSF transmitter's
 * (SSF 1.0 §8.1 defines no error body) and the cookie-authenticated consent
 * routes, whose 401 is the `unauthorized` problem like any other route's.
 */
describe('by-design error statuses in the maximal OpenAPI document (#513)', () => {
  const operations = new Map(operationsOf(DOCUMENTS.maximal));

  it.each([
    ['GET /.well-known/ssf-configuration', ['404']],
    ['GET /ssf/jwks.json', ['404']],
    ['POST /ssf/stream', ['400', '401', '403', '404', '409']],
    ['GET /ssf/stream', ['400', '401', '403', '404']],
    ['PATCH /ssf/stream', ['400', '401', '403', '404']],
    ['PUT /ssf/stream', ['400', '401', '403', '404']],
    ['DELETE /ssf/stream', ['400', '401', '403', '404']],
    ['GET /ssf/status', ['400', '401', '403', '404']],
    ['POST /ssf/status', ['400', '401', '403', '404']],
    ['POST /ssf/subjects/add', ['400', '401', '403', '404']],
    ['POST /ssf/subjects/remove', ['400', '401', '403', '404']],
    ['POST /ssf/verify', ['400', '401', '403', '404', '429']],
    ['GET /consents/', ['401']],
    ['DELETE /consents/{id}', ['400', '401', '404']],
  ])('lists what %s answers by design', (operation, statuses) => {
    const responses = operations.get(operation)?.responses;

    expect(responses, operation).toBeDefined();
    expect(Object.keys(responses ?? {})).toEqual(expect.arrayContaining(statuses));
  });
});
