import { randomUUID } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { serverPath, wireConfig } from '../../config';
import {
  EXPERIMENTAL_DISCOVERY_MEMBERS,
  EXPERIMENTAL_OPERATIONS,
} from '../../fixtures/experimental';
import { expectProblem } from '../../helpers/error-shape';
import { getJsonObject } from '../../helpers/http';

/**
 * An experimental item sits behind a switch that is off by default, and
 * discovery does not mention it until the switch is on (ADR-018 §5, #477). CI
 * runs this suite against a server with every switch at its default, so each
 * experimental operation is a route that does not exist, and no discovery
 * document names a member an experimental item adds.
 *
 * The lists come from `src/fixtures/experimental.ts`, which the auth server's
 * tests generate from the maximal OpenAPI export and the experimental-feature
 * registry.
 */

const { baseUrl } = wireConfig();

const DISCOVERY_DOCUMENTS = [
  '/.well-known/oauth-authorization-server',
  '/.well-known/openid-configuration',
];

/** A request path for an OpenAPI path template: each `{parameter}` gets a fresh value. */
function concretePath(template: string): string {
  return template.replace(/\{[^}]+\}/g, () => `wire-suite-${randomUUID()}`);
}

/**
 * How the server answers `method` at `path`, as a `404` problem document,
 * with the path itself replaced and the `trace_id` left out (it names the
 * request, so it differs on every answer) so that the answers at two paths
 * compare.
 */
async function notFoundAnswer(method: string, path: string): Promise<unknown> {
  const response = await fetch(serverPath(baseUrl, path), {
    method,
    redirect: 'manual',
    ...(method === 'GET' || method === 'HEAD'
      ? {}
      : { headers: { 'content-type': 'application/json' }, body: '{}' }),
  });
  const problem = await expectProblem(response, { status: 404, code: 'not_found' });
  const body: Record<string, unknown> = { ...problem };
  delete body['trace_id'];
  return JSON.parse(JSON.stringify(body).replaceAll(path, '<path>'));
}

describe('experimental items on a default deployment', () => {
  it('has experimental operations and discovery members to check', () => {
    expect(EXPERIMENTAL_OPERATIONS).toContain('POST /oid4vp/response');
    expect(EXPERIMENTAL_DISCOVERY_MEMBERS.length).toBeGreaterThan(0);
  });

  // A registered route may answer 404 too, for an unknown handle, so the
  // answer must be the one a path that does not exist gets.
  it.each(EXPERIMENTAL_OPERATIONS.map((operation) => operation.split(' ')))(
    'answers %s %s with 404, as a route that does not exist',
    async (method, template) => {
      const answer = await notFoundAnswer(method, concretePath(template));
      const unknownRoute = await notFoundAnswer(
        method,
        `/wire-suite/no-such-route/${randomUUID()}`
      );

      expect(answer).toEqual(unknownRoute);
    }
  );

  it.each(DISCOVERY_DOCUMENTS)('lists no member of an experimental item at %s', async (path) => {
    const { body } = await getJsonObject(serverPath(baseUrl, path));

    for (const member of EXPERIMENTAL_DISCOVERY_MEMBERS) {
      expect(Object.keys(body), member).not.toContain(member);
    }
  });
});
