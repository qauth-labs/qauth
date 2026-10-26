import { randomUUID } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { serverPath, wireConfig } from '../../config';
import { expectProblem } from '../../helpers/error-shape';

const { baseUrl } = wireConfig();

describe('RFC 9457 §3 — the problem document on an unknown route', () => {
  it.each(['GET', 'POST', 'DELETE'])(
    'answers %s on a route that does not exist with a 404 not_found problem (§3.1)',
    async (method) => {
      const response = await fetch(
        serverPath(baseUrl, `/wire-suite/no-such-route/${randomUUID()}`),
        {
          method,
          redirect: 'manual',
          ...(method === 'POST'
            ? { headers: { 'content-type': 'application/json' }, body: '{}' }
            : {}),
        }
      );

      const problem = await expectProblem(response, { status: 404, code: 'not_found' });
      expect(problem).not.toHaveProperty('statusCode');
    }
  );
});
