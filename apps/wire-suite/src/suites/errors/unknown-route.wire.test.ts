import { randomUUID } from 'node:crypto';

import { describe, it } from 'vitest';

import { serverPath, wireConfig } from '../../config';
import { expectStandardError } from '../../helpers/error-shape';

const { baseUrl } = wireConfig();

describe('the standard JSON error on an unknown route', () => {
  it.each(['GET', 'POST', 'DELETE'])(
    'answers %s on a route that does not exist with 404',
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

      await expectStandardError(response, { status: 404 });
    }
  );
});
