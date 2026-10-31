import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';

import {
  deprecationFieldValue,
  DEPRECATIONS_PAGE_URL,
  LEGACY_ACCOUNT_DEVELOPER_PATHS_DEPRECATED_AT,
  sendDeprecationHeaders,
} from './deprecation';

describe('deprecated operations (#524)', () => {
  it('writes the date as an RFC 9651 Date, as RFC 9745 §2.1 requires', () => {
    expect(deprecationFieldValue('2026-10-31T00:00:00Z')).toBe('@1793404800');
    expect(deprecationFieldValue(LEGACY_ACCOUNT_DEVELOPER_PATHS_DEPRECATED_AT)).toBe('@1793404800');
    expect(() => deprecationFieldValue('yesterday')).toThrow();
  });

  it('sends Deprecation and its Link on every answer of the scope, errors included', async () => {
    const app = Fastify();
    await app.register(async (scope) => {
      sendDeprecationHeaders(scope);
      scope.get('/old', async () => ({ ok: true }));
      scope.get('/old-failing', async () => {
        throw Object.assign(new Error('nope'), { statusCode: 404 });
      });
    });
    app.get('/new', async () => ({ ok: true }));

    for (const url of ['/old', '/old-failing']) {
      const response = await app.inject({ method: 'GET', url });
      expect(response.headers['deprecation'], url).toBe('@1793404800');
      expect(response.headers['link'], url).toBe(
        `<${DEPRECATIONS_PAGE_URL}>; rel="deprecation"; type="text/html"`
      );
    }
    const fresh = await app.inject({ method: 'GET', url: '/new' });
    expect(fresh.headers['deprecation']).toBeUndefined();
    await app.close();
  });
});
