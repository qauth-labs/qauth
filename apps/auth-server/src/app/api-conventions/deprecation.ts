import type { FastifyInstance } from 'fastify';

/**
 * Deprecated operations (#506, #524): the API conventions page's
 * Deprecations section. A deprecated operation carries `deprecated: true` in
 * the OpenAPI document, and each of its responses, errors included, the
 * `Deprecation` header of RFC 9745 with the date it was deprecated, and a
 * `Link` to the page that names its replacement (RFC 9745 §3). A `Sunset`
 * header (RFC 8594) is added once a removal date exists.
 */

/**
 * When the account and developer routes outside the API families were
 * deprecated (#524): `/api/clients`, `/api/consents` and the cookie
 * `/consents`. The conventions page's Deprecations table lists them.
 */
export const LEGACY_ACCOUNT_DEVELOPER_PATHS_DEPRECATED_AT = '2026-10-31T00:00:00Z';

/** Where a deprecated operation's replacement is named. */
export const DEPRECATIONS_PAGE_URL =
  'https://docs.qauth.dev/reference/api-conventions/#deprecations';

/**
 * The `Deprecation` field value for an RFC 3339 date (RFC 9745 §2.1): an RFC
 * 9651 Date, `@` and the seconds since the epoch.
 */
export function deprecationFieldValue(deprecatedAt: string): string {
  const ms = Date.parse(deprecatedAt);
  if (Number.isNaN(ms)) {
    throw new Error(`Not an RFC 3339 date: ${deprecatedAt}`);
  }
  return `@${Math.floor(ms / 1000)}`;
}

/**
 * Send the `Deprecation` header and its `Link` on every response of every
 * route the encapsulated `fastify` registers, errors included: an `onSend`
 * hook, which runs whatever path the reply took.
 *
 * The route schemas carry `deprecated: true` themselves, so the OpenAPI
 * document says it too.
 */
export function sendDeprecationHeaders(
  fastify: FastifyInstance,
  deprecatedAt: string = LEGACY_ACCOUNT_DEVELOPER_PATHS_DEPRECATED_AT
): void {
  const deprecation = deprecationFieldValue(deprecatedAt);
  const link = `<${DEPRECATIONS_PAGE_URL}>; rel="deprecation"; type="text/html"`;
  fastify.addHook('onSend', async (_request, reply, payload) => {
    reply.header('deprecation', deprecation);
    reply.header('link', link);
    return payload;
  });
}
