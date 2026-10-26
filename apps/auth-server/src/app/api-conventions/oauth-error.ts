import { z } from 'zod';

import { statusTitle } from './problem';

/**
 * The error shape of the OAuth protocol endpoints (ADR-019 Decision 7, #513):
 * token, authorization, introspection, revocation, dynamic registration,
 * userinfo and the wallet-facing OID4VP endpoints. Their clients and the
 * libraries written to their specifications parse the body those
 * specifications define, so these endpoints answer it instead of a problem
 * document.
 *
 * The body carries only the members RFC 6749 §5.2 defines: `error`, and
 * `error_description` and `error_uri` when there is one. QAuth's own members
 * (`code`, `statusCode`, `feedback`, `retryAfter`) are not sent. The
 * `Retry-After` and `WWW-Authenticate` headers carry what a client acts on.
 */

/**
 * Every `error` value an OAuth protocol endpoint answers with, and the
 * specification that registers it. An error the handler cannot place gets
 * `invalid_request` (4xx), `temporarily_unavailable` (429 and 503) or
 * `server_error` (anything else).
 */
export const OAUTH_ERROR_CODES = {
  invalid_request: 'RFC 6749 §5.2',
  invalid_client: 'RFC 6749 §5.2',
  invalid_grant: 'RFC 6749 §5.2',
  unauthorized_client: 'RFC 6749 §5.2',
  unsupported_grant_type: 'RFC 6749 §5.2',
  invalid_scope: 'RFC 6749 §5.2',
  access_denied: 'RFC 6749 §4.1.2.1',
  server_error: 'RFC 6749 §4.1.2.1',
  temporarily_unavailable: 'RFC 6749 §4.1.2.1',
  invalid_token: 'RFC 6750 §3.1',
  invalid_target: 'RFC 8707 §2.2',
  invalid_client_metadata: 'RFC 7591 §3.2.2',
  invalid_redirect_uri: 'RFC 7591 §3.2.2',
  invalid_dpop_proof: 'RFC 9449 §12.2',
} as const satisfies Record<string, string>;

export type OAuthErrorCode = keyof typeof OAUTH_ERROR_CODES;

/** The id under which the OpenAPI document holds {@link oauthErrorSchema}. */
export const OAUTH_ERROR_SCHEMA_ID = 'OAuthError';

/** The reference every error response of an OAuth protocol endpoint carries. */
export const OAUTH_ERROR_SCHEMA_REF = `#/components/schemas/${OAUTH_ERROR_SCHEMA_ID}`;

/** The media type of an OAuth error body (RFC 6749 §5.2). */
export const OAUTH_ERROR_MEDIA_TYPE = 'application/json';

/**
 * The OAuth error body (RFC 6749 §5.2). `error` is declared with
 * `x-extensible-enum`, not `enum`, for the reason `problemSchema`'s `code` is:
 * an extension may add a value, and a growing response enum is a break to the
 * stable-surface check.
 *
 * Registered under {@link OAUTH_ERROR_SCHEMA_ID}, so a route that uses it gets
 * a `$ref` to one shared component instead of a copy.
 *
 * A loose object: the published schema does not refuse members it does not
 * name (no `additionalProperties: false`). RFC 6749 §5.2 lets an extension
 * add response parameters and a client ignores those it does not know; QAuth
 * itself sends only these three (`plugins/error-handler.ts`).
 */
export const oauthErrorSchema = z
  .looseObject({
    error: z.string().meta({ 'x-extensible-enum': Object.keys(OAUTH_ERROR_CODES) }),
    error_description: z.string().optional(),
    error_uri: z.string().optional(),
  })
  .meta({
    id: OAUTH_ERROR_SCHEMA_ID,
    description: 'An OAuth error (RFC 6749 §5.2). Branch on `error`, never on `error_description`.',
  });

export type OAuthErrorBody = z.infer<typeof oauthErrorSchema>;

/**
 * The `response` entries for the error statuses an OAuth protocol endpoint
 * declares, each one `application/json` with the shared
 * {@link oauthErrorSchema}:
 *
 * ```ts
 * schema: { response: { 200: tokenResponseSchema, ...oauthErrorResponses(400, 401, 503) } }
 * ```
 *
 * The content-type form selects the serializer, as `problemResponses` does:
 * Fastify serializes an `application/json` error body with this schema, which
 * drops any member the schema does not list.
 */
export function oauthErrorResponses<const Statuses extends readonly number[]>(
  ...statuses: Statuses
) {
  const entries = statuses.map((status) => [
    status,
    {
      description: statusTitle(status),
      content: { [OAUTH_ERROR_MEDIA_TYPE]: { schema: oauthErrorSchema } },
    },
  ]);
  return Object.fromEntries(entries) as Record<
    Statuses[number],
    {
      description: string;
      content: { [OAUTH_ERROR_MEDIA_TYPE]: { schema: typeof oauthErrorSchema } };
    }
  >;
}
