import { STATUS_CODES } from 'node:http';

import { z } from 'zod';

/**
 * RFC 9457 problem details: the error format of the admin, account and
 * developer APIs and of every other route that is not an OAuth protocol
 * endpoint (ADR-019 Decision 7, ADR-018 §5; #506, #513).
 *
 * This module holds the parts every such route shares: the media type, the
 * `Problem` schema the OpenAPI document references, the published `code`
 * values with their problem types, and the helper a route schema uses to
 * declare its error responses. `error-classes.ts` maps each domain error class
 * to its code, and the error handler (`plugins/error-handler.ts`) builds the
 * documents. The OAuth protocol endpoints answer `oauth-error.ts`'s shape.
 */

/** RFC 9457 §3: the media type of a problem details document in JSON. */
export const PROBLEM_MEDIA_TYPE = 'application/problem+json';

/**
 * Where the problem types are documented: one heading per type on the docs
 * site's problem types page. A document's `type` is this base followed by the
 * type's slug, `https://docs.qauth.dev/reference/problem-types/#not-found`, so
 * a person who reads one in a log can open it (RFC 9457 §3.1.1). A client never
 * dereferences it, and branches on `code`.
 */
export const PROBLEM_TYPE_BASE = 'https://docs.qauth.dev/reference/problem-types/#';

/**
 * One published `code`: the status it is sent with, its problem type's slug
 * and title, and what it means.
 *
 * The `title` is the problem type's own (RFC 9457 §3.1.3): it names the type,
 * not the occurrence, so every document with this code carries the same one.
 * The `detail` of a document says what went wrong in this request.
 */
export interface ProblemCodeEntry {
  readonly status: number;
  readonly type: string;
  readonly title: string;
  readonly description: string;
}

/**
 * Every `code` a problem document can carry, with the status it is sent with
 * and its problem type.
 *
 * The values are part of the 1.0 stability promise (ADR-018 §5): a code keeps
 * its meaning within a major version and a minor release may add codes, so a
 * client treats a code it does not know by its HTTP status. The same holds for
 * each type's slug. The error handler sends no other value: an error whose
 * class the registry (`error-classes.ts`) does not list is sent with the code
 * of its status ({@link codeForStatus}). The docs site publishes this table on
 * `reference/problem-types.md`, and a test keeps the page equal to it.
 */
export const PROBLEM_CODES = {
  bad_request: {
    status: 400,
    type: 'bad-request',
    title: 'Bad request',
    description: 'The request is malformed and no more specific code applies.',
  },
  validation_error: {
    status: 400,
    type: 'validation-error',
    title: 'Validation error',
    description:
      'The request does not match the schema of the operation. `errors` names each field.',
  },
  invalid_request: {
    status: 400,
    type: 'invalid-request',
    title: 'Invalid request',
    description:
      'A parameter of an OAuth or OpenID request is missing, repeated or not valid (RFC 6749 §5.2).',
  },
  invalid_scope: {
    status: 400,
    type: 'invalid-scope',
    title: 'Invalid scope',
    description: 'A requested scope is unknown, malformed or not allowed (RFC 6749 §5.2).',
  },
  invalid_grant: {
    status: 400,
    type: 'invalid-grant',
    title: 'Invalid grant',
    description:
      'An authorization grant or refresh token is not valid, has expired or was issued to another client (RFC 6749 §5.2).',
  },
  invalid_target: {
    status: 400,
    type: 'invalid-target',
    title: 'Invalid target',
    description: 'A requested `resource` is not one the grant allows (RFC 8707 §2.2).',
  },
  unauthorized_client: {
    status: 400,
    type: 'unauthorized-client',
    title: 'Unauthorized client',
    description: 'The client may not use this grant or this response type (RFC 6749 §5.2).',
  },
  unsupported_grant_type: {
    status: 400,
    type: 'unsupported-grant-type',
    title: 'Unsupported grant type',
    description: 'The server does not support the `grant_type` (RFC 6749 §5.2).',
  },
  invalid_client_metadata: {
    status: 400,
    type: 'invalid-client-metadata',
    title: 'Invalid client metadata',
    description: 'A client metadata value is not valid or not allowed (RFC 7591 §3.2.2).',
  },
  invalid_redirect_uri: {
    status: 400,
    type: 'invalid-redirect-uri',
    title: 'Invalid redirect URI',
    description: 'A redirect URI is not valid or not allowed (RFC 7591 §3.2.2).',
  },
  invalid_cursor: {
    status: 400,
    type: 'invalid-cursor',
    title: 'Invalid cursor',
    description: 'The `cursor` does not parse, or it belongs to another list.',
  },
  invalid_token: {
    status: 400,
    type: 'invalid-token',
    title: 'Invalid token',
    description:
      'A one-time token in the request, such as an email verification token, is not valid.',
  },
  invalid_csrf_token: {
    status: 400,
    type: 'invalid-csrf-token',
    title: 'Invalid CSRF token',
    description:
      "A cookie-authenticated request that changes state carries no CSRF token, or not the browser session's.",
  },
  unauthorized: {
    status: 401,
    type: 'unauthorized',
    title: 'Unauthorized',
    description: 'The request carries no valid credentials.',
  },
  jwt_expired: {
    status: 401,
    type: 'jwt-expired',
    title: 'Access token expired',
    description: 'The access token has expired.',
  },
  jwt_invalid: {
    status: 401,
    type: 'jwt-invalid',
    title: 'Access token not valid',
    description:
      'The access token is not valid, is not valid for this operation, or names no active user.',
  },
  invalid_credentials: {
    status: 401,
    type: 'invalid-credentials',
    title: 'Invalid credentials',
    description: 'The identifier or the credential is wrong. The answer does not say which.',
  },
  invalid_client: {
    status: 401,
    type: 'invalid-client',
    title: 'Invalid client',
    description: 'Client authentication failed (RFC 6749 §5.2).',
  },
  invalid_dpop_proof: {
    status: 401,
    type: 'invalid-dpop-proof',
    title: 'Invalid DPoP proof',
    description: 'The DPoP proof is missing or not valid for this request (RFC 9449 §7.1).',
  },
  forbidden: {
    status: 403,
    type: 'forbidden',
    title: 'Forbidden',
    description: 'The caller is authenticated but may not perform the operation.',
  },
  email_not_verified: {
    status: 403,
    type: 'email-not-verified',
    title: 'Email address not verified',
    description: 'The account must verify its email address first.',
  },
  not_found: {
    status: 404,
    type: 'not-found',
    title: 'Not found',
    description: 'The resource does not exist, or the caller may not know that it exists.',
  },
  method_not_allowed: {
    status: 405,
    type: 'method-not-allowed',
    title: 'Method not allowed',
    description: 'The resource does not support the method.',
  },
  conflict: {
    status: 409,
    type: 'conflict',
    title: 'Conflict',
    description: 'The request conflicts with the current state of the resource.',
  },
  unique_constraint_violation: {
    status: 409,
    type: 'unique-constraint-violation',
    title: 'Resource already exists',
    description: 'A resource with the same unique value already exists.',
  },
  email_already_verified: {
    status: 409,
    type: 'email-already-verified',
    title: 'Email address already verified',
    description: 'The email address is already verified.',
  },
  token_already_used: {
    status: 409,
    type: 'token-already-used',
    title: 'Token already used',
    description: 'The one-time token has already been used.',
  },
  token_expired: {
    status: 410,
    type: 'token-expired',
    title: 'Token expired',
    description: 'The one-time token has expired.',
  },
  request_timeout: {
    status: 408,
    type: 'request-timeout',
    title: 'Request timeout',
    description: 'The request did not arrive whole within the time the server waits for it.',
  },
  precondition_failed: {
    status: 412,
    type: 'precondition-failed',
    title: 'Precondition failed',
    description: 'The `If-Match` value does not match the current `ETag` of the resource.',
  },
  content_too_large: {
    status: 413,
    type: 'content-too-large',
    title: 'Content too large',
    description: 'The request body is larger than the server accepts.',
  },
  uri_too_long: {
    status: 414,
    type: 'uri-too-long',
    title: 'URI too long',
    description: 'A segment of the request path is longer than the server accepts.',
  },
  unsupported_media_type: {
    status: 415,
    type: 'unsupported-media-type',
    title: 'Unsupported media type',
    description: 'The media type of the request body is not one the operation accepts.',
  },
  misdirected_request: {
    status: 421,
    type: 'misdirected-request',
    title: 'Misdirected request',
    description:
      'The server does not answer for the host the request names, or not for this operation on that host.',
  },
  unprocessable_content: {
    status: 422,
    type: 'unprocessable-content',
    title: 'Unprocessable content',
    description:
      'The request is well formed, but its content cannot be applied, such as a merge patch whose result fails the schema of the resource.',
  },
  weak_password: {
    status: 422,
    type: 'weak-password',
    title: 'Weak password',
    description: 'The new password is too weak. `errors` carries the feedback under `/password`.',
  },
  precondition_required: {
    status: 428,
    type: 'precondition-required',
    title: 'Precondition required',
    description: 'The update needs an `If-Match` header.',
  },
  too_many_requests: {
    status: 429,
    type: 'too-many-requests',
    title: 'Too many requests',
    description:
      'The caller has sent too many requests. `Retry-After`, when present, says when to try again.',
  },
  request_header_fields_too_large: {
    status: 431,
    type: 'request-header-fields-too-large',
    title: 'Request header fields too large',
    description: 'The request headers are larger than the server accepts.',
  },
  internal_error: {
    status: 500,
    type: 'internal-error',
    title: 'Internal error',
    description: 'The server failed. `trace_id` finds the failure in the server log.',
  },
  service_unavailable: {
    status: 503,
    type: 'service-unavailable',
    title: 'Service unavailable',
    description:
      'The server cannot answer now, for example while a dependency is down or it is too busy. `Retry-After`, when present, says when to try again.',
  },
} as const satisfies Record<string, ProblemCodeEntry>;

export type ProblemCode = keyof typeof PROBLEM_CODES;

/** The `type` URI of a published code: {@link PROBLEM_TYPE_BASE} and its slug. */
export function problemTypeUri(code: ProblemCode): string {
  return `${PROBLEM_TYPE_BASE}${PROBLEM_CODES[code].type}`;
}

/** The code a status gets when the error carries no published code of its own. */
const STATUS_FALLBACK_CODES: Readonly<Record<number, ProblemCode>> = {
  400: 'bad_request',
  401: 'unauthorized',
  403: 'forbidden',
  404: 'not_found',
  405: 'method_not_allowed',
  408: 'request_timeout',
  409: 'conflict',
  412: 'precondition_failed',
  413: 'content_too_large',
  414: 'uri_too_long',
  415: 'unsupported_media_type',
  421: 'misdirected_request',
  422: 'unprocessable_content',
  428: 'precondition_required',
  429: 'too_many_requests',
  431: 'request_header_fields_too_large',
  500: 'internal_error',
  503: 'service_unavailable',
};

/** Whether `value` is a published {@link ProblemCode}. */
export function isProblemCode(value: unknown): value is ProblemCode {
  return typeof value === 'string' && Object.hasOwn(PROBLEM_CODES, value);
}

/**
 * The published code for a status: its own entry, else `bad_request` for any
 * other 4xx and `internal_error` for anything else.
 */
export function codeForStatus(status: number): ProblemCode {
  return (
    STATUS_FALLBACK_CODES[status] ??
    (status >= 400 && status < 500 ? 'bad_request' : 'internal_error')
  );
}

/**
 * The code a problem document carries for an error the registry does not
 * list: the error's own `code`, in lower case, when it is published for this
 * status, else the code of the status. A framework code (`FST_ERR_*`) or an
 * internal one never reaches the wire.
 */
export function problemCodeFor(errorCode: unknown, status: number): ProblemCode {
  const code = typeof errorCode === 'string' ? errorCode.toLowerCase() : errorCode;
  if (isProblemCode(code) && PROBLEM_CODES[code].status === status) return code;
  return codeForStatus(status);
}

/** The id under which the OpenAPI document holds {@link problemSchema}. */
export const PROBLEM_SCHEMA_ID = 'Problem';

/** The reference every error response of a family operation carries. */
export const PROBLEM_SCHEMA_REF = `#/components/schemas/${PROBLEM_SCHEMA_ID}`;

/**
 * One field the request got wrong. `pointer` is an RFC 6901 JSON Pointer into
 * the part of the request that failed: the body, or the object of query or
 * path parameters (`/limit`).
 */
export const problemFieldErrorSchema = z.object({
  pointer: z.string(),
  message: z.string(),
});

/**
 * The problem details document (RFC 9457 §3) with QAuth's two extension
 * members, `code` and `trace_id` (ADR-019 Decision 7).
 *
 * `trace_id` is the one snake_case member outside the OAuth and OIDC names:
 * ADR-019 fixed its name. `code` is declared with `x-extensible-enum`, not
 * `enum`, because the list grows in minor releases and a response enum that
 * grows is a break to the stable-surface check (`stable-surface/README.md`).
 *
 * Registered under {@link PROBLEM_SCHEMA_ID}, so a route that uses it gets a
 * `$ref` to one shared component instead of a copy (see `openapi-options.ts`).
 */
export const problemSchema = z
  .object({
    type: z.string().meta({
      description: `The problem type: \`${PROBLEM_TYPE_BASE}\` followed by the type's slug.`,
    }),
    title: z.string(),
    status: z.int().min(400).max(599),
    detail: z.string().optional(),
    instance: z.string().optional(),
    code: z.string().meta({ 'x-extensible-enum': Object.keys(PROBLEM_CODES) }),
    trace_id: z.string(),
    errors: z.array(problemFieldErrorSchema).optional(),
  })
  .meta({
    id: PROBLEM_SCHEMA_ID,
    description:
      'RFC 9457 problem details. Branch on `code`, never on `title` or `detail`. `trace_id` is the id the server logged the request under. `errors` lists each field the request got wrong.',
  });

export type ProblemDocument = z.infer<typeof problemSchema>;

/** The status phrase of RFC 9110 §15 for `status`, as `title` and as a response description. */
export function statusTitle(status: number): string {
  return STATUS_CODES[status] ?? 'Error';
}

/**
 * The `response` entries for the error statuses an operation declares, each
 * one `application/problem+json` with the shared {@link problemSchema}:
 *
 * ```ts
 * schema: { response: { 200: realmSchema, ...problemResponses(401, 403, 404) } }
 * ```
 *
 * The content-type form also selects the serializer: the error handler sets
 * `Content-Type: application/problem+json`, and Fastify serializes the body
 * with the schema declared for that status and media type.
 */
export function problemResponses<const Statuses extends readonly number[]>(...statuses: Statuses) {
  const entries = statuses.map((status) => [
    status,
    {
      description: statusTitle(status),
      content: { [PROBLEM_MEDIA_TYPE]: { schema: problemSchema } },
    },
  ]);
  return Object.fromEntries(entries) as Record<
    Statuses[number],
    {
      description: string;
      content: { [PROBLEM_MEDIA_TYPE]: { schema: typeof problemSchema } };
    }
  >;
}
