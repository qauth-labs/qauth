import { STATUS_CODES } from 'node:http';

import { z } from 'zod';

/**
 * RFC 9457 problem details: the error format of the admin, account and
 * developer APIs and of every other route that is not an OAuth protocol
 * endpoint (ADR-019 Decision 7, ADR-018 §5; #506).
 *
 * This module holds the parts every such route shares: the media type, the
 * `Problem` schema the OpenAPI document references, the published `code`
 * values and the helper a route schema uses to declare its error responses.
 * The error handler (`plugins/error-handler.ts`) builds the documents.
 */

/** RFC 9457 §3: the media type of a problem details document in JSON. */
export const PROBLEM_MEDIA_TYPE = 'application/problem+json';

/**
 * RFC 9457 §4.2.1: the problem type that adds nothing to the HTTP status. Every
 * problem document uses it today, so `title` is the status phrase. A code may
 * get its own type URI later. That is an addition, so a client branches on
 * `code` and never on `type`.
 */
export const DEFAULT_PROBLEM_TYPE = 'about:blank';

/** One published `code`: the status it is sent with, and what it means. */
export interface ProblemCodeEntry {
  readonly status: number;
  readonly description: string;
}

/**
 * Every `code` a problem document can carry, with the status it is sent with.
 *
 * The values are part of the 1.0 stability promise (ADR-018 §5): a code keeps
 * its meaning within a major version and a minor release may add codes, so a
 * client treats a code it does not know by its HTTP status. The error handler
 * sends no other value: an error whose own `code` is missing here, or listed
 * with another status, is sent with the code of its status
 * ({@link codeForStatus}). The docs site publishes this table on
 * `reference/api-conventions.md`, and a test keeps the page equal to it.
 */
export const PROBLEM_CODES = {
  bad_request: {
    status: 400,
    description: 'The request is malformed and no more specific code applies.',
  },
  validation_error: {
    status: 400,
    description:
      'The request does not match the schema of the operation. `errors` names each field.',
  },
  invalid_cursor: {
    status: 400,
    description: 'The `cursor` does not parse, or it belongs to another list.',
  },
  invalid_token: {
    status: 400,
    description:
      'A one-time token in the request, such as an email verification token, is not valid.',
  },
  unauthorized: {
    status: 401,
    description: 'The request carries no valid credentials.',
  },
  jwt_expired: {
    status: 401,
    description: 'The access token has expired.',
  },
  jwt_invalid: {
    status: 401,
    description: 'The access token is not valid.',
  },
  invalid_credentials: {
    status: 401,
    description: 'The identifier or the credential is wrong. The answer does not say which.',
  },
  forbidden: {
    status: 403,
    description: 'The caller is authenticated but may not perform the operation.',
  },
  email_not_verified: {
    status: 403,
    description: 'The account must verify its email address first.',
  },
  not_found: {
    status: 404,
    description: 'The resource does not exist, or the caller may not know that it exists.',
  },
  method_not_allowed: {
    status: 405,
    description: 'The resource does not support the method.',
  },
  conflict: {
    status: 409,
    description: 'The request conflicts with the current state of the resource.',
  },
  unique_constraint_violation: {
    status: 409,
    description: 'A resource with the same unique value already exists.',
  },
  email_already_verified: {
    status: 409,
    description: 'The email address is already verified.',
  },
  token_already_used: {
    status: 409,
    description: 'The one-time token has already been used.',
  },
  token_expired: {
    status: 410,
    description: 'The one-time token has expired.',
  },
  precondition_failed: {
    status: 412,
    description: 'The `If-Match` value does not match the current `ETag` of the resource.',
  },
  content_too_large: {
    status: 413,
    description: 'The request body is larger than the server accepts.',
  },
  unsupported_media_type: {
    status: 415,
    description: 'The media type of the request body is not one the operation accepts.',
  },
  misdirected_request: {
    status: 421,
    description:
      'The server does not answer for the host the request names, or not for this operation on that host.',
  },
  unprocessable_content: {
    status: 422,
    description:
      'The request is well formed, but its content cannot be applied, such as a merge patch whose result fails the schema of the resource.',
  },
  weak_password: {
    status: 422,
    description: 'The new password is too weak. `errors` carries the feedback under `/password`.',
  },
  precondition_required: {
    status: 428,
    description: 'The update needs an `If-Match` header.',
  },
  too_many_requests: {
    status: 429,
    description: 'The caller has sent too many requests. `Retry-After` says when to try again.',
  },
  internal_error: {
    status: 500,
    description: 'The server failed. `trace_id` finds the failure in the server log.',
  },
  service_unavailable: {
    status: 503,
    description: 'The server cannot answer now, for example while a dependency is down.',
  },
} as const satisfies Record<string, ProblemCodeEntry>;

export type ProblemCode = keyof typeof PROBLEM_CODES;

/** The code a status gets when the error carries no published code of its own. */
const STATUS_FALLBACK_CODES: Readonly<Record<number, ProblemCode>> = {
  400: 'bad_request',
  401: 'unauthorized',
  403: 'forbidden',
  404: 'not_found',
  405: 'method_not_allowed',
  409: 'conflict',
  412: 'precondition_failed',
  413: 'content_too_large',
  415: 'unsupported_media_type',
  421: 'misdirected_request',
  422: 'unprocessable_content',
  428: 'precondition_required',
  429: 'too_many_requests',
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
 * The code a problem document carries: the error's own `code`, in lower case,
 * when it is published for this status, else the code of the status. The
 * error classes of `@qauth-labs/shared-errors` name their codes in upper case
 * for the earlier body; a problem document names them in lower case. A
 * framework code (`FST_ERR_*`) or an internal one never reaches the wire.
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
    type: z.string(),
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
      'RFC 9457 problem details. Branch on `code`, never on `title` or `detail`. `trace_id` is the id the server logged the request under.',
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
