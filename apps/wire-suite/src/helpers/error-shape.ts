import { expect } from 'vitest';

/**
 * The two error formats QAuth answers with (ADR-019 Decision 7, #513), checked
 * from the wire alone:
 *
 * - every route but the OAuth protocol endpoints answers an RFC 9457 problem
 *   details document ({@link expectProblem});
 * - the OAuth protocol endpoints (token, authorization, introspection,
 *   revocation, dynamic registration, userinfo, the wallet-facing OID4VP
 *   endpoints) answer the body their specification defines, RFC 6749 §5.2
 *   ({@link expectOAuthError}).
 *
 * Neither carries a member of the envelope QAuth answered before #513:
 * `error` prose beside a `statusCode`, an upper-case `code`, `message`,
 * `details`, `feedback`.
 */

/** Where QAuth documents its problem types; every `type` starts with it. */
export const PROBLEM_TYPE_BASE = 'https://docs.qauth.dev/reference/problem-types/#';

/** RFC 9457 §3: `application/problem+json`, with or without parameters. */
export const PROBLEM_CONTENT_TYPE = /^application\/problem\+json\s*(?:;|$)/i;

/** `application/json`, with or without parameters. */
const JSON_CONTENT_TYPE = /^application\/json\s*(?:;|$)/i;

/** The members of the pre-#513 envelope; a problem document carries none of them. */
export const LEGACY_ERROR_MEMBERS = ['error', 'statusCode', 'message', 'details', 'feedback'];

/** The members RFC 6749 §5.2 defines for an error body, and the only ones it may carry. */
export const OAUTH_ERROR_MEMBERS = ['error', 'error_description', 'error_uri'];

/** An RFC 9457 problem details document with QAuth's `code` and `trace_id`. */
export interface Problem {
  readonly type: string;
  readonly title: string;
  readonly status: number;
  readonly detail?: string;
  readonly instance?: string;
  readonly code: string;
  readonly trace_id: string;
  readonly errors?: readonly { readonly pointer: string; readonly message: string }[];
  readonly [member: string]: unknown;
}

/** An OAuth error body (RFC 6749 §5.2). */
export interface OAuthError {
  readonly error: string;
  readonly error_description?: string;
  readonly error_uri?: string;
}

export interface ProblemExpectation {
  /** The HTTP status, which `status` in the document must repeat. */
  readonly status: number;
  /** When set, `code` must equal it. */
  readonly code?: string;
}

export interface OAuthErrorExpectation {
  /** The HTTP status. */
  readonly status: number;
  /** When set, `error` must equal it: an RFC 6749 §5.2 (or extension) error code. */
  readonly error?: string;
}

/**
 * Read the body of an error response as a JSON object, after checking the
 * status and the content type. Returns the object and a context line that
 * every failed assertion repeats.
 */
async function readErrorObject(
  response: Response,
  status: number,
  contentType: RegExp
): Promise<{ body: Record<string, unknown>; context: string }> {
  const text = await response.text();
  const context = `${response.status} ${response.url}: ${text.slice(0, 500)}`;

  expect(response.status, context).toBe(status);
  expect(response.headers.get('content-type') ?? '', context).toMatch(contentType);

  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    throw new Error(`error body is not JSON — ${context}`);
  }
  expect(body, context).toBeTypeOf('object');
  expect(body, context).not.toBeNull();
  expect(Array.isArray(body), context).toBe(false);

  const object = body as Record<string, unknown>;
  // A stack trace on the wire is a leak whatever else the body says.
  expect(object, context).not.toHaveProperty('stack');
  return { body: object, context };
}

/**
 * Assert that a response is an RFC 9457 problem document and return it.
 *
 * Checked on every problem: the status, the `application/problem+json`
 * content type (§3), a `type` under {@link PROBLEM_TYPE_BASE} (§3.1.1), a
 * string `title` (§3.1.3), a `status` equal to the HTTP status (§3.1.2), a
 * `code` in lower snake_case, a non-empty `trace_id`, no `stack`, and none of
 * the {@link LEGACY_ERROR_MEMBERS}. Other members are allowed (§3.2).
 */
export async function expectProblem(
  response: Response,
  expectation: ProblemExpectation
): Promise<Problem> {
  const { body, context } = await readErrorObject(
    response,
    expectation.status,
    PROBLEM_CONTENT_TYPE
  );

  expect(body['type'], context).toBeTypeOf('string');
  expect((body['type'] as string).startsWith(PROBLEM_TYPE_BASE), context).toBe(true);
  expect(body['title'], context).toBeTypeOf('string');
  expect(body['status'], context).toBe(expectation.status);
  expect(body['code'], context).toBeTypeOf('string');
  expect(body['code'], context).toMatch(/^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$/);
  expect(body['trace_id'], context).toBeTypeOf('string');
  expect((body['trace_id'] as string).length, context).toBeGreaterThan(0);
  for (const member of LEGACY_ERROR_MEMBERS) {
    expect(body, `${member} — ${context}`).not.toHaveProperty(member);
  }

  if (expectation.code !== undefined) expect(body['code'], context).toBe(expectation.code);

  return body as Problem;
}

/**
 * Assert that a response is an OAuth error body (RFC 6749 §5.2) and return it.
 *
 * Checked on every error: the status, a JSON content type, a non-empty string
 * `error`, a string `error_description` and `error_uri` when present, no
 * member besides those three (so no `statusCode`, `code` or `stack`).
 */
export async function expectOAuthError(
  response: Response,
  expectation: OAuthErrorExpectation
): Promise<OAuthError> {
  const { body, context } = await readErrorObject(response, expectation.status, JSON_CONTENT_TYPE);

  expect(body['error'], context).toBeTypeOf('string');
  expect((body['error'] as string).length, context).toBeGreaterThan(0);
  for (const member of ['error_description', 'error_uri']) {
    if (body[member] !== undefined)
      expect(body[member], `${member} — ${context}`).toBeTypeOf('string');
  }
  for (const member of Object.keys(body)) {
    expect(OAUTH_ERROR_MEMBERS, `unexpected member ${member} — ${context}`).toContain(member);
  }

  if (expectation.error !== undefined) expect(body['error'], context).toBe(expectation.error);

  return body as unknown as OAuthError;
}
