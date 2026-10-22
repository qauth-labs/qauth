import { expect } from 'vitest';

/**
 * The error envelope every QAuth route answers with (the "Error model" in the
 * API reference): `{ error, statusCode, code? }`, plus `error_description` on
 * OAuth endpoints and `details` on validation failures.
 */
export interface StandardError {
  readonly error: string;
  readonly statusCode: number;
  readonly code?: string;
  readonly error_description?: string;
  readonly [member: string]: unknown;
}

export interface ErrorExpectation {
  /** The HTTP status, which `statusCode` in the body must repeat. */
  readonly status: number;
  /** When set, `error` must equal it — e.g. an RFC 6749 §5.2 error code. */
  readonly error?: string;
  /** When set, `code` must equal it. */
  readonly code?: string;
}

/**
 * Assert that a response is the standard JSON error and return its body.
 *
 * Checked on every error: the status, a JSON content type, a non-empty string
 * `error`, a `statusCode` equal to the HTTP status, a `code` in UPPER_SNAKE
 * form when present, and no `stack` — a stack trace on the wire is a leak
 * whatever else the body says. Other members are allowed.
 */
export async function expectStandardError(
  response: Response,
  expectation: ErrorExpectation
): Promise<StandardError> {
  const text = await response.text();
  const context = `${response.status} ${response.url}: ${text.slice(0, 500)}`;

  expect(response.status, context).toBe(expectation.status);
  expect(response.headers.get('content-type') ?? '', context).toMatch(/^application\/json\b/i);

  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    throw new Error(`error body is not JSON — ${context}`);
  }
  expect(body, context).toBeTypeOf('object');
  expect(body, context).not.toBeNull();
  expect(Array.isArray(body), context).toBe(false);

  const envelope = body as Record<string, unknown>;
  expect(envelope['error'], context).toBeTypeOf('string');
  expect((envelope['error'] as string).length, context).toBeGreaterThan(0);
  expect(envelope['statusCode'], context).toBe(expectation.status);
  if (envelope['code'] !== undefined) {
    expect(envelope['code'], context).toMatch(/^[A-Z][A-Z0-9_]*$/);
  }
  expect(envelope, context).not.toHaveProperty('stack');

  if (expectation.error !== undefined) expect(envelope['error'], context).toBe(expectation.error);
  if (expectation.code !== undefined) expect(envelope['code'], context).toBe(expectation.code);

  return envelope as StandardError;
}
