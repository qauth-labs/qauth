import { expect } from 'vitest';

/** A response whose body was read as a JSON object. */
export interface JsonResponse {
  readonly response: Response;
  readonly body: Record<string, unknown>;
}

/**
 * GET a URL and assert the answer is `200` with an `application/json` object.
 *
 * The content type is checked on the header, not inferred from the body, and
 * the body must be an object: a JSON array or a scalar fails.
 */
export async function getJsonObject(url: string, init: RequestInit = {}): Promise<JsonResponse> {
  const response = await fetch(url, { ...init, method: 'GET', redirect: 'manual' });
  const text = await response.text();
  const context = `GET ${url} answered ${response.status}: ${text.slice(0, 500)}`;

  expect(response.status, context).toBe(200);
  expect(response.headers.get('content-type') ?? '', context).toMatch(/^application\/json\b/i);

  const body: unknown = JSON.parse(text);
  expect(body !== null && typeof body === 'object' && !Array.isArray(body), context).toBe(true);
  return { response, body: body as Record<string, unknown> };
}
