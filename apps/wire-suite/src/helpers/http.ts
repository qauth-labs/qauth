import { expect } from 'vitest';

/** A response whose body was read as a JSON object. */
export interface JsonResponse {
  readonly response: Response;
  readonly body: Record<string, unknown>;
}

/** `application/json`, with or without parameters. */
export const JSON_CONTENT_TYPE = /^application\/json\b/i;

/**
 * GET a URL and assert the answer is `200` with a JSON object.
 *
 * The content type is checked on the header, not inferred from the body, and
 * the body must be an object: a JSON array or a scalar fails. A caller whose
 * document has its own registered media type passes a pattern that names it.
 */
export async function getJsonObject(
  url: string,
  contentType: RegExp = JSON_CONTENT_TYPE
): Promise<JsonResponse> {
  const response = await fetch(url, { method: 'GET', redirect: 'manual' });
  const text = await response.text();
  const context = `GET ${url} answered ${response.status}: ${text.slice(0, 500)}`;

  expect(response.status, context).toBe(200);
  expect(response.headers.get('content-type') ?? '', context).toMatch(contentType);

  const body: unknown = JSON.parse(text);
  expect(body !== null && typeof body === 'object' && !Array.isArray(body), context).toBe(true);
  return { response, body: body as Record<string, unknown> };
}
