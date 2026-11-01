import { serverPath, wireConfig } from '../config';

/** The methods the published OpenAPI document lists operations under. */
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

/**
 * An operation of the published OpenAPI document
 * (`apps/docs-site/public/openapi.json`), written as `METHOD /path` exactly as
 * the document lists it, e.g. `POST /oauth/token`.
 */
export type Operation = `${HttpMethod} /${string}`;

/** What a request to an operation carries. At most one body option. */
export interface CallOptions {
  /** Added to the path as the query string. */
  readonly query?: Record<string, string> | URLSearchParams;
  readonly headers?: Record<string, string>;
  /** Sent as `application/x-www-form-urlencoded`. */
  readonly form?: Record<string, string> | URLSearchParams;
  /** Sent as `application/json`. */
  readonly json?: unknown;
}

/** Split `METHOD /path` into its two parts. */
export function parseOperation(operation: Operation): { method: HttpMethod; path: string } {
  const space = operation.indexOf(' ');
  return {
    method: operation.slice(0, space) as HttpMethod,
    path: operation.slice(space + 1),
  };
}

/** The absolute URL of an operation's path on the server under test. */
export function operationUrl(
  operation: Operation,
  query?: Record<string, string> | URLSearchParams
): URL {
  const url = new URL(serverPath(wireConfig().baseUrl, parseOperation(operation).path));
  if (query) url.search = new URLSearchParams(query).toString();
  return url;
}

/**
 * Send one request to an operation of the server under test and return the
 * answer, following no redirect.
 *
 * The method and the path come from the one `METHOD /path` literal, so a test
 * cannot name one operation and request another. The suite's operation
 * coverage test (`src/operation-coverage.test.ts`) reads these literals to
 * prove that every OAuth and discovery operation of the published document is
 * called by at least one wire test.
 */
export function call(operation: Operation, options: CallOptions = {}): Promise<Response> {
  const { method } = parseOperation(operation);
  const headers = new Headers(options.headers);
  let body: string | undefined;
  if (options.form !== undefined) {
    headers.set('content-type', 'application/x-www-form-urlencoded');
    body = new URLSearchParams(options.form).toString();
  } else if (options.json !== undefined) {
    headers.set('content-type', 'application/json');
    body = JSON.stringify(options.json);
  }
  return fetch(operationUrl(operation, options.query), {
    method,
    headers,
    body,
    redirect: 'manual',
  });
}
